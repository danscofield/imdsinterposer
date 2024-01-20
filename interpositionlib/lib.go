package imdsinterposition

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

type IMDSCredentialResponse struct {
	Code            string
	LastUpdated     string
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
}
type SharedCredentials struct {
	Credentials *IMDSCredentialResponse
	mu          sync.Mutex
}

type SourcePortQueue struct {
	Capacity uint64
	Q        chan int
}
type IMDSInterposer struct {
	Ports                     *SourcePortQueue
	CurrentCreds              *SharedCredentials
	IMDSBaseAddress           string
	IMDSPort                  int64
	TokenCache                *expirable.LRU[string, bool]
	CredentialVendingEndpoint string
	QueryStringParameter      string
	HopHeadersToKill          []string
	RefreshTime               int
}

func (p *IMDSInterposer) GetIpAddress() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP, nil
		}
	}
	return nil, net.InvalidAddrError("No IP found")
}

func (p *IMDSInterposer) TakePort() int {
	item := <-p.Ports.Q
	atomic.AddUint64(&p.Ports.Capacity, uint64(0))
	return item
}

func (p *IMDSInterposer) ReturnPort(item int) {
	atomic.AddUint64(&p.Ports.Capacity, uint64(1))
	p.Ports.Q <- item
}

func (p *IMDSInterposer) GetHTTPClient() (*http.Client, int, error) {
	ip, err := p.GetIpAddress()
	sourcePort := p.TakePort()
	if err != nil {
		return nil, 0, err
	}

	localTCPAddr := net.TCPAddr{
		IP:   ip,
		Port: sourcePort,
	}

	webclient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &localTCPAddr,
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	return webclient, sourcePort, nil
}

func (p *IMDSInterposer) CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (p *IMDSInterposer) DelHopHeaders(header http.Header) {
	for _, h := range p.HopHeadersToKill {
		header.Del(h)
	}
}

func (p *IMDSInterposer) GetIMDSToken() (*string, error) {

	client, sourcePort, err := p.GetHTTPClient()
	defer p.ReturnPort(sourcePort)
	if err != nil {
		return nil, err
	}
	imdsAddress := p.IMDSBaseAddress
	if p.IMDSPort != 80 {
		imdsAddress += ":" + strconv.FormatInt(p.IMDSPort, 10)
	}

	imdsTokenUrl := "http://" + imdsAddress + "/latest/api/token"

	req, err := http.NewRequest(http.MethodPut, imdsTokenUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	r := string(body)
	return &r, nil
}
func (p *IMDSInterposer) GetEC2CallerIdentityPresigned(creds *IMDSCredentialResponse) (*string, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials(creds.AccessKeyId, creds.SecretAccessKey, creds.Token),
	})
	if err != nil {
		return nil, err
	}
	stsClient := sts.New(sess)
	input := &sts.GetCallerIdentityInput{}
	req, _ := stsClient.GetCallerIdentityRequest(input)
	presigned, err := req.Presign(15 * time.Minute)
	if err != nil {
		return nil, err
	}
	return &presigned, nil
}
func (p *IMDSInterposer) GetHostCredentialsFromCVS(presignedUrl *string, endpoint string, queryParameter string) (*IMDSCredentialResponse, error) {
	client := &http.Client{}

	encodedPSUrl := b64.StdEncoding.EncodeToString([]byte(*presignedUrl))

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add(p.QueryStringParameter, encodedPSUrl)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, net.UnknownNetworkError("Server did not accept your presigned url")
	}
	var creds IMDSCredentialResponse

	err = json.Unmarshal(body, &creds)

	if err != nil {
		return nil, err
	}
	return &creds, nil

}
func (p *IMDSInterposer) GetEC2InstanceCreds() (*IMDSCredentialResponse, error) {
	imdsToken, err := p.GetIMDSToken()
	if err != nil {
		return nil, err
	}
	client, sourcePort, err := p.GetHTTPClient()
	defer p.ReturnPort(sourcePort)
	if err != nil {
		return nil, err
	}
	imdsAddress := p.IMDSBaseAddress
	if p.IMDSPort != 80 {
		imdsAddress += ":" + strconv.FormatInt(p.IMDSPort, 10)
	}

	imdsEC2CredUrl := "http://" + imdsAddress + "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance"

	req, err := http.NewRequest(http.MethodGet, imdsEC2CredUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", *imdsToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var creds IMDSCredentialResponse

	err = json.Unmarshal(body, &creds)

	if err != nil {
		return nil, err
	}
	return &creds, nil
}
func (p *IMDSInterposer) GetCurrentCredentials() *IMDSCredentialResponse {
	p.CurrentCreds.mu.Lock()
	defer p.CurrentCreds.mu.Unlock()
	return p.CurrentCreds.Credentials
}

func (p *IMDSInterposer) UpdateCredentials() error {
	rsp, err := p.GetEC2InstanceCreds()
	if err != nil {
		return err
	}

	x, err := p.GetEC2CallerIdentityPresigned(rsp)
	if err != nil {
		return err
	}
	y, err := p.GetHostCredentialsFromCVS(x, p.CredentialVendingEndpoint, "presigned_url")
	if err != nil {
		return err
	}
	p.CurrentCreds.mu.Lock()
	defer p.CurrentCreds.mu.Unlock()
	p.CurrentCreds.Credentials = y
	return nil
}
func (p *IMDSInterposer) StartCredentialRotation() {
	for {
		log.Println("Updating credentials")
		err := p.UpdateCredentials()
		if err != nil {
			time.Sleep(10 * time.Second)
		} else {
			d := time.Minute * time.Duration(p.RefreshTime)
			time.Sleep(d)
		}
	}
}

func (p *IMDSInterposer) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	log.Println(req.RemoteAddr, " ", req.Method, " ", req.URL)

	if req.URL.Scheme == "https" {
		msg := "unsupported protocal scheme " + req.URL.Scheme + "!"
		http.Error(wr, msg, http.StatusBadRequest)
		return
	}
	if req.URL.Host != p.IMDSBaseAddress && req.URL.Host != "" {
		imdsAddress := p.IMDSBaseAddress + ":" + strconv.FormatInt(p.IMDSPort, 10)
		if req.URL.Host != imdsAddress {
			msg := "cant redirect outside of the imds"
			http.Error(wr, msg, http.StatusNotFound)
			return

		}
	}
	if req.URL.Path == "/latest/meta-data/iam/security-credentials/" {
		// we cant validate these tokens, so we just maintain an LRU
		// cache of the ones we proxied
		ssrftoken := req.Header.Get("X-aws-ec2-metadata-token")
		if len(ssrftoken) != 56 || !p.TokenCache.Contains(ssrftoken) {
			http.Error(wr, "", http.StatusUnauthorized)
			return
		}

		resp := http.Response{
			Body:       io.NopCloser(bytes.NewBufferString("YouCanHazRole")),
			StatusCode: 200,
			Status:     "200 OK",
		}
		defer resp.Body.Close()
		p.DelHopHeaders(resp.Header)
		p.CopyHeader(wr.Header(), resp.Header)
		wr.WriteHeader(resp.StatusCode)
		io.Copy(wr, resp.Body)
		log.Println(req.RemoteAddr, " ", resp.Status)
		return
	}
	if req.URL.Path == "/latest/meta-data/iam/security-credentials/YouCanHazRole" {
		// we cant validate these tokens, so we just maintain an LRU
		// cache of the ones we proxied
		ssrftoken := req.Header.Get("X-aws-ec2-metadata-token")
		if len(ssrftoken) != 56 || !p.TokenCache.Contains(ssrftoken) {
			http.Error(wr, "", http.StatusUnauthorized)
			return
		}
		creds, err := json.Marshal(p.GetCurrentCredentials())
		if err != nil {
			msg := "Credentials are currently out of sync"
			http.Error(wr, msg, http.StatusBadRequest)
			return
		}
		resp := http.Response{
			Body:       io.NopCloser(bytes.NewBuffer(creds)),
			StatusCode: 200,
			Status:     "200 OK",
		}
		defer resp.Body.Close()
		p.DelHopHeaders(resp.Header)
		p.CopyHeader(wr.Header(), resp.Header)
		wr.WriteHeader(resp.StatusCode)
		io.Copy(wr, resp.Body)
		log.Println(req.RemoteAddr, " ", resp.Status)
		return
	}

	req.RequestURI = ""

	p.DelHopHeaders(req.Header)

	client, sourcePort, err := p.GetHTTPClient()
	defer p.ReturnPort(sourcePort)

	req.URL.Scheme = "http"
	req.URL.Host = p.IMDSBaseAddress
	if p.IMDSPort != 80 {
		req.URL.Host += ":" + strconv.FormatInt(p.IMDSPort, 10)
	}

	if err != nil {
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	resp, err := client.Do(req)

	if err != nil {
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	log.Println(req.RemoteAddr, " ", resp.Status)

	p.DelHopHeaders(resp.Header)

	p.CopyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	responseBytes, err := io.ReadAll(resp.Body)

	// cache the ssrf token
	if req.URL.Path == "/latest/api/token" && resp.StatusCode == 200 && resp.ContentLength == 56 {
		if err == nil {
			tokenString := string(responseBytes)
			if len(tokenString) > 0 {
				p.TokenCache.Add(tokenString, true)
			}
		}

	}
	io.Copy(wr, bytes.NewReader(responseBytes))

}
