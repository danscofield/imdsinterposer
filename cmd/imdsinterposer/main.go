package main

import (
	imdsinterposition "imdsinterposition/interpositionlib"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/akamensky/argparse"
)

type InterposerArgs struct {
	endpoint    string
	imds        string
	imdsport    int
	bindport    int
	startport   int
	endport     int
	queryParam  string
	refreshTime int
}

func argparsing() (*InterposerArgs, error) {
	parser := argparse.NewParser("imdsinterposer", "Hijacks calls to the IMDS for great good")
	endpoint := parser.String("e", "endpoint", &argparse.Options{Required: true, Help: "HTTP endpoint for credential vending machine"})
	querystring := parser.String("q", "querystring", &argparse.Options{Required: false, Default: "presigned_url", Help: "IP of IMDS"})

	imds := parser.String("i", "imds", &argparse.Options{Required: false, Default: "169.254.169.254", Help: "Querystring parameter to pass encoded presigned url"})
	imdsport := parser.Int("j", "imdsport", &argparse.Options{Default: 80, Required: false, Help: "Port to bind interceptor to"})
	bindPort := parser.Int("p", "port", &argparse.Options{Default: 8080, Required: false, Help: "Port to bind interceptor to"})
	startPort := parser.Int("a", "srcPortStart", &argparse.Options{Default: 1337, Required: false, Help: "Start of source port range to use"})
	endPort := parser.Int("b", "srcPortEnd", &argparse.Options{Default: 2337, Required: false, Help: "End of source port range to use"})
	refresh := parser.Int("r", "refresh", &argparse.Options{Default: 1, Required: false, Help: "Frequency (minutes) to refresh creds"})

	err := parser.Parse(os.Args)
	if err != nil {
		log.Println(parser.Usage(err))
		return nil, err
	}

	opts := &InterposerArgs{
		endpoint:    *endpoint,
		bindport:    *bindPort,
		startport:   *startPort,
		endport:     *endPort,
		imds:        *imds,
		imdsport:    *imdsport,
		queryParam:  *querystring,
		refreshTime: *refresh,
	}
	return opts, nil

}
func main() {
	opts, err := argparsing()
	if err != nil {
		return
	}
	sports := &imdsinterposition.SourcePortQueue{
		Q:        make(chan int, (opts.endport-opts.startport)+1),
		Capacity: (uint64(opts.endport) - uint64(opts.startport)) + 1,
	}
	for i := opts.startport; i <= opts.endport; i++ {
		sports.Q <- i
	}

	var creds imdsinterposition.SharedCredentials

	// Hop-by-hop headers. These are removed when sent to the backend.
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
	var hopHeaders = []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te", // canonicalized version of "TE"
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	handler := &imdsinterposition.IMDSInterposer{
		Ports:                     sports,
		CurrentCreds:              &creds,
		IMDSBaseAddress:           opts.imds,
		IMDSPort:                  int64(opts.imdsport),
		CredentialVendingEndpoint: opts.endpoint,
		QueryStringParameter:      opts.queryParam,
		HopHeadersToKill:          hopHeaders,
		RefreshTime:               opts.refreshTime,
	}
	go handler.StartCredentialRotation()

	addr := "127.0.0.1:" + strconv.FormatUint(uint64(opts.bindport), 10)

	log.Println("Starting proxy server on", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
