# IMDS Interposer

***Disclaimer***: This is a proof of concept, please don't use it in production. I just wanted to use my own instance roles for Lightsail. Please use EC2 instance roles instead of this hackery! 

IMDS Interposer proxies requests to the EC2 IMDS from other applications on the instance and lies about the attached [EC2 Instance IAM role](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html). The credentials returned by the `/latest/meta-data/iam/security-credentials/` endpoint are sourced from an API that verifies host identity using a bearer token strategy. These bearer tokens are basically base64-encoded pre-signed calls to `sts get-caller-identity` that are signed with [instance identity role](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-identity-roles.html) credentials. A CDK stack that implements this API is available [here](https://github.com/danscofield/hicred)

# Usage
To build the binary run `./build.sh`. Next, modify `run.sh` to include your own api endpoint. Enable `iptables` redirection by running `./setup.sh`. Once `./setup.sh` is run, the real IMDS will be unavailable to applications on your instance. To start the interposer, run `./run.sh`. At this point, the interposer will start proxying requests to the real IMDS. To disable the `iptables` redirection rule and restore the real IMDS, run `./teardown.sh`

# How it works

TCP source port numbers in Linux are generally chosen from a range defined in `/proc/sys/net/ipv4/ip_local_port_range`. The `imdsinterposer` makes requests to the IMDS using source ports that are in a range that does not overlap with the one defined in `/proc/sys/net/ipv4/ip_local_port_range` (i.e., `1337-2337`). The `./setup.sh` script adds an `iptables` rule that redirects IMDS-bound traffic on the `OUTPUT` chain to `imdsinterposer` unless the TCP source port is in the range `1337:2337`. This allows `imdsinterposer` to talk to the real IMDS, but forces other applications to talk to `imdsinterposer` instead.

