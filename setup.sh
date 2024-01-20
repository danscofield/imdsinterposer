#!/bin/sh

sudo sysctl -w net.ipv4.conf.all.route_localnet=1
sudo iptables -t nat -A OUTPUT -p tcp --destination 169.254.169.254 --dport 80 ! --sport 1337:2337 -j REDIRECT --to 8080