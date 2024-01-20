#!/bin/sh

sudo iptables -t nat -D OUTPUT -p tcp --destination 169.254.169.254 --dport 80 ! --sport 1337:2337 -j REDIRECT --to 8080