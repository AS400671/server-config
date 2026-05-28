#!/bin/sh

# This is an example file, you need to add your clients accordingly
# Use cronjob to regularly run this renew.sh!

bgpq4 -4 -b -A -l cloudflare_v4_prefixes AS-CLOUDFLARE > /etc/bird/irr/cloudflare_v4.conf
bgpq4 -6 -b -A -l cloudflare_v6_prefixes AS-CLOUDFLARE > /etc/bird/irr/cloudflare_v6.conf

