#!/bin/sh

# This is an example file, you need to add your clients accordingly
# Use cronjob to regularly run this renew.sh!
# In real server this is already implemented.

# Running the following command should produce an output like this
# define cloudflare_v4_prefixes = [
#   ...
# ];

bgpq4 -4 -b -A -l cloudflare_v4_prefixes AS-CLOUDFLARE \
  | sed '1s/^/define /' > /etc/bird/irr/cloudflare_v4.conf
bgpq4 -6 -b -A -l cloudflare_v6_prefixes AS-CLOUDFLARE \
  | sed '1s/^/define /' > /etc/bird/irr/cloudflare_v6.conf
