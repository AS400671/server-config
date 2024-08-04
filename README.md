# AS400671 Server Configuration

This repository contains example BGP/Web configurations of PoPs used by AS400671 (https://network.stypr.com/).

Decided to open-source it for everyone's sake.. 

Please note that some constants and variables were redacted for security reasons.

## Technologies used for PoPs

* Bird
    * 2.0.11: Manually compiled, the upgrade script is available
    * RPKI (RFC6811, RFC8893) implemented with stayrtr+rpki-client   
    * BGP Large Communities (RFC8092) implemented (Based on https://network.stypr.com/#community)
    * Configurations of interconnects with upstream, peers, etc.
        * Exchanges are mostly connected over GRETAP for stability

* Web
    * PHP 8.x
        * For sharing information to https://network.stypr.com/
    * Caddy (You can use Apache and other things)
    * Python
        * For cronjob; used for crawling interconnected IXPs, etc.

* Network
    * All inbound/outbound connections go through wg0 (WireGuard)


## Notes

### RPKI

RPKI eats up a lot of memory as RPKI data is cached and compared on both RPKI and bird. so make sure to increase your swap memory in case RPKI server crashes.

### IRR Filtering

RPKI is currently enabled for this setup, but there are also plans to use bgpq4 (https://github.com/bgp/bgpq4) to filter direct peers and customers. 

IRR filters hasn't been implemented yet since customers / peers are currently considered as a fully trusted ones, but there is a plan to add automated checks on AS-SETs.

Commands to run bgpq4 would be the following (suggested by AS50058), but it is always recommended to grep and handpick some options from the help option.

```sh
bgpq4 -S $source -h $server -l $name -A4s $asset
```

### Debugging Traffics

Sometimes you might get stuck with GRETAP connections with IXPs or peers, and most of the time it may take some time to check and debug the configuration. so just install Wireshark and use `tcpdump` to capture and debug packet-wise. This is very useful even for GRETAP connections. Most of the time network just crashes because of TTL or multihop issues, so just try to check packets and see what went wrong. Wireshark is actually very friendly on BGP protocols.

### GRETAP

If you're using gretap, make sure that bird resets the GRETAP connection everytime bird starts/restarts.

You can do this by editing the `/usr/lib/bird/prepare-environment` as follows

```sh
#!/bin/sh

set -eu

...

/srv/gretap.sh 2>&1
```

### For Vultr users

You need to route your traffic properly so that servers are reachable from your end.  Reference: https://skym.fi/blog/2020/07/vultr-trouble/

As for the configs from this repo, all you need to do is to add lines in `bird/config/basic/routes.conf` so that it looks something like this

```
protocol static
{
    ipv6;
    route (my_ip_range)/48 via my_ipv6%enp1s0;
    route (my_ip_range)/48 via my_ipv6%enp1s0;
    route 2001:19f0:ffff::1/128 via my_ipv6%enp1s0;
}
```
