# AS400671 Server Configuration

This repository contains example BGP/Web configurations of PoPs used by AS400671 (https://stypr.network/).

Decided to open-source it for everyone's sake.. 

Please note that some constants and variables were redacted for security reasons.

## Technologies used for PoPs

* Bird
    * 3.x: [Manually compiled](./bird/scripts/upgrade-latest.sh)
    * RPKI (RFC6811, RFC8893) check is implemented with `stayrtr` and `rpki-client`
    * BGP Large Communities (RFC8092) implemented (Check https://stypr.network/#community)
    * Configurations of interconnects with upstream, peers, etc.
        * Exchanges are mostly connected over GRETAP for stability

* API
    * PHP 8.x
        * For sharing information with the [Network Dashboard](https://stypr.network/)
    * Caddy (Apache and other webservers can be used as an alternative)
    * Python
        * For cronjobs; used for crawling interconnected IXPs, peers, etc.

* Network
    * All inbound/outbound connections go through wg0 (WireGuard)


## Notes

### RPKI

RPKI consumes a lot of memory as RPKI data is directly cached in the memory to sync data between the RPKI client and the bird daemon.

Make sure to increase your (swap) memory in case your server runs on a low memory. `stayrtr` or `rpki-client` may randomly crash when the free memory space is insufficient.


### IRR Filtering

RPKI has been enabled for the setup, but there are also plans to use bgpq4 (https://github.com/bgp/bgpq4) to filter direct peers and customers. 

IRR filters hasn't been implemented yet since customers or peers are considered as a fully trusted ones, but there is a plan to add automated checks on AS-SETs.

Commands to run `bgpq4` would be the following (as suggested by AS50058), but it is always recommended to grep and handpick some options from the manual.

```sh
bgpq4 -S $source -h $server -l $name -A4s $asset
```

### Debugging Traffics

Sometimes you might get stuck with GRETAP connections with IXPs or peers, and most of the time it may take some time to check and debug the configuration. 

On such cases, install Wireshark and use `tcpdump` to capture and debug packets.

This is very useful even for debugging GRETAP connections. 

Most of the time, network connectivity fails due to TTL mismatches or multihop issues. 

Check packets and see what went wrong to troubleshoot. Wireshark is actually very friendly with BGP protocols.

### GRETAP Tunneling

If you're using GRETAP tunneling, make sure that bird resets the GRETAP connection upon starting (and restarting) bird daemon.

You can do this by editing the `/usr/lib/bird/prepare-environment` as follows

```sh
#!/bin/sh

set -eu

...

/srv/gretap.sh 2>&1
```

### For Vultr users

You need to route your traffic properly so that servers are reachable from your end.  [Reference](https://skym.fi/blog/2020/07/vultr-trouble/)

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
