# AS400671 Server Configuration

This repository contains example BGP/Web configurations of PoPs used by AS400671 (https://stypr.network/).

Decided to open-source it for everyone's sake.

Please note that some constants and variables were redacted for security reasons.

## Breaking Changes since May 1, 2025

Since v3.1.0, it is recommended to add `authentication` when passwords are added to the connection options.

However, this could potentially cause configuration errors on older versions of BIRD daemon.

Please remove accordingly when the error appears on your machine.

[Reference Commit](https://github.com/CZ-NIC/bird/commit/f5d9f36276bfbf5e6a2d7facbd829b2d45cfe6bc#diff-b2e11157926a32e724a539c3c63cdc945907a274d273a28aaa5b45ad73d6eee2R2946)

## Technologies used for PoPs

* BIRD
    * 3.3.0 and higher: [Manually compiled](./bird/scripts/upgrade-latest.sh)
    * RPKI (RFC6811, RFC8893) check is implemented with `rpki-client`
    * BGP Large Communities (RFC8092) implemented (Check https://stypr.network/#community)
    * Route Leak Prevention and Detection (RFC9234) added for [bird](https://bird.nic.cz/doc/bird-3.3.0.html#bgp-local-role)
    * Configurations of interconnects with upstream, peers, etc.
        * Exchanges are mostly connected over GRETAP for stability

* API
    * PHP 8.4+
        * For looking glass and traffic info to show on the [Network Dashboard](https://stypr.network/)
    * Caddy (Apache and other webservers can be used as an alternative)
    * Python
        * For cronjobs; used for crawling interconnected IXPs, peers, etc.

* Network
    * All inbound/outbound connections go through wg0 (WireGuard)


## Notes

### RPKI

RPKI consumes a lot of memory as RPKI data is directly cached in the memory to sync data between the RPKI client and the BIRD daemon.

Make sure to increase your (swap) memory in case your server runs on a low memory. `stayrtr` or `rpki-client` may randomly crash when the free memory space is insufficient.

**Updates as of May 27, 2026**

Running `rpki-client` alone does work perfectly without having `stayrtr` dependencies. It also leaves lesser memory footprints.

You may still want to use `stayrtr` if you're not sure of what you're doing.

Some files were left on `bird/rpki/` as a reference: these files let `rpki-client` pass all information directly to bird.

You might want to edit `/etc/default/rpki-client` and `systemctl edit rpki-client.service` to make things work smoothly.

### IRR Filtering

RPKI is already enabled for the setup. But we also utilize bgpq4 (https://github.com/bgp/bgpq4) for direct peers and customers. This is to ensure that 

You might want to check `bird/config/irr/renew.sh`, `bird/config/bird.conf` and `bird/config/bgp/cloudflare.conf` to see how this works for clients.

### Debugging Traffics

Sometimes you might get stuck with GRETAP connections with IXPs or peers, and most of the time it may take some time to check and debug the configuration. 

On such cases, install Wireshark and use `tcpdump` to capture and debug packets.

This is very useful even for debugging GRETAP connections. 

Most of the time, network connectivity fails due to TTL mismatches or multihop issues. 

Check packets and see what went wrong to troubleshoot. Wireshark is actually very friendly with BGP protocols.

### GRETAP Tunneling

If you're using GRETAP tunneling, make sure that BIRD resets the GRETAP connection upon starting (and restarting) BIRD daemon.

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
