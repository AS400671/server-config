# AS400671 Server Configuration

This repository contains example BGP/Web configurations of PoPs used by AS400671 (https://network.stypr.com/).

Decided to open-source it for everyone's sake.. 

Please note that some constants and variables were redacted for security reasons.

## Technologies used for PoPs

* Bird
    * 2.0.10: Manually compiled, the upgrade script is available
    * RPKI (RFC6811, RFC8893) implemented with Cloudflare's gortr
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