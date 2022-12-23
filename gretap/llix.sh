#!/bin/sh
# LL-IX

/bin/ip link delete LLIX
/bin/ip link add LLIX type gretap local **REDACTED** remote **REDACTED** ttl 128
/usr/bin/macchanger -m **REDACTED** LLIX
/bin/ip addr add **REDACTED**/22 dev LLIX
/bin/ip addr add **REDACTED**/48 dev LLIX
/bin/ip link set dev LLIX mtu 1450
/bin/ip link set dev LLIX up
