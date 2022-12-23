#!/bin/sh
# 4ixp

/bin/ip link delete fourixp
/bin/ip link add fourixp type gretap local **REDACTED** remote **REDACTED** ttl 255
/usr/bin/macchanger -m **REDACTED** fourixp
/bin/ip link set dev fourixp up
/bin/ip addr add **REDACTED**/24 dev fourixp
/bin/ip addr add **REDACTED**/64 dev fourixp