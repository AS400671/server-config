#!/bin/sh

/bin/ip link delete BGPExchange
/bin/ip link add BGPExchange type gretap local **REDACTED** remote **REDACTED** ttl 255
/usr/bin/macchanger -m **REDACTED** BGPExchange
/bin/ip link set dev BGPExchange up
/bin/ip addr add **REDACTED**/22 dev BGPExchange
/bin/ip addr add **REDACTED**/64 dev BGPExchange
