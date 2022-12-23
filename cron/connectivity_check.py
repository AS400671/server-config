#!/usr/bin/python3 -u
#-*- coding: utf-8 -*-

"""
connectivity_check.py

Simple tool for checking Bird2 connectivity (for personal use)
Developed by AS400671 (https://network.stypr.com/)

You can use description to set speed, countries and names of providers.

```
protocol bgp constant6
{
    description "The Constant Company LLC | 1G | US";
    local as my_asn;
    source address my_ipv6;
    ...
}
```

"""

import os
import re
import json
import socket
import base64
import sqlite3
import requests
from config import UPSTREAM_PROTOCOLS, PEERINGDB_NET, PEERINGDB_API
from ipaddress import ip_address, IPv4Address

BIRDC_BINARY = "/usr/sbin/birdc"
PEER_LIST = set()
db = sqlite3.connect('/root/asn.db')
db_cur = db.cursor()
db_cur.execute('''CREATE TABLE IF NOT EXISTS asn
               (asn text, country text, name text)''')

def list_total_peers():
    """
    Returns list of peer ASNs from exchange
    """
    headers = {
        "Authorization": f"Api-Key {PEERINGDB_API}"
    }
    output = []

    result = requests.get(f"https://www.peeringdb.com/api/net/{PEERINGDB_NET}", headers=headers).json()
    for ixp in result['data'][0]['netixlan_set']:
        ixp_result = requests.get(f"https://www.peeringdb.com/api/ixlan/{ixp['ix_id']}", headers=headers).json()
        for ix_peer in ixp_result['data'][0]['net_set']:
            output.append(str(ix_peer['asn']))

    return set(output)


def parse_protocol_output(output):
    """
    Parses the result of birdc show proto all {protocol}
    """
    result = {}
    ret_address_version = ""
    ret_asn_number = ""
    ret_provider = ""
    ret_ip_addr = ""

    for ret_line in output.split("\n"):
        if not ret_address_version:
            ret_address = re.findall(r"Neighbor address:[\ ]+([0-9a-f\.\:]+)", ret_line.strip())
            if ret_address:
                ret_address_version = validate_ipaddress(ret_address[0])

        if not ret_asn_number:
            ret_asn_number = re.findall(r"Neighbor AS:[\ ]+([0-9]+)", ret_line.strip())
            if ret_asn_number:
                ret_asn_number = ret_asn_number[0]

        if not ret_provider:
            ret_provider = re.findall(r"Description:[\ ]+([\w\?\ \(\)\.\|\-\_]+)", ret_line.strip())
            if ret_provider:
                ret_provider = ret_provider[0].strip()

        if not ret_ip_addr:
            ret_ip_addr = re.findall(r"Source address:[\ ]+([0-9a-f\.\:]+)", ret_line.strip())
            if ret_ip_addr:
                ret_ip_addr = ret_ip_addr[0].strip()

        if ret_asn_number and ret_address_version and ret_provider and ret_ip_addr:
            break

    if not ret_provider:
        ret_provider = "? | ? | ?"

    result = {
        'asn': ret_asn_number,
        'provider': ret_provider,
        'version': ret_address_version,
        'ip': ret_ip_addr,
    }
    return result


def validate_ipaddress(target):
    """
    Check if the IP address is valid
    Return version of IP address if valid
    """
    try:
        return "v4" if isinstance(ip_address(target), IPv4Address) else "v6"
    except ValueError:
        return ""


def list_exchanges():
    """
    List available protocols from bird
    Returns dict of protocols and its descriptions
    """
    global UPSTREAM_PROTOCOLS
    global BIRDC_BINARY
    result = {}
    exchanges = []

    # fetch exchanges from show proto
    ret = os.popen(f"{BIRDC_BINARY} -r 'show proto' 2>&1").read()
    ret_parsed = [[j for j in i.split(" ") if j] for i in ret.split("\n") if i]
    for protocol in ret_parsed:
        if protocol[1] != "BGP":
            continue
        if protocol[0] in UPSTREAM_PROTOCOLS:
            continue
        exchanges.append(protocol[0])

    # parse all info from each exchange
    for exchange in exchanges:
        ret = os.popen(f"{BIRDC_BINARY} -r 'show proto all {exchange}' 2>&1").read()
        proto_output = parse_protocol_output(ret)

        if proto_output:
            ret_address_version = proto_output['version']
            ret_asn = proto_output['asn']

            ret_provider = proto_output['provider'].split("|")
            ret_ip_addr = proto_output['ip']
            if result.get(exchange):
                continue

            ret_speed = "1G"
            if len(ret_provider) > 1:
                if ret_provider[1].strip() == "?":
                    continue
                ret_speed = ret_provider[1].strip()

            result[exchange] = {
                'asn': ret_asn,
                'ip': ret_ip_addr,
                'version': ret_address_version,
                'provider': ret_provider[0].strip(),
                'speed': ret_speed,
                'country': ret_provider[2].strip() if len(ret_provider) > 1 else "us",
            }

    return result

def list_peers(protocol):
    """ (list) -> list
    List available protocols from bird
    Returns list of protocols
    """
    global BIRDC_BINARY
    result = {'v4': {}, 'v6': {}}

    for blocked_char in ["'", "\"", "$", "`", "|", "\\", ";", ">", "<", "{", "}"]:
        if blocked_char in protocol:
            return result

    ret = os.popen(f"{BIRDC_BINARY} -r 'show route primary protocol {protocol}'").read().split("\n")
    for i in range(3, len(ret), 2):
        row = [q for q in ret[i].split(" ") if q]
        if not row:
            continue

        row_prefix = row[0]
        row_status = row[1]
        row_asn = row[-1]

        row_asn = re.findall(r"\[AS([0-9]+)[i\*\?]\]", row_asn)
        if not row_asn:
            continue

        row_asn = row_asn[0]
        if row_asn not in PEER_LIST:
            continue


        # Check if the imported network is reachable
        if row_status == "unreachable":
            continue

        if row_status != "unicast":
            # print(f"[*] Debug plz: {row}")
            continue

        # Check if the ASN is valid
        try:
            row_address_version = validate_ipaddress(row_prefix.split("/")[0])
        except IndexError:
            continue

        if result[row_address_version].get(row_asn):
            continue

        result[row_address_version][row_asn] = {
            'type': 'downstream',
            'name': '',
            'country': '',
        }

    return result


def list_upstream():
    """
    List available protocols from bird, parse neighbor NS from upstream protocol info
    Returns list of ASNs
    """
    global UPSTREAM_PROTOCOLS
    global BIRDC_BINARY

    result = {'v4': {}, 'v6': {}}

    # get available upstreams
    available_upstreams = []
    ret = os.popen("id 2>&1").read()
    ret += os.popen(f"{BIRDC_BINARY} -r 'show proto' 2>&1").read()
    f = open("/srv/ret", "w")
    f.write(ret)
    f.close()

    ret = os.popen(f"{BIRDC_BINARY} -r 'show proto' | tail -n +4").read()
    ret_parsed = [[j for j in i.split(" ") if j] for i in ret.split("\n") if i]
    for protocol in ret_parsed:
        if protocol[1] != "BGP":
            continue
        if protocol[0] not in UPSTREAM_PROTOCOLS:
            continue
        available_upstreams.append(protocol[0])

    # parse neighbor ns
    for upstream in available_upstreams:
        ret = os.popen(f"{BIRDC_BINARY} -r 'show proto all {upstream}'").read()
        proto_output = parse_protocol_output(ret)

        if proto_output:
            ret_address_version = proto_output['version']
            ret_asn = proto_output['asn']
            ret_provider = proto_output['provider'].split("|")
            if result[ret_address_version].get(ret_asn):
                continue

            result[ret_address_version][ret_asn] = {
                'type': 'upstream',
                'name': '',
                'provider': ret_provider[0].strip(),
                'country': ret_provider[2].strip() if len(ret_provider) > 1 else "us",
                'speed': ret_provider[1].strip() if len(ret_provider) > 1 else "1G",
            }
            continue

    return result

def list_downstream():
    """
    List available exchanges from bird, get list of exported info
    Returns list of ASNs
    """
    server_list = list_exchanges()
    server_peers = {'v4': {}, 'v6': {}}

    for server in server_list:
        peers = list_peers(server)
        for version in peers.keys():
            for asn, asn_info in peers[version].items():
                server_peers[version][asn] = asn_info
                server_peers[version][asn]['exchange'] = server

    return server_peers

def fetch_asn_info(asn_list):
    """ (list) -> dict

    Interact with BGP.tools to retrieve ASN Information
    Returns dict of dict ASN
    """
    whois_server = ("bgp.tools", 43)
    result = {}
    result_db = []

    # fetch db first!
    for row in db_cur.execute('SELECT * FROM asn;'):
        result[row[0]] = {
            "country": row[1],
            "name": row[2],
        }

    # asn_list is all parted from asn
    curr_asn_list = []
    result_keys = result.keys()
    for i in asn_list:
        if i not in result_keys:
            curr_asn_list.append(i)

    if not curr_asn_list:
        return result

    payload = ("begin\nverbose\nas" + ("\nas".join(curr_asn_list)) + "\nend\n").encode()
    # connect to server and fetch ASN information
    recv_data = b""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(whois_server)
        sock.sendall(payload)
        while True:
            data = sock.recv(1024)
            if not data:
                break
            recv_data += data

    # parse data based on info from bgp.tools
    for asn_info in recv_data.split(b"\n"):
        if not asn_info:
            continue
        asn_info_parsed = [i.strip() for i in asn_info.split(b"|")]

        if asn_info_parsed:
            result[asn_info_parsed[0].decode()] = {
                "country":  asn_info_parsed[3].decode().lower(),
                "name": asn_info_parsed[-1].decode()
            }
            result_db.append((asn_info_parsed[0].decode(), asn_info_parsed[3].decode().lower(), asn_info_parsed[-1].decode()))

    db_cur.executemany("INSERT INTO asn VALUES(?, ?, ?)", result_db)
    db.commit()
    return result

def main():
    """
    main function to render json output of the connectivity
    """
    result = {
        'upstreams': list_upstream(),
        'downstreams': list_downstream(),
    }

    # fetch ASN information
    asn_list = []
    for version in ['v4', 'v6']:
        for asn_type in result:
            asn_list.extend(list(result[asn_type][version].keys()))
            asn_list.extend(list(result[asn_type][version].keys()))
    asn_list_info = fetch_asn_info(asn_list)

    # add country and name based on fetched asn info
    for asn in asn_list_info:
        for version in ['v4', 'v6']:
            for asn_type in result:
                if result[asn_type][version].get(asn):
                    if not result[asn_type][version][asn]['country']:
                        result[asn_type][version][asn]['country'] = asn_list_info[asn]['country']
                    if not result[asn_type][version][asn]['name']:
                        result[asn_type][version][asn]['name'] = asn_list_info[asn]['name']

    # add exchange at last
    exchanges = list_exchanges()
    result['exchanges'] = exchanges

    return json.dumps(result)

if __name__ == "__main__":
    PEER_LIST = list_total_peers()
    result = main()
    fp_connect = open("/var/www/connectivity.json", "w")
    fp_connect.write(result)
    fp_connect.close()
    print(result)
