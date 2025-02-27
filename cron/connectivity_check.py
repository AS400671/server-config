#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

"""
connectivity_check.py

Simple tool for checking Bird2 connectivity (for personal use)
Developed by AS400671 (https://stypr.network/)

Example protocol description:
    protocol bgp constant6 {
        description "The Constant Company LLC | 1G | US";
        local as my_asn;
        source address my_ipv6;
        ...
    }
"""

import os
import re
import json
import socket
import sqlite3
import subprocess
import logging
from collections import Counter
from ipaddress import ip_address, IPv4Address

import requests
from config import UPSTREAM_PROTOCOLS, PEERINGDB_NET, PEERINGDB_API

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BIRDC_BINARY = "/usr/sbin/birdc"

def run_birdc_command(command):
    """Run a restricted birdc command and return its output as text."""
    try:
        result = subprocess.run(
            [BIRDC_BINARY, "-r", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("Error running command '%s': %s", command, e.output)
        return ""

class ASNDatabase:
    """Class to manage the ASN SQLite database."""
    def __init__(self, db_path="/root/asn.db"):
        self.conn = sqlite3.connect(db_path)
        self.cur = self.conn.cursor()
        self.cur.execute('''CREATE TABLE IF NOT EXISTS asn
                            (asn TEXT, country TEXT, name TEXT)''')
        self.conn.commit()

    def fetch_all(self):
        """Fetch all ASN records from the database."""
        result = {}
        for row in self.cur.execute("SELECT * FROM asn;"):
            result[row[0]] = {"country": row[1], "name": row[2]}
        return result

    def insert_many(self, records):
        """Insert multiple ASN records into the database."""
        if records:
            self.cur.executemany("INSERT INTO asn VALUES(?, ?, ?)", records)
            self.conn.commit()

    def close(self):
        self.conn.close()

def list_total_peers():
    """
    Retrieve a set of peer ASNs from PeeringDB.
    """
    headers = {"Authorization": f"Api-Key {PEERINGDB_API}"}
    output = set()
    try:
        response = requests.get(f"https://www.peeringdb.com/api/net/{PEERINGDB_NET}", headers=headers)
        response.raise_for_status()
        data = response.json()
        for ixp in data['data'][0].get('netixlan_set', []):
            ixp_response = requests.get(f"https://www.peeringdb.com/api/ixlan/{ixp['ix_id']}", headers=headers)
            ixp_response.raise_for_status()
            ixp_data = ixp_response.json()
            for net in ixp_data['data'][0].get('net_set', []):
                output.add(str(net['asn']))
    except requests.RequestException as e:
        logging.error("Error fetching total peers: %s", e)
    return output

def validate_ipaddress(target):
    """
    Validate the IP address and return its version ('v4' or 'v6').
    Returns an empty string if invalid.
    """
    try:
        return "v4" if isinstance(ip_address(target), IPv4Address) else "v6"
    except ValueError:
        return ""

def parse_protocol_output(output):
    """
    Parse the output from the command:
      birdc show proto all {protocol}

    Returns a dictionary with keys:
      - 'asn': neighbor AS number,
      - 'provider': provider description,
      - 'version': IP version of the neighbor address,
      - 'ip': source IP address.
    """
    ret_address_version = ""
    ret_asn_number = ""
    ret_provider = ""
    ret_ip_addr = ""

    for line in output.splitlines():
        line = line.strip()
        if not ret_address_version:
            match = re.search(r"Neighbor address:\s+([0-9a-f\.\:]+)", line)
            if match:
                ret_address_version = validate_ipaddress(match.group(1))
        if not ret_asn_number:
            match = re.search(r"Neighbor AS:\s+([0-9]+)", line)
            if match:
                ret_asn_number = match.group(1)
        if not ret_provider:
            match = re.search(r"Description:\s+([\w\?\ \(\)\.\|\-\_]+)", line)
            if match:
                ret_provider = match.group(1).strip()
        if not ret_ip_addr:
            match = re.search(r"Source address:\s+([0-9a-f\.\:]+)", line)
            if match:
                ret_ip_addr = match.group(1).strip()

        if ret_asn_number and ret_address_version and ret_provider and ret_ip_addr:
            break

    if not ret_provider:
        ret_provider = "? | ? | ?"
    return {
        'asn': ret_asn_number,
        'provider': ret_provider,
        'version': ret_address_version,
        'ip': ret_ip_addr,
    }

def list_exchanges():
    """
    List available exchanges from Bird by parsing protocol descriptions.
    Returns a dictionary mapping exchange names to their details.
    """
    result = {}
    exchanges = []

    # Fetch protocol list using "birdc show proto"
    proto_output = run_birdc_command("show proto")
    for line in proto_output.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] != "BGP":
            continue
        if parts[0] in UPSTREAM_PROTOCOLS:
            continue
        exchanges.append(parts[0])

    # For each exchange, parse detailed information
    for exchange in exchanges:
        output = run_birdc_command(f"show proto all {exchange}")
        proto_data = parse_protocol_output(output)
        if not proto_data:
            continue

        provider_parts = [p.strip() for p in proto_data['provider'].split("|")]

        # skip bgp.tools / etc.
        if len(provider_parts) > 1:
            if provider_parts[1].strip() == "?":
                continue

        ret_speed = provider_parts[1] if len(provider_parts) > 1 and provider_parts[1] != "?" else "1G"
        ret_country = provider_parts[2] if len(provider_parts) > 2 else "us"


        result[exchange] = {
            'asn': proto_data['asn'],
            'ip': proto_data['ip'],
            'version': proto_data['version'],
            'provider': provider_parts[0] if provider_parts else "",
            'speed': ret_speed,
            'country': ret_country,
        }
    return result

def list_peers(protocol):
    """
    List peers for a given protocol from Bird.

    Returns a dictionary with keys 'v4' and 'v6', mapping ASN to peer info.
    """
    result = {'v4': {}, 'v6': {}}

    # Reject potentially unsafe protocol strings
    for ch in ["'", "\"", "$", "`", "|", "\\", ";", ">", "<", "{", "}"]:
        if ch in protocol:
            return result

    output = run_birdc_command(f"show route primary protocol {protocol}")
    lines = output.splitlines()

    for i in range(3, len(lines)):
        row = [q for q in lines[i].split() if q]
        if not row:
            continue

        if len(row) < 2:
            continue

        row_prefix = row[0]
        row_status = row[1]
        row_asn_field = row[-1]
        asn_match = re.search(r"\[AS([0-9]+)[i\*\?]\]", row_asn_field)
        if not asn_match:
            continue

        row_asn = asn_match.group(1)
        # if row_asn not in PEER_LIST:
        #     continue

        if row_status == "unreachable": # or row_status != "unicast":
            continue

        ip_part = row_prefix.split("/")[0]
        row_address_version = validate_ipaddress(ip_part)
        if row_asn in result.get(row_address_version, {}):
            continue

        result[row_address_version][row_asn] = {
            'type': 'downstream',
            'name': '',
            'country': '',
        }
    return result

def list_upstream():
    """
    List upstream peers from Bird.

    Returns a dictionary with keys 'v4' and 'v6' mapping ASN to upstream peer info.
    """
    result = {'v4': {}, 'v6': {}}
    available_upstreams = []

    proto_output = run_birdc_command("show proto")
    for line in proto_output.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] != "BGP":
            continue
        if parts[0] not in UPSTREAM_PROTOCOLS:
            continue
        available_upstreams.append(parts[0])

    for upstream in available_upstreams:
        output = run_birdc_command(f"show proto all {upstream}")
        proto_data = parse_protocol_output(output)
        if not proto_data:
            continue

        provider_parts = [p.strip() for p in proto_data['provider'].split("|")]
        result[proto_data['version']][proto_data['asn']] = {
            'type': 'upstream',
            'name': '',
            'provider': provider_parts[0] if provider_parts else "",
            'country': provider_parts[2] if len(provider_parts) > 2 else "us",
            'speed': provider_parts[1] if len(provider_parts) > 1 else "1G",
        }
    return result

def list_downstream():
    """
    List downstream peers from exchanges.

    Returns a dictionary with keys 'v4' and 'v6' mapping ASN to peer info,
    including the exchange from which they were learned.
    """
    exchanges = list_exchanges()
    server_peers = {'v4': {}, 'v6': {}}

    for exchange, details in exchanges.items():
        peers = list_peers(exchange)
        for version, asn_dict in peers.items():
            for asn, info in asn_dict.items():
                info['exchange'] = exchange
                server_peers[version][asn] = info
    return server_peers

def fetch_asn_info(asn_list, db_manager):
    """
    Retrieve ASN information from bgp.tools and cache results in a local SQLite DB.

    Returns a dictionary mapping ASN to its details.
    """
    whois_server = ("bgp.tools", 43)
    result = db_manager.fetch_all()
    missing_asns = [asn for asn in asn_list if asn not in result]

    if not missing_asns:
        return result

    payload = ("begin\nverbose\n" +
               "\n".join(f"as{asn}" for asn in missing_asns) +
               "\nend\n").encode()
    recv_data = b""

    # connect to server and fetch ASN information
    with socket.create_connection(whois_server) as sock:
        sock.sendall(payload)
        while True:
            data = sock.recv(1024)
            if not data:
                break
            recv_data += data

    # parse data based on info from bgp.tools
    records_to_insert = []
    for line in recv_data.split(b"\n"):
        if not line:
            continue
        parts = [p.strip() for p in line.split(b"|")]
        if parts:
            asn_key = parts[0].decode()
            country = parts[3].decode().lower() if len(parts) > 3 else ""
            name = parts[-1].decode() if parts else ""
            result[asn_key] = {"country": country, "name": name}
            records_to_insert.append((asn_key, country, name))

    db_manager.insert_many(records_to_insert)
    return result

def main():
    """
    Main function to gather connectivity information and output JSON.
    """
    db_manager = ASNDatabase()
    try:
        connectivity = {
            'upstreams': list_upstream(),
            'downstreams': list_downstream(),
        }

        # Aggregate ASN list from both upstreams and downstreams
        asn_set = set()
        for peer_type in ['upstreams', 'downstreams']:
            for version in connectivity.get(peer_type, {}):
                asn_set.update(connectivity[peer_type][version].keys())

        asn_info = fetch_asn_info(list(asn_set), db_manager)

        # Merge ASN info into connectivity data
        for peer_type in ['upstreams', 'downstreams']:
            for version, peers in connectivity[peer_type].items():
                for asn, info in peers.items():
                    if asn in asn_info:
                        if not info.get('country'):
                            info['country'] = asn_info[asn]['country']
                        if not info.get('name'):
                            info['name'] = asn_info[asn]['name']

        connectivity['exchanges'] = list_exchanges()
        return json.dumps(connectivity)
    finally:
        db_manager.close()

if __name__ == "__main__":
    # Fetch the peer list from PeeringDB before processing
    # PEER_LIST = list_total_peers()
    result_json = main()
    output_path = "/var/www/connectivity.json"
    with open(output_path, "w") as fp:
        fp.write(result_json)
    logging.info("Connectivity data written to %s", output_path)
    print(result_json)
