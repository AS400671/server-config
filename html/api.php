<?php

/*
    AS400671 PoP API

    Installation
    * php7+ with php-sqlite
    * bird2
    * vnstat
    * add www-data to bird group

    API Usage
    * ?method=ip
    * ?method=traffic
    * ?method=ping&target=1.1.1.1
    * ?method=traceroute&target=1.1.1.1
    * ?method=bgp_status
    * ?method=bgp_route_for&target=1.1.1.1
    * ?method=connectivity

    Please set before use
    * INTERFACE_NAME
    * SOURCE_IPV4
    * SOURCE_IPV6
*/

//  ip link property add dev enp1s0 altname eth0
define("INTERFACE_NAME", "eth0");

// Define network ethernets: if you do not use IPv4, keep it as eth0
define("NETWORK4_ID", INTERFACE_NAME);
define("NETWORK6_ID", "wg0");
define("SOURCE_IPV4", getInterfaceIP(NETWORK4_ID));
define("SOURCE_IPV6", getInterfaceIP(NETWORK6_ID, true));
define("CURRENT_VERSION", "v1.2.2-220810");
define("API_KEY", null);
define("ENABLE_CACHE", true);

set_time_limit(60);
error_reporting(0);
ini_set("display_errors", "off");

header("Content-Type: application/json");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Origin: *");

function check_cache(string $method, string $argument)
{
    global $cache_db;

    /* Limit 120 */
    $stm = $cache_db->prepare(
        "SELECT COUNT(*) AS requests FROM cache WHERE timestamp > :timestamp"
    );
    $stm->bindValue(":timestamp", (int) (time() - 60), SQLITE3_INTEGER);
    $res = $stm->execute();
    $count = $res->fetchArray()["requests"];
    if ($count >= 120) {
        return [
            "result" => "Ratelimited!",
            "status" => "error",
        ];
    }

    /* Get cached data if exists */
    $stm = $cache_db->prepare(
        "SELECT * FROM cache WHERE method = :method AND argument = :argument AND timestamp > :timestamp"
    );
    $stm->bindValue(":method", $method, SQLITE3_TEXT);
    $stm->bindValue(":argument", $argument, SQLITE3_TEXT);
    $stm->bindValue(":timestamp", (int) (time() - 60), SQLITE3_INTEGER);
    $res = $stm->execute();
    $row = $res->fetchArray();

    if ($row) {
        return [
            "result" => $row["result"],
            "status" => "success",
        ];
    }

    return false;
}

function write_cache(string $method, string $argument, string $result)
{
    global $cache_db;
    $stm = $cache_db->prepare(
        "INSERT INTO cache (timestamp, method, argument, result) VALUES (:timestamp, :method, :argument, :result)"
    );
    $stm->bindValue(":method", $method, SQLITE3_TEXT);
    $stm->bindValue(":argument", $argument, SQLITE3_TEXT);
    $stm->bindValue(":timestamp", time(), SQLITE3_INTEGER);
    $stm->bindValue(":result", $result, SQLITE3_TEXT);
    @$stm->execute();
    return true;
}

/* IP check */
function getInterfaceIP(string $interface = "eth0", bool $isV6 = false)
{
    if ($isV6) {
        $command =
            "$(/usr/bin/which ifconfig) " .
            escapeshellarg($interface) .
            " | grep 'inet6 ' | cut -d' ' -f10 | awk '{ print $1 }' | head -1";
    } else {
        $command =
            "$(/usr/bin/which ifconfig) " .
            escapeshellarg($interface) .
            " | grep 'inet ' | cut -d' ' -f10 | awk '{ print $1 }' | head -1";
    }
    $output = trim(@shell_exec($command));
    return $output;
}

function gethostbyname6(string $host, bool $try_a = false)
{
    $dns = gethostbynamel6($host, $try_a);
    if ($dns == false) {
        return false;
    } else {
        return $dns[0];
    }
}

function gethostbynamel6(string $host, bool $try_a = false)
{
    $dns6 = dns_get_record($host, DNS_AAAA);
    if ($try_a == true) {
        $dns4 = dns_get_record($host, DNS_A);
        $dns = array_merge($dns4, $dns6);
    } else {
        $dns = $dns6;
    }

    $ip6 = [];
    $ip4 = [];

    foreach ($dns as $record) {
        if ($record["type"] == "A") {
            $ip4[] = $record["ip"];
        }
        if ($record["type"] == "AAAA") {
            $ip6[] = $record["ipv6"];
        }
    }

    if (count($ip6) < 1) {
        if ($try_a == true) {
            if (count($ip4) < 1) {
                return false;
            }
            return $ip4;
        } else {
            return false;
        }
    } else {
        return $ip6;
    }
}

function sanitize_ip_address(string $ip_address): string
{
    $ip_address = preg_replace("/[^A-Fa-f0-9\.\:\/]/u", "", $ip_address);
    return $ip_address;
}

function sanitize_domain_name(string $domain_name): string
{
    $domain_name = preg_replace("/[^A-Za-z0-9\-\.]/u", "", $domain_name);
    return $domain_name;
}

function validate_domain_name(string $domain_name): string
{
    $domain_regex =
        "^(?!\-)(?:(?:[a-zA-Z\d][a-zA-Z\d\-]{0,61})?[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$";
    return $domain_regex;
}

function validate_ip_address(string $ip_address, bool $prefix = false): bool
{
    /* Returns true if the IP is valid */
    if (!$ip_address) {
        return false;
    }
    if ($prefix) {
        $parse_data = explode("/", $ip_address);
        if(count($parse_data) == 2){
            $parse_ip = $parse_data[0];
            $parse_prefix = $parse_data[1];
            if($parse_ip && is_numeric($parse_prefix)){
                return filter_var($parse_ip, FILTER_VALIDATE_IP) &&
                    ($parse_prefix <= 128 && $parse_prefix >= 0);
            }
        }
    }
    return filter_var($ip_address, FILTER_VALIDATE_IP);
}

function check_ip_version(string $ip_address): string
{
    /* Returns 6 if the string is a valid IPv6 */
    if (
        filter_var($ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
    ) {
        return "6";
    } else {
        return "";
    }
}

/* Caching */
$cache_db = new SQLite3("/tmp/api_cache.db");
$cache_db->exec(
    "CREATE TABLE IF NOT EXISTS cache (id INTEGER PRIMARY KEY, timestamp INTEGER, method TEXT, argument TEXT, result TEXT);"
);

/* Optimize database */
$stm = $cache_db->prepare("SELECT COUNT(*) AS requests FROM cache");
$res = $stm->execute();
$count = $res->fetchArray()["requests"];
if ($count >= 65535) {
    $cache_db->exec("DELETE FROM cache");
}

/* Init */
$method = (string) $_GET["method"];
$argument = (string) $_GET["target"];
$result = null;

/* Cache Check */
if (ENABLE_CACHE) {
    $result = check_cache($method, $argument);
    if ($result) {
        $result["version"] = CURRENT_VERSION;
        $result["cached"] = true;
        die(json_encode($result));
    }
}

/* Check method */
switch ($method) {
    case "ip":
        $result = [
            "result" => $_SERVER["REMOTE_ADDR"],
            "status" => "success",
        ];
        break;

    case "traffic":
        $command =
            "vnstat -i " . escapeshellarg(INTERFACE_NAME) . " --json h 24";
        $result = [
            "result" => json_encode(
                json_decode(trim(shell_exec($command)))->interfaces[0]->traffic
            ),
            "status" => "success",
        ];
        write_cache($method, $argument, $result["result"]);
        break;

    case "ping":
        $target = (string) $argument;
        if (validate_ip_address($target)) {
            $ip_version = check_ip_version($target);
            $target = sanitize_ip_address($target);
        } elseif (validate_domain_name($target)) {
            $ip_version = check_ip_version(gethostbyname6($target));
            $target = sanitize_domain_name($target);
        } else {
            break;
        }
        $ip_source = $ip_version === "6" ? SOURCE_IPV6 : SOURCE_IPV4;
        $target = escapeshellarg($target);
        $command = "timeout 10 $(/usr/bin/which ping{$ip_version}) {$target} -I '{$ip_source}' -c 4 -l 2 -i 0.2 -W 2 2>&1";

        $result = [
            "result" => trim(shell_exec($command)),
            "command" => $command,
            "status" => "success",
        ];
        write_cache($method, $argument, $result["result"]);
        break;

    case "traceroute":
        $target = (string) $argument;
        if (validate_ip_address($target)) {
            $ip_version = check_ip_version($target);
            $target = sanitize_ip_address($target);
        } elseif (validate_domain_name($target)) {
            $ip_version = check_ip_version(gethostbyname6($target));
            $target = sanitize_domain_name($target);
        } else {
            break;
        }
        $ip_source = $ip_version === "6" ? SOURCE_IPV6 : SOURCE_IPV4;
        $target = escapeshellarg($target);
        $command = "timeout 60 $(/usr/bin/which traceroute{$ip_version}) -A -n -w 1 -q 1 -s '{$ip_source}' {$target} 2>&1";
        $result = [
            "result" => trim(shell_exec($command)),
            "status" => "success",
        ];
        write_cache($method, $argument, $result["result"]);
        break;

    case "bgp_announcement":
        $command_real = "show static static1";
        $command_real = escapeshellarg($command_real);
        $command = "timeout 3 $(/usr/bin/which birdc) -r {$command_real} 2>&1 | tail -n +3";

        $result = [
            "result" => trim(shell_exec($command)),
            "status" => "success",
        ];
        write_cache($method, $argument, $result["result"]);
        break;

    case "bgp_status":
        $command_real = "show proto all";
        $command_real = escapeshellarg($command_real);
        $command = "timeout 3 $(/usr/bin/which birdc) -r {$command_real} 2>&1 | tail -n +3";

        $result = [
            "result" => trim(shell_exec($command)),
            "status" => "success",
        ];
        write_cache($method, $argument, $result["result"]);
        break;

    case "bgp_route_for":
        $target = sanitize_ip_address($argument);
        if (!($target && validate_ip_address($target, true))) {
            break;
        }

        $command_real = "show route all for {$target}";
        $command_real = escapeshellarg($command_real);
        $command = "timeout 3 $(/usr/bin/which birdc) -r {$command_real} 2>&1 | tail -n +3";
        $result = [
            "result" => trim(shell_exec($command)),
            "status" => "success",
        ];
        write_cache($method, $argument, $result["result"]);
        break;

    case "connectivity":
        $result = [
            "result" => file_get_contents("/var/www/connectivity.json"),
            "status" => "success",
        ];
        write_cache($method, "", $result["result"]);
        break;

    default:
        $result = [
            "result" => "Unknown method",
            "status" => "error",
        ];
}

/* API key check */
if (API_KEY && API_KEY !== (string) $_GET["api_key"]) {
    die(
        json_encode([
            "result" => "Invalid API key",
            "status" => "error",
        ])
    );
}

$result["cached"] = false;
$result["version"] = CURRENT_VERSION;
die(json_encode($result));

?>
