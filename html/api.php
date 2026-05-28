<?php

declare(strict_types=1);

/*
    AS400671 PoP Looking Glass API

    Installation
    * php8.4+ with php-sqlite
    * bird3
    * vnstat
    * add www-data to bird group

    API Usage
    * ?method=ip
    * ?method=traffic
    * ?method=ping&target=1.1.1.1
    * ?method=traceroute&target=1.1.1.1
    * ?method=bgp_route_for&target=1.1.1.1
    * ?method=connectivity

    Please set before use
    * INTERFACE_NAME
    * NETWORK4_ID / NETWORK6_ID
    * BIRD_MASTER6 / BIRD_MASTER4
*/

/* --- Setup --- */

define("INTERFACE_NAME",  "enp1s0"); // Use `ip link property add dev enp1s0 altname eth0`
define("NETWORK4_ID",     "wg0"); // Define network ethernets: if you do not use IPv4, keep it as eth0
define("NETWORK6_ID",     "wg0");
define("BIRD_MASTER4",    "static5"); // Usually static1, check via `birdc show proto`
define("BIRD_MASTER6",    "static4"); // Usually static2, check via `birdc show proto`
define("SOURCE_IPV4",     get_interface_ip(NETWORK4_ID));
define("SOURCE_IPV6",     get_interface_ip(NETWORK6_ID, true));
define("CURRENT_VERSION", "v1.4.2-260528");
define("ENABLE_CACHE",    true);
define("CORS_HOST",       "https://stypr.network"); // Change to dashboard domain

set_time_limit(60);
error_reporting(0);
ini_set("display_errors", "off");

header("Content-Type: application/json");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Origin: " . CORS_HOST);


/* --- Return OPTIONS --- */

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(204);
    exit;
}

/* --- Utilities --- */

function abort(array $payload): never
{
    die(json_encode($payload));
}

function ok(string $result): array
{
    return ["result" => $result, "status" => "success"];
}

function err(string $message): array
{
    return ["result" => $message, "status" => "error"];
}

function binary_path(string $name): string
{
    static $cache = [];
    if (!array_key_exists($name, $cache)) {
        $path = trim((string) shell_exec("/usr/bin/which " . escapeshellarg($name)));
        $cache[$name] = is_executable($path) ? $path : "";
    }
    return $cache[$name];
}

/* --- Cache --- */

function is_rate_limited(SQLite3 $db): bool
{
    $stm = $db->prepare("SELECT COUNT(*) AS n FROM cache WHERE timestamp > :ts");
    $stm->bindValue(":ts", time() - 60, SQLITE3_INTEGER);
    return (int) $stm->execute()->fetchArray(SQLITE3_ASSOC)["n"] >= 120;
}

function check_cache(SQLite3 $db, string $method, string $argument): array|false
{
    $stm = $db->prepare("SELECT result FROM cache WHERE method = :method AND argument = :argument AND timestamp > :ts");
    $stm->bindValue(":method",   $method,     SQLITE3_TEXT);
    $stm->bindValue(":argument", $argument,   SQLITE3_TEXT);
    $stm->bindValue(":ts",       time() - 60, SQLITE3_INTEGER);
    $row = $stm->execute()->fetchArray(SQLITE3_ASSOC);
    return $row !== false ? ["result" => $row["result"], "status" => "success"] : false;
}

function write_cache(SQLite3 $db, string $method, string $argument, string $result): void
{
    $stm = $db->prepare(
        "INSERT INTO cache (timestamp, method, argument, result) VALUES (:ts, :method, :argument, :result)"
    );
    $stm->bindValue(":method",   $method,   SQLITE3_TEXT);
    $stm->bindValue(":argument", $argument, SQLITE3_TEXT);
    $stm->bindValue(":ts",       time(),    SQLITE3_INTEGER);
    $stm->bindValue(":result",   $result,   SQLITE3_TEXT);
    $stm->execute();
}

/* --- Network utils --- */

function get_interface_ip(string $interface = "eth0", bool $ipv6 = false): string
{
    $bin = binary_path("ip");
    if ($bin === "") {
        return "";
    }
    $family = $ipv6 ? "-6" : "-4";
    $cmd = sprintf(
        "%s %s -j addr show dev %s 2>/dev/null",
        escapeshellcmd($bin),
        $family,
        escapeshellarg($interface)
    );
    $raw = (string) shell_exec($cmd);
    if (!json_validate($raw)) {
        return "";
    }
    $data = json_decode($raw, true);
    if (!is_array($data) || empty($data[0]["addr_info"])) {
        return "";
    }

    foreach ($data[0]["addr_info"] as $addr) {
        if (($addr["scope"] ?? "") !== "global") {
            continue;
        }
        $ip = $addr["local"] ?? "";
        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            return $ip;
        }
    }
    return "";
}

function dns_lookup(string $host, bool $try_a = false): string|false
{
    $dns4 = $try_a ? (dns_get_record($host, DNS_A)   ?: []) : [];
    $dns6 =           dns_get_record($host, DNS_AAAA) ?: [];
    $records = array_merge($dns4, $dns6);

    // array_find should return first matching element (PHP 8.4+ )
    $aaaa = array_find($records, fn(array $r): bool => $r["type"] === "AAAA");
    if ($aaaa !== null) {
        return $aaaa["ipv6"];
    }

    if ($try_a) {
        $a = array_find($records, fn(array $r): bool => $r["type"] === "A");
        if ($a !== null) {
            return $a["ip"];
        }
    }

    return false;
}

function sanitize_ip(string $ip): string
{
    return (string) preg_replace('/[^A-Fa-f0-9.:\/]/', "", $ip);
}

function sanitize_domain(string $domain): string
{
    return (string) preg_replace('/[^A-Za-z0-9\-.]/', "", $domain);
}

function validate_domain(string $domain): bool
{
    return (bool) preg_match(
        '/^(?!\-)(?:(?:[a-zA-Z\d][a-zA-Z\d\-]{0,61})?[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$/',
        $domain
    );
}

function validate_ip(string $ip, bool $with_prefix = false): bool
{
    if ($ip === "") {
        return false;
    }

    if ($with_prefix) {
        [$addr, $prefix] = explode("/", $ip, 2) + ["", ""];
        if ($addr === "" || !is_numeric($prefix)) {
            return false;
        }

        $is_v6 = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        $is_v4 = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;

        if (!$is_v4 && !$is_v6) {
            return false;
        }

        $max = $is_v6 ? 128 : 32;
        return (int) $prefix >= 0 && (int) $prefix <= $max;
    }

    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function ip_version(string $ip): string
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? "6" : "";
}

function ip_in_cidr(string $ip, string $base, int $bits): bool
{
    $packed_ip   = inet_pton($ip);
    $packed_base = inet_pton($base);
    if ($packed_ip === false || $packed_base === false || strlen($packed_ip) !== strlen($packed_base)) {
        return false;
    }
    $full_bytes = intdiv($bits, 8);
    $rem_bits   = $bits % 8;
    if (substr($packed_ip, 0, $full_bytes) !== substr($packed_base, 0, $full_bytes)) {
        return false;
    }
    if ($rem_bits === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem_bits)) & 0xFF;
    return (ord($packed_ip[$full_bytes]) & $mask) === (ord($packed_base[$full_bytes]) & $mask);
}

function is_public_ip(string $ip): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    static $extra = [
        ['100.64.0.0',   10],  // RFC 6598  CGNAT
        ['192.0.0.0',    24],  // RFC 6890  IETF Protocol
        ['192.0.2.0',    24],  // RFC 5737  TEST-NET-1
        ['198.18.0.0',   15],  // RFC 2544  Benchmarking
        ['198.51.100.0', 24],  // RFC 5737  TEST-NET-2
        ['203.0.113.0',  24],  // RFC 5737  TEST-NET-3
        ['2001:db8::',   32],  // RFC 3849  Documentation
        ['2001::',       32],  // RFC 4380  Teredo
        ['2002::',       16],  // RFC 3056  6to4
    ];
    foreach ($extra as [$base, $bits]) {
        if (ip_in_cidr($ip, $base, $bits)) {
            return false;
        }
    }
    return true;
}

function resolve_target(string $argument): array|false
{
    if (validate_ip($argument)) {
        $ip = sanitize_ip($argument);
        if (!is_public_ip($ip)) {
            return false;
        }
        return [
            "version" => ip_version($ip),
            "ip" => $ip,
            "domain" => null
        ];
    }
    if (validate_domain($argument)) {
        $resolved = dns_lookup($argument, try_a: true);
        if ($resolved === false || !is_public_ip($resolved)) {
            return false;
        }
        return [
            "version" => ip_version($resolved),
            "ip" => $resolved,
            "domain" => sanitize_domain($argument)
        ];
    }
    return false;
}

/* --- handlers --- */

function handle_ip(): array
{
    return ok($_SERVER["REMOTE_ADDR"]);
}

function handle_traffic(SQLite3 $db, string $method, string $argument): array
{
    $bin_path = binary_path("vnstat");
    if ($bin_path === "") {
        return err("vnstat unavailable");
    }
    $raw = (string) shell_exec(escapeshellcmd($bin_path) . " -i " . escapeshellarg(INTERFACE_NAME) . " --json h 24");

    if (!json_validate($raw)) {
        return err("vnstat unavailable");
    }

    $decoded = json_decode($raw);
    $traffic = $decoded->interfaces[0]->traffic ?? null;
    if ($traffic === null) {
        return err("traffic data unavailable");
    }

    $result = ok((string) json_encode($traffic));
    write_cache($db, $method, $argument, $result["result"]);
    return $result;
}

function handle_probe(string $tool, SQLite3 $db, string $method, array $target_data): array
{
    ["version" => $ver, "ip" => $target] = $target_data;

    $ip_source = $ver === "6" ? SOURCE_IPV6 : SOURCE_IPV4;
    if ($ip_source === "") {
        return err("source interface unavailable");
    }

    $timeout_path = binary_path("timeout");
    if ($timeout_path === "") {
        return err("timeout not found");
    }

    $bin_path = binary_path("{$tool}{$ver}");
    if ($bin_path === "") {
        return err("target binary not found");
    }

    $timeout = escapeshellcmd($timeout_path);
    $bin     = escapeshellcmd($bin_path);
    $t       = escapeshellarg($target);
    $src     = escapeshellarg($ip_source);

    $command = match($tool) {
        "ping"       => "{$timeout} 10 {$bin} {$t} -I {$src} -c 4 -l 2 -i 0.2 -W 2 2>&1",
        "traceroute" => "{$timeout} 60 {$bin} -A -n -w 1 -q 1 -s {$src} {$t} 2>&1",
        default      => throw new \ValueError("Unknown probe tool: {$tool}"),
    };

    $result = ok(trim((string) shell_exec($command)));
    $result["target"] = $target;
    $result["domain"] = $target_data["domain"];
    write_cache($db, $method, $target, $result["result"]);
    return $result;
}

function handle_birdc(SQLite3 $db, string $method, string $argument, string ...$cmds): array
{
    $bin_path = binary_path("birdc");
    if ($bin_path === "") {
        return err("daemon not available");
    }
    $timeout_path = binary_path("timeout");
    if ($timeout_path === "") {
        return err("timeout not found");
    }
    $timeout = escapeshellcmd($timeout_path);
    $bin     = escapeshellcmd($bin_path);
    $parts   = array_map(
        fn(string $cmd): string => trim(
            (string) shell_exec("{$timeout} 3 {$bin} -r " . escapeshellarg($cmd) . " 2>&1 | tail -n +3")
        ),
        $cmds
    );

    $result = ok(implode("\n\t", $parts));
    write_cache($db, $method, $argument, $result["result"]);
    return $result;
}

function handle_bgp_route_for(SQLite3 $db, string $method, string $argument): array
{
    $target = sanitize_ip($argument);
    if (!validate_ip($target) && !validate_ip($target, with_prefix: true)) {
        return err("Invalid target");
    }

    $addr = explode("/", $target, 2)[0];
    if (!is_public_ip($addr)) {
        return err("Private or reserved addresses not allowed");
    }

    $bin_path = binary_path("birdc");
    if ($bin_path === "") {
        return err("daemon not available");
    }
    $timeout_path = binary_path("timeout");
    if ($timeout_path === "") {
        return err("timeout not found");
    }

    $timeout = escapeshellcmd($timeout_path);
    $bin     = escapeshellcmd($bin_path);
    $cmd     = escapeshellarg("show route all for {$target}");
    $result  = ok(trim((string) shell_exec("{$timeout} 3 {$bin} -r {$cmd} 2>&1 | tail -n +3")));
    write_cache($db, $method, $argument, $result["result"]);
    return $result;
}

function handle_connectivity(SQLite3 $db): array
{
    $content = file_get_contents("/var/www/connectivity.json");
    if ($content === false) {
        return err("connectivity data not available");
    }
    $result = ok($content);
    write_cache($db, "connectivity", "", $result["result"]);
    return $result;
}

/* --- Bootstrap --- */

// if you use systemd hardening `/tmp` will be sandboxed, check bird/scripts/systemd-hardening/
$cache_db = new SQLite3("/tmp/api_cache.db");
$cache_db->exec(
    "CREATE TABLE IF NOT EXISTS cache (id INTEGER PRIMARY KEY, timestamp INTEGER, method TEXT, argument TEXT, result TEXT);"
);

$row = $cache_db->prepare("SELECT COUNT(*) AS n FROM cache")->execute()->fetchArray(SQLITE3_ASSOC);
if ((int) ($row["n"] ?? 0) >= 65535) {
    $cache_db->exec("DELETE FROM cache");
}

/* --- Cache + Rebinding check --- */

$method   = (string) ($_GET["method"] ?? "");
$argument = (string) ($_GET["target"] ?? "");

if (ENABLE_CACHE && is_rate_limited($cache_db)) {
    abort([
        ...err("Ratelimited!"),
        "cached"  => false,
        "version" => CURRENT_VERSION,
    ]);
}

$target_data = null;
$cache_key   = $argument;
if ($method === "ping" || $method === "traceroute") {
    if (ENABLE_CACHE && check_cache($cache_db, "{$method}:invalid", $argument) !== false) {
        abort([
            ...err("invalid target"),
            "cached"  => true,
            "version" => CURRENT_VERSION,
        ]);
    }

    $target_data = resolve_target($argument);
    if ($target_data === false) {
        write_cache($cache_db, "{$method}:invalid", $argument, "1");
        abort([
            ...err("invalid target"),
            "cached"  => false,
            "version" => CURRENT_VERSION,
        ]);
    }
    $cache_key = $target_data["ip"];
}

if (ENABLE_CACHE) {
    $cached = check_cache($cache_db, $method, $cache_key);
    if ($cached !== false) {
        $payload = [
            ...$cached,
            "version" => CURRENT_VERSION,
            "cached"  => true,
        ];
        if ($target_data !== null) {
            $payload["target"] = $target_data["ip"];
            $payload["domain"] = $target_data["domain"];
        }
        abort($payload);
    }
}

$result = match($method) {
    "ip"               => handle_ip(),
    "traffic"          => handle_traffic($cache_db, $method, $argument),
    "ping"             => handle_probe("ping",       $cache_db, $method, $target_data),
    "traceroute"       => handle_probe("traceroute", $cache_db, $method, $target_data),
    "bgp_announcement" => handle_birdc($cache_db, $method, $argument, "show static " . BIRD_MASTER4, "show static " . BIRD_MASTER6),
    "bgp_route_for"    => handle_bgp_route_for($cache_db, $method, $argument),
    "connectivity"     => handle_connectivity($cache_db),
    default            => err("Unknown method"),
};

abort([
    ...$result,
    "cached" => false,
    "version" => CURRENT_VERSION
]);
