<?php
/**
 * lib/network.php — Network helpers: IP resolution, socket queries, WHOIS referrals
 */

// ── Network ────────────────────────────────────────────────────────────────

function getClientIP(): string {
    static $cached = null;
    if ($cached !== null) return $cached;
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (TRUST_PROXY) {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        }
    }
    $cached = filter_var($ip, FILTER_VALIDATE_IP) ?: 'unknown';
    return $cached;
}

/**
 * Resolve a hostname to a public IP string safe for fsockopen.
 * Returns "[ipv6]" for IPv6, plain string for IPv4, null if private/invalid.
 */
function getSafeWhoisIP(string $host): ?string {
    $host = strtolower(trim($host));
    if ($host === '') return null;
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ip = $host;
    } else {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (empty($records)) return null;
        $ip = null;
        foreach ($records as $rec) {
            if (isset($rec['ip']))   { $ip = $rec['ip'];   break; }
            if (isset($rec['ipv6'])) { $ip = $rec['ipv6']; break; }
        }
        if (!$ip) return null;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return null;
    }
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$ip]" : $ip;
}

/**
 * Open a TCP socket to WHOIS port 43, send query, return lines array.
 */
function queryWhoisServer(string $server, string $query, int $timeout = 7): array {
    $ip = getSafeWhoisIP($server);
    if (!$ip) return [];
    $sock = @fsockopen($ip, 43, $errno, $errstr, $timeout);
    if (!$sock) return [];
    stream_set_timeout($sock, $timeout);
    fwrite($sock, $query . "\r\n");
    $raw = '';
    while (!feof($sock)) {
        $chunk = fgets($sock, 4096);
        if ($chunk === false) break;
        $raw .= $chunk;
        if (strlen($raw) > 524288) break;
    }
    fclose($sock);
    return explode("\n", $raw);
}

/**
 * Query a text server on custom TCP port (e.g. whois.nic.ch:4343).
 */
function queryTextServer(string $server, int $port, string $query, int $timeout = 7): array {
    $ip = getSafeWhoisIP($server);
    if (!$ip || $port < 1 || $port > 65535) return [];
    $sock = @fsockopen($ip, $port, $errno, $errstr, $timeout);
    if (!$sock) return [];
    stream_set_timeout($sock, $timeout);
    fwrite($sock, $query . "\r\n");
    $raw = '';
    while (!feof($sock)) {
        $chunk = fgets($sock, 4096);
        if ($chunk === false) break;
        $raw .= $chunk;
        if (strlen($raw) > 524288) break;
    }
    fclose($sock);
    return explode("\n", $raw);
}

/**
 * Query primary WHOIS server; if response contains a Registrar WHOIS Server,
 * follow the referral once for richer data.
 */
function resolveFullWhois(string $server, string $query): array {
    $lines = queryWhoisServer($server, $query);
    if (empty($lines)) return [$lines, $server];
    $referral = null;
    foreach ($lines as $line) {
        if (preg_match('/^Registrar WHOIS Server\s*:\s*(.+)$/i', trim($line), $m)) {
            $c = strtolower(trim($m[1]));
            if ($c !== '' && strcasecmp($c, $server) !== 0) { $referral = $c; break; }
        }
    }
    if ($referral !== null) {
        $full = queryWhoisServer($referral, $query, 5);
        if (count($full) > 5) return [$full, $referral];
    }
    return [$lines, $server];
}
