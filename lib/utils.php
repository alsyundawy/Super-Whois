<?php
/** lib/utils.php — Rate limiting, input sanitization, query classification, RIR routing */

// ── RIR Routing ───────────────────────────────────────────────────────────

function getRIRServer(string $ip): string {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'whois.arin.net';
    $l = ip2long($ip);
    $r = fn($a,$b) => $l >= ip2long($a) && $l <= ip2long($b);
    // APNIC
    if ($r('1.0.0.0','1.255.255.255')||$r('14.0.0.0','14.255.255.255')||
        $r('27.0.0.0','27.255.255.255')||$r('49.0.0.0','49.255.255.255')||
        $r('58.0.0.0','60.255.255.255')||$r('101.0.0.0','103.255.255.255')||
        $r('110.0.0.0','126.255.255.255')||$r('175.0.0.0','180.255.255.255')||
        $r('182.0.0.0','183.255.255.255')||$r('202.0.0.0','203.255.255.255')||
        $r('210.0.0.0','211.255.255.255')||$r('218.0.0.0','223.255.255.255'))
        return 'whois.apnic.net';
    // RIPE
    if ($r('2.0.0.0','2.255.255.255')||$r('5.0.0.0','5.255.255.255')||
        $r('31.0.0.0','31.255.255.255')||$r('37.0.0.0','37.255.255.255')||
        $r('46.0.0.0','46.255.255.255')||$r('77.0.0.0','95.255.255.255')||
        $r('176.0.0.0','178.255.255.255')||$r('185.0.0.0','185.255.255.255')||
        $r('188.0.0.0','195.255.255.255')||$r('212.0.0.0','213.255.255.255')||
        $r('217.0.0.0','217.255.255.255'))
        return 'whois.ripe.net';
    // LACNIC
    if ($r('177.0.0.0','177.255.255.255')||$r('179.0.0.0','179.255.255.255')||
        $r('181.0.0.0','181.255.255.255')||$r('186.0.0.0','191.255.255.255')||
        $r('200.0.0.0','201.255.255.255'))
        return 'whois.lacnic.net';
    // AFRINIC
    if ($r('41.0.0.0','41.255.255.255')||$r('102.0.0.0','102.255.255.255')||
        $r('105.0.0.0','105.255.255.255')||$r('154.0.0.0','154.255.255.255')||
        $r('196.0.0.0','197.255.255.255'))
        return 'whois.afrinic.net';
    return 'whois.arin.net';
}

// ── Rate Limiting ──────────────────────────────────────────────────────────

/**
 * Enforce per-IP rate limiting using a single JSON file per IP.
 * On success, returns rate limit headers array.
 * On failure, sets HTTP 429 and exits.
 *
 * @param string $context  'web' or 'api' — used for log event name
 */
function enforceRateLimit(string $context = 'web'): array {
    $dir = RATE_STORE;
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $ip   = getClientIP();
    $key  = preg_replace('/[^a-z0-9.:]/i', '_', strtolower($ip));
    $file = $dir . '/' . $key . '.json';
    $now  = time();
    $fp   = fopen($file, 'c+');
    if (!$fp) {
        appendLog('rate_store_error', ['context' => $context]);
        http_response_code(500);
        exit('Rate limit storage unavailable.');
    }
    flock($fp, LOCK_EX);
    $size = filesize($file);
    $raw  = $size > 0 ? fread($fp, $size) : '';
    $data = json_decode($raw, true) ?: ['count' => 0, 'reset' => $now + RATE_WINDOW];
    if ($now > $data['reset'] || !isset($data['count'])) {
        $data = ['count' => 0, 'reset' => $now + RATE_WINDOW];
    }
    $data['count']++;
    ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp); flock($fp, LOCK_UN); fclose($fp);

    $headers = [
        'X-RateLimit-Limit'     => RATE_LIMIT,
        'X-RateLimit-Remaining' => max(0, RATE_LIMIT - $data['count']),
        'X-RateLimit-Reset'     => $data['reset'],
    ];

    if ($data['count'] > RATE_LIMIT) {
        appendLog('rate_limit_exceeded', ['context' => $context, 'count' => $data['count']]);
        http_response_code(429);
        if ($context === 'api') {
            header('Content-Type: application/json');
            foreach ($headers as $k => $v) header("$k: $v");
            echo json_encode(['error' => 'Rate limit exceeded.', 'code' => 429,
                'retry_after' => $data['reset']]);
        } else {
            echo 'Rate limit exceeded. Try again after ' . gmdate('H:i', $data['reset']) . ' UTC.';
        }
        exit();
    }
    return $headers;
}

/**
 * Sanitize query input (strip URLs, ports, whitespace).
 */
function sanitizeQuery(string $input): string {
    $q = trim($input);
    $q = preg_replace('/^https?:\/\//i', '', $q);
    $q = explode('/', $q, 2)[0];
    $q = preg_replace('/:\d+$/', '', $q);
    $q = preg_replace('/\s+/', '', $q);
    return substr($q, 0, 253);
}

/**
 * Check whether a domain string is a valid query to dispatch.
 */
function classifyQuery(string $q): string {
    if (filter_var($q, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'ipv4';
    if (filter_var($q, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'ipv6';
    if (preg_match('/^AS\d{1,10}$/i', $q))                   return 'asn';
    $ascii = idn_to_ascii($q, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($ascii !== false
        && filter_var($ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
        && substr_count($ascii, '.') >= 1)
        return 'domain';
    return 'invalid';
}
