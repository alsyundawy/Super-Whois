<?php
// lib/rdap.php — RDAP bootstrap, lookup, and response parsing

function whoisFetchRdapResponse(string $url): array {
    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 8,
            'ignore_errors' => true,
            'header' => "Accept: application/rdap+json, application/json\r\nUser-Agent: SuperWhois/3.0\r\n",
        ],
    ]);
    $body = @file_get_contents($url, false, $ctx);
    $headers = $http_response_header ?? [];
    $code = 0;
    foreach ($headers as $h) {
        if (preg_match('/^HTTP\/\d+\.\d+\s+(\d+)/i', $h, $m)) $code = (int)$m[1];
    }
    return ['code' => $code, 'body' => ($body === false ? '' : $body)];
}

function getRdapBootstrapData(): array {
    static $cache = null;
    if (is_array($cache)) return $cache;
    $data = cacheGetOrFetch('rdap_bootstrap', CACHE_TTL_RDAP, function () {
        $resp = whoisFetchRdapResponse('https://data.iana.org/rdap/dns.json');
        if ($resp['code'] !== 200 || $resp['body'] === '') return null;
        $json = json_decode($resp['body'], true);
        if (!is_array($json) || empty($json['services']) || !is_array($json['services'])) return null;
        return $json['services'];
    });
    $cache = is_array($data) ? $data : [];
    return $cache;
}

/**
 * Resolve RDAP base URL for domain via IANA bootstrap.
 * Longest matching suffix wins.
 */
function resolveRdapBaseForDomain(string $domainAscii): ?string {
    $domainAscii = strtolower(trim($domainAscii, '.'));
    $services = getRdapBootstrapData();
    $bestBase = null;
    $bestLen = -1;
    foreach ($services as $service) {
        if (!is_array($service) || count($service) < 2) continue;
        $suffixes = $service[0];
        $bases = $service[1];
        if (!is_array($suffixes) || !is_array($bases) || empty($bases[0])) continue;
        foreach ($suffixes as $suffix) {
            $suffix = strtolower((string)$suffix);
            if ($suffix === '') continue;
            if ($domainAscii === $suffix || str_ends_with($domainAscii, '.' . $suffix)) {
                $len = strlen($suffix);
                if ($len > $bestLen) {
                    $bestLen = $len;
                    $bestBase = (string)$bases[0];
                }
            }
        }
    }
    return $bestBase;
}

/**
 * Perform RDAP lookup and normalize into common structure.
 */
function lookupDomainViaRdap(string $domainAscii, ?array $preferredBases = null): ?array {
    $bases = [];
    if (is_array($preferredBases)) {
        foreach ($preferredBases as $b) {
            $b = trim((string)$b);
            if ($b !== '') $bases[] = $b;
        }
    }
    $bootstrapBase = resolveRdapBaseForDomain($domainAscii);
    if ($bootstrapBase !== null) $bases[] = $bootstrapBase;
    $bases = array_values(array_unique($bases));
    if (empty($bases)) return null;

    foreach ($bases as $base) {
        $base = rtrim($base, '/');
        $url = $base . '/domain/' . rawurlencode($domainAscii);
        $resp = whoisFetchRdapResponse($url);
        $code = (int)$resp['code'];
        $host = parse_url($base, PHP_URL_HOST) ?: $base;
        if ($code === 404) {
            return [
                'status' => 'available',
                'method' => 'rdap',
                'server' => (string)$host,
                'parsed' => [],
                'raw'    => ["RDAP $code from $host", "Domain appears unregistered in RDAP."],
            ];
        }
        if ($code === 429) {
            appendLog('rdap_rate_limited', ['domain' => $domainAscii, 'base' => $base, 'code' => 429]);
            continue;
        }
        if ($code === 403) {
            appendLog('rdap_forbidden', ['domain' => $domainAscii, 'base' => $base, 'code' => 403]);
            continue;
        }
        if ($code >= 500 && $code < 600) {
            appendLog('rdap_server_error', ['domain' => $domainAscii, 'base' => $base, 'code' => $code]);
            continue;
        }
        if ($code === 200 || $code === 401) {
            $json = json_decode($resp['body'], true);
            if (!is_array($json)) $json = [];
            $raw = ["RDAP $code from $host"];
            if ($resp['body'] !== '') {
                $raw[] = '--- RDAP JSON ---';
                foreach (explode("\n", trim($resp['body'])) as $line) $raw[] = $line;
            }
            return [
                'status' => 'registered',
                'method' => 'rdap',
                'server' => (string)$host,
                'parsed' => whoisParseRdapDomainData($json),
                'raw'    => $raw,
            ];
        }
        appendLog('rdap_unexpected_code', ['domain' => $domainAscii, 'base' => $base, 'code' => $code]);
    }
    return null;
}

function whoisParseRdapDomainData(array $rdap): array {
    $out = [];
    if (!empty($rdap['events']) && is_array($rdap['events'])) {
        foreach ($rdap['events'] as $ev) {
            if (!is_array($ev) || empty($ev['eventAction']) || empty($ev['eventDate'])) continue;
            $action = strtolower((string)$ev['eventAction']);
            $date   = (string)$ev['eventDate'];
            if (in_array($action, ['registration', 'registered'], true) && empty($out['creation_date'])) $out['creation_date'] = $date;
            if (in_array($action, ['expiration', 'expiry'], true) && empty($out['expiration_date'])) $out['expiration_date'] = $date;
            if (in_array($action, ['last changed', 'last update of rdap database'], true) && empty($out['updated_date'])) $out['updated_date'] = $date;
        }
    }
    if (!empty($rdap['status']) && is_array($rdap['status'])) {
        $out['status'] = array_values(array_filter(array_map('strval', $rdap['status'])));
    }
    if (!empty($rdap['nameservers']) && is_array($rdap['nameservers'])) {
        $ns = [];
        foreach ($rdap['nameservers'] as $n) {
            if (is_array($n) && !empty($n['ldhName'])) $ns[] = strtolower((string)$n['ldhName']);
        }
        if (!empty($ns)) $out['nameservers'] = array_values(array_unique($ns));
    }
    if (!empty($rdap['secureDNS']) && is_array($rdap['secureDNS']) && array_key_exists('delegationSigned', $rdap['secureDNS'])) {
        $out['dnssec'] = !empty($rdap['secureDNS']['delegationSigned']) ? 'signed' : 'unsigned';
    }
    if (!empty($rdap['entities']) && is_array($rdap['entities'])) {
        foreach ($rdap['entities'] as $entity) {
            if (!is_array($entity)) continue;
            $roles = array_map('strtolower', array_map('strval', $entity['roles'] ?? []));
            $vcard = $entity['vcardArray'][1] ?? null;
            if (!is_array($vcard)) continue;

            // Helper: extract vcard value by type
            $getVcard = function (string $type) use ($vcard): ?string {
                foreach ($vcard as $v) {
                    if (is_array($v) && count($v) >= 4 && strtolower((string)$v[0]) === $type && !empty($v[3])) {
                        return (string)$v[3];
                    }
                }
                return null;
            };

            if (in_array('registrar', $roles, true)) {
                if (!empty($entity['handle']) && empty($out['registrar_iana_id'])) $out['registrar_iana_id'] = (string)$entity['handle'];
                $fn = $getVcard('fn');
                if ($fn !== null && empty($out['registrar'])) $out['registrar'] = $fn;
            }
            if (in_array('registrant', $roles, true)) {
                $fn = $getVcard('fn');
                if ($fn !== null && empty($out['registrant_name'])) $out['registrant_name'] = $fn;
                $org = $getVcard('org');
                if ($org !== null && empty($out['registrant_org'])) $out['registrant_org'] = $org;
                $email = $getVcard('email');
                if ($email !== null && empty($out['registrant_email'])) $out['registrant_email'] = $email;
                $tel = $getVcard('tel');
                if ($tel !== null && empty($out['registrant_phone'])) $out['registrant_phone'] = $tel;
            }
            if (in_array('administrative', $roles, true) && empty($out['admin_email'])) {
                $email = $getVcard('email');
                if ($email !== null) $out['admin_email'] = $email;
            }
            if (in_array('technical', $roles, true) && empty($out['tech_email'])) {
                $email = $getVcard('email');
                if ($email !== null) $out['tech_email'] = $email;
            }
            if (in_array('abuse', $roles, true)) {
                $email = $getVcard('email');
                if ($email !== null && empty($out['abuse_email'])) $out['abuse_email'] = $email;
                $tel = $getVcard('tel');
                if ($tel !== null && empty($out['abuse_phone'])) $out['abuse_phone'] = $tel;
            }
        }
    }
    return $out;
}
