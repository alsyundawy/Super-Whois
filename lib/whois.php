<?php
declare(strict_types=1);
// lib/whois.php — WHOIS lookup, fallback chain, routing, and server resolution

// ── Restricted WHOIS / RDAP fallback ───────────────────────────────────────

/**
 * Web WHOIS portals for TLDs that often block direct port-43 access.
 */
function whoisGetWebLookupUrl(string $tld): ?string {
    static $map = [
        'ch' => 'https://www.nic.ch/whois/',
        'li' => 'https://www.nic.li/',
        'es' => 'https://www.dominios.es/en/tools/search',
        'ao' => 'https://dns.ao/',
        'tt' => 'https://whois.nic.tt/',
        'uy' => 'https://nic.uy/whois/',
        'ba' => 'https://www.nic.ba/',
        'gr' => 'https://grweb.ics.forth.gr/public/whois',
        'it' => 'https://www.nic.it/en/tools/whois',
        'fr' => 'https://www.afnic.fr/',
        'eu' => 'https://www.eurid.eu/en/register-a-eu-domain/whois-domain-lookup/',
        'nl' => 'https://www.sidn.nl/whois',
        'br' => 'https://registro.br/tecnologia/ferramentas/whois/',
        'pl' => 'https://www.dns.pl/en/whois',
        'pt' => 'https://www.dns.pt/en/services/whois/',
        'se' => 'https://internetstiftelsen.se/en/domain/',
        'fi' => 'https://domain.fi/info/en/index/services/whois.html',
        'no' => 'https://www.norid.no/en/om-domenenavn/sjekk-domenenavn/',
        'at' => 'https://www.nic.at/en/service/whois-service',
        'dk' => 'https://www.dk-hostmaster.dk/en/find-whois',
        'cz' => 'https://www.nic.cz/whois/',
        'sk' => 'https://www.sk-nic.sk/en/whois/',
        'ro' => 'https://www.rotld.ro/en/whois/',
        'hr' => 'https://www.dns.hr/en/whois',
        'tr' => 'https://www.nic.tr/whois.php',
        'cn' => 'https://whois.cnnic.cn/',
        'jp' => 'https://jprs.jp/en/whois/',
        'kr' => 'https://whois.kr/',
        'tw' => 'https://whois.twnic.net.tw/',
        'hk' => 'https://www.hkdnr.hk/en_US/whois-search/',
        'sg' => 'https://www.sgnic.sg/domain-registration/whois-search',
        'my' => 'https://mynic.my/en/whois/',
        'id' => 'https://pandi.id/en/domain/whois/',
        'th' => 'https://whois.thnic.co.th/',
        'vn' => 'https://whois.vnnic.vn/',
        'ph' => 'https://www.dot.ph/whois',
        'nz' => 'https://www.dnc.org.nz/whois/search-the-whois-database/',
        'au' => 'https://whois.auda.org.au/',
        'za' => 'https://www.registry.net.za/whois.php',
    ];
    return $map[strtolower($tld)] ?? null;
}

/**
 * Detects if the WHOIS response is solely a legal disclaimer without actual domain fields.
 * This is a heuristic approach to catch soft-blocks from registries.
 */
function whoisIsDisclaimerOnly(array $lines): bool {
    // 0. 狀態互斥檢查：若明確指示網域可註冊（未找到），則它不是單純的「免責聲明阻擋」。
    // 這是修復邏輯短路的關鍵：未註冊的網域不會有資料標籤，但可能有免責聲明。
    if (whoisIndicatesDomainAvailable($lines)) {
        return false;
    }

    $raw = strtolower(implode("\n", $lines));

    // 1. 若包含實質的網域資料標籤，則它不是「純」免責聲明。
    $dataMarkers = [
        'domain name:', 'domain:', 'registry domain id:', 'registrar:',
        'creation date:', 'updated date:', 'name server:', 'nserver:',
        'registrant:', 'domain status:', 'status:'
    ];
    foreach ($dataMarkers as $marker) {
        if (str_contains($raw, $marker)) {
            return false;
        }
    }

    // 2. 在排除「可用」與「已註冊」後，尋找強烈的免責聲明阻擋指標。
    $disclaimerIndicators = [
        'terms of use',
        'by submitting a whois query',
        'compilation, repackaging, dissemination',
        'whois database is provided',
        'for information purposes only',
        'restrict or terminate your access'
    ];
    foreach ($disclaimerIndicators as $indicator) {
        if (str_contains($raw, $indicator)) {
            return true;
        }
    }

    return false;
}

/**
 * True if WHOIS response clearly indicates access-denied/rate-limited.
 */
function whoisLooksLikeDenied(array $lines): bool {
    $raw = strtolower(implode("\n", $lines));
    $patterns = [
        '/\baccess denied\b/i',
        '/\baccess restricted\b/i',
        '/\bquery(?:ing)? (?:is )?not permitted\b/i',
        '/\brequests?\s+of\s+this\s+client\s+are\s+not\s+permitted\b/i',
        '/\bqueries? (?:from|for) your (?:ip|host) (?:address )?(?:have been )?(?:blocked|denied)\b/i',
        '/\bquota exceeded\b/i',
        '/\brate[\s-]?limit(?:ed|ing)?\b/i',
        '/\btoo many requests\b/i',
        '/\berror:\s*55\b/i',
        '/\bport\s*43\s*(?:queries?|access)\s*(?:are )?(?:not supported|not allowed|disabled)\b/i',
        '/\bplease use (?:the )?web whois\b/i',
        '/\bwhois service unavailable\b/i',
        // Chinese denial patterns
        '/\b查询过于频繁\b/',
        '/\b访问被拒绝\b/',
        '/\b请求被拒绝\b/',
        '/\b连接被拒绝\b/',
        '/\b您的IP.*(?:已被|被)\s*(?:限制|禁止|封锁)/',
        '/\b该IP.*(?:已被|被)\s*(?:限制|禁止|封锁)/',
        '/\b超出查询.*限制\b/',
        '/\b已被禁止查询\b/',
        '/\b请稍后再试\b/',
        '/\b服务不可用\b/',
        // Additional English patterns
        '/\bquery refused\b/i',
        '/\bconnection has been rejected\b/i',
        '/\btemporarily blocked\b/i',
        '/\byour ip has been (?:temporarily )?(?:blocked|blacklisted)\b/i',
    ];
    foreach ($patterns as $p) {
        if (preg_match($p, $raw) === 1) return true;
    }
    if (preg_match('/\bno whois server\b/i', $raw) === 1 && preg_match('/\bdomain name:\b/i', $raw) !== 1) {
        return true;
    }

    // Detect disclaimer-only responses: legal text with no parseable WHOIS fields
    if (whoisIsDisclaimerOnly($lines)) {
        return true;
    }

    return false;
}

function whoisIndicatesDomainAvailable(array $lines): bool {
    $rawStr = strtolower(implode("\n", $lines));
    $freeKws = [
        'not found','no match','no data found','no entries found',
        'domain not found','is not registered','not exist',
        'object does not exist','no object found','status: free',
        'available for registration','this domain is not registered',
        'no information available',
        // Chinese / CNNIC responses
        'no matching record','no entries found in database',
        '没有匹配的记录','域名不存在','该域名尚未注册',
        '你要查询的域名不存在','该域名没有注册记录',
        '没有找到相关信息','查詢的域名不存在',
        '查询的域名不存在',
    ];
    foreach ($freeKws as $kw) {
        if (str_contains($rawStr, $kw)) return true;
    }
    return false;
}

function buildWhoisDomainQueryByTld(string $domainAscii, string $tld): string {
    if ($tld === 'de') return '-T dn,ace ' . $domainAscii;
    if ($tld === 'jp') return $domainAscii . '/e';
    return $domainAscii;
}

function lookupDomainOtherMethods(string $domainAscii): ?array {
    $labels = explode('.', $domainAscii);
    $tld = strtolower((string)end($labels));

    // SWITCH Domain Check for .ch/.li
    if (in_array($tld, ['ch', 'li'], true)) {
        $dcLines = queryTextServer('whois.nic.ch', 4343, $domainAscii, 7);
        if (!empty($dcLines)) {
            $joined = trim(implode("\n", $dcLines));
            if (preg_match('/^\s*1\s*:/m', $joined) === 1) {
                return [
                    'status' => 'available',
                    'method' => 'special',
                    'server' => 'whois.nic.ch:4343',
                    'parsed' => [],
                    'raw'    => array_merge(['Domain Check response (SWITCH)'], $dcLines),
                ];
            }
            if (preg_match('/^\s*0\s*:/m', $joined) === 1) {
                return [
                    'status' => 'registered',
                    'method' => 'special',
                    'server' => 'whois.nic.ch:4343',
                    'parsed' => [],
                    'raw'    => array_merge(['Domain Check response (SWITCH)'], $dcLines),
                ];
            }
        }
    }

    // IANA WHOIS discovery as final protocol-level fallback.
    $ianaServer = getIANAWhoisServer($tld);
    if ($ianaServer === null) return null;
    $query = buildWhoisDomainQueryByTld($domainAscii, $tld);
    [$rawLines, $usedServer] = resolveFullWhois($ianaServer, $query);
    if (empty($rawLines) || whoisLooksLikeDenied($rawLines)) return null;

    if (whoisIndicatesDomainAvailable($rawLines)) {
        return [
            'status' => 'available',
            'method' => 'whois-iana',
            'server' => $usedServer,
            'parsed' => [],
            'raw'    => $rawLines,
        ];
    }

    $censored = censorIPs($rawLines);
    return [
        'status' => 'registered',
        'method' => 'whois-iana',
        'server' => $usedServer,
        'parsed' => parseWhoisData($censored),
        'raw'    => $rawLines,
    ];
}

/**
 * Domain fallback chain:
 * whois_servers -> RDAP -> other methods -> error.
 * This function handles the last two stages (RDAP, other methods).
 */
function lookupRestrictedDomainFallback(string $domainAscii): ?array {
    $labels = explode('.', $domainAscii);
    $tld = strtolower((string)end($labels));

    // Stage 2: RDAP (with preferred bases for known registries)
    if (in_array($tld, ['ch', 'li'], true)) {
        $rdap = lookupDomainViaRdap($domainAscii, ['https://rdap.nic.li/']);
    } elseif ($tld === 'hk') {
        $rdap = lookupDomainViaRdap($domainAscii, ['https://rdap.hkirc.hk/']);
    } elseif ($tld === 'tw') {
        $rdap = lookupDomainViaRdap($domainAscii, ['https://rdap.twnic.tw/']);
    } elseif ($tld === 'kr') {
        $rdap = lookupDomainViaRdap($domainAscii, ['https://rdap.kr/']);
    } elseif ($tld === 'cn') {
        $rdap = lookupDomainViaRdap($domainAscii, ['https://rdap.cnnic.cn/']);
    } elseif ($tld === 'jp') {
        $rdap = lookupDomainViaRdap($domainAscii, ['https://rdap.jprs.jp/']);
    } else {
        $rdap = lookupDomainViaRdap($domainAscii);
    }
    if ($rdap !== null) return $rdap;

    // Stage 3: other methods
    return lookupDomainOtherMethods($domainAscii);
}

/**
 * Unified domain lookup — RDAP-first, WHOIS fallback.
 */
function lookupDomain(string $domainAscii, array $whoisServers): array {
    $domainAscii = strtolower(trim($domainAscii, '.'));
    $labels = explode('.', $domainAscii);
    $tld = strtolower((string)end($labels));

    // Stage 1: Check routing table for special TLDs
    $route = getRoutedProviderForDomain($domainAscii);
    if ($route !== null) {
        $result = lookupRestrictedDomainFallback($domainAscii);
        if ($result !== null) {
            $result['method'] = $result['method'] ?? ('special:' . $route['provider']);
            return $result;
        }
        // Routing failed — return error
        return [
            'status' => 'restricted',
            'method' => 'special',
            'server' => 'route:' . $route['provider'],
            'parsed' => [],
            'raw'    => ['This suffix requires a special lookup route, but all methods failed.'],
            'route_provider' => $route['provider'],
            'route_suffix'   => $route['suffix'],
        ];
    }

    // Stage 2: RDAP first (for all non-routed domains)
    $rdap = lookupDomainViaRdap($domainAscii);
    if ($rdap !== null) return $rdap;

    // Stage 3: WHOIS (port 43) as fallback
    $server = resolveWhoisServer($domainAscii, $whoisServers);
    if ($server === null) {
        // No WHOIS server known — try IANA discovery
        $other = lookupDomainOtherMethods($domainAscii);
        if ($other !== null) return $other;
        return [
            'status' => 'error',
            'method' => 'none',
            'server' => '',
            'parsed' => [],
            'raw'    => ['No WHOIS server known for this TLD, and RDAP/other fallback methods failed.'],
        ];
    }

    $query = buildWhoisDomainQueryByTld($domainAscii, $tld);
    [$rawLines, $usedServer] = resolveFullWhois($server, $query);

    if (empty($rawLines)) {
        // WHOIS failed — try IANA discovery as last resort
        $other = lookupDomainOtherMethods($domainAscii);
        if ($other !== null) return $other;
        return [
            'status' => 'error',
            'method' => 'whois',
            'server' => $usedServer,
            'parsed' => [],
            'raw'    => ['Could not reach WHOIS server.'],
        ];
    }

    // Check for access denial
    if (whoisLooksLikeDenied($rawLines)) {
        // Try IANA WHOIS discovery
        $other = lookupDomainOtherMethods($domainAscii);
        if ($other !== null) return $other;
        $webUrl = whoisGetWebLookupUrl($tld);
        return [
            'status'     => 'restricted',
            'method'     => 'whois',
            'server'     => $usedServer,
            'parsed'     => [],
            'raw'        => $rawLines,
            'web_url'    => $webUrl,
        ];
    }

    // Check for availability
    if (whoisIndicatesDomainAvailable($rawLines)) {
        return [
            'status' => 'available',
            'method' => 'whois',
            'server' => $usedServer,
            'parsed' => [],
            'raw'    => $rawLines,
        ];
    }

    // Registered — parse WHOIS data
    $censored = censorIPs($rawLines);
    return [
        'status' => 'registered',
        'method' => 'whois',
        'server' => $usedServer,
        'parsed' => parseWhoisData($censored),
        'raw'    => $rawLines,
    ];
}

/**
 * Provider routing table for suffixes requiring dedicated lookup methods.
 */
function getRoutedProviderForDomain(string $domainAscii): ?array {
    $domainAscii = strtolower(trim($domainAscii, '.'));
    if ($domainAscii === '' || !str_contains($domainAscii, '.')) return null;

    static $routes = [
        'nic_ch' => ['ch'],
        'nic_li' => ['li'],
        'ao_session_web' => ['ao'],
        'nic_tt' => ['tt'],
        'nic_uy' => ['uy'],
        'nic_ba' => ['ba'],
        'nic_gr' => ['gr'],
        'nic_hk' => ['hk', 'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk', 'idv.hk', '公司.hk', '個人.hk', '網絡.hk', '組織.hk', '教育.hk', '政府.hk'],
        // .tw WHOIS often blocked — prefer RDAP
        'nic_tw' => ['tw', 'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw', 'idv.tw'],
        // .kr WHOIS restricted
        'nic_kr' => ['kr', 'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr', 're.kr'],
        // .cn WHOIS rate-limited
        'nic_cn' => ['cn', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn'],
        // .jp WHOIS requires special query format
        'nic_jp' => ['jp', 'co.jp', 'ne.jp', 'ac.jp', 'go.jp', 'or.jp', 'gr.jp'],
        // Legacy web provider suffixes
        'legacy_web' => [
            'bo','bn','com.bn','org.bn','net.bn','edu.bn','gov.bn',
            'bt',
            'cu','com.cu','edu.cu','gob.cu','inf.cu','nat.cu','net.cu','org.cu',
            'dz','gf','ge','gq',
            'gt','com.gt','edu.gt','org.gt','gob.gt','net.gt','ind.gt','mil.gt',
            'gy','hn','hu','jo','lk','mt',
            'np','com.np','edu.np','gov.np','net.np','org.np','mil.np','name.np','coop.np',
            'nf','om','pa','ph','sv','tj',
            've','com.ve','org.ve','info.ve','net.ve','web.ve','co.ve','emprende.ve','la.ve','1.a.ve',
            'mq',
        ],
    ];

    $best = null;
    $bestLen = -1;
    foreach ($routes as $provider => $suffixes) {
        foreach ($suffixes as $suffix) {
            $suffix = strtolower($suffix);
            if ($domainAscii === $suffix || str_ends_with($domainAscii, '.' . $suffix)) {
                $len = strlen($suffix);
                if ($len > $bestLen) {
                    $best = ['provider' => $provider, 'suffix' => $suffix];
                    $bestLen = $len;
                }
            }
        }
    }
    return $best;
}

// ── WHOIS Server Resolution ────────────────────────────────────────────────

/**
 * Find a WHOIS server from the local whois_servers.php list only.
 */
function resolveWhoisServer(string $domainAscii, array $whoisServers): ?string {
    $labels = explode('.', strtolower($domainAscii));
    $n      = count($labels);
    // Try SLD.TLD first (e.g. co.uk)
    if ($n >= 2) {
        $sld = $labels[$n-2] . '.' . $labels[$n-1];
        if (isset($whoisServers[$sld])) return $whoisServers[$sld];
    }
    // Try TLD
    $tld = $labels[$n-1];
    if (isset($whoisServers[$tld])) return $whoisServers[$tld];
    return null;
}

/**
 * Query whois.iana.org to discover WHOIS server for unknown TLDs.
 */
function getIANAWhoisServer(string $tld): ?string {
    static $cache = [];
    $tld = strtolower(trim($tld, '.'));
    if (array_key_exists($tld, $cache)) return $cache[$tld];

    // Load persistent cache
    $persistent = cacheGetOrFetch('iana_whois_servers', CACHE_TTL_IANA, function () { return []; });
    if (is_array($persistent) && array_key_exists($tld, $persistent)) {
        return $cache[$tld] = $persistent[$tld];
    }

    $lines = queryWhoisServer('whois.iana.org', $tld, 5);
    $server = null;
    foreach ($lines as $line) {
        if (preg_match('/^whois:\s*(.+)$/i', trim($line), $m)) {
            $server = strtolower(trim($m[1]));
            if ($server === '') $server = null;
            break;
        }
    }
    // Update persistent cache
    if (is_array($persistent)) {
        $persistent[$tld] = $server;
    } else {
        $persistent = [$tld => $server];
    }
    ensureCacheDir();
    $file = CACHE_DIR . '/iana_whois_servers.json';
    $fp = @fopen($file, 'w');
    if ($fp) {
        flock($fp, LOCK_EX);
        fwrite($fp, json_encode($persistent, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }
    return $cache[$tld] = $server;
}