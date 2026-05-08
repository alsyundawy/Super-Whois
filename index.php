<?php
/**
 * index.php — Super Whois v2.2.0
 */
define('RATE_LIMIT',  30);
define('RATE_WINDOW', 3600);
define('RATE_STORE',  __DIR__ . '/rate_store');
define('TRUST_PROXY', true);
define('LOG_DIR',     __DIR__ . '/logs');
define('LOG_KEEP_DAYS', 30);

ini_set('pcre.backtrack_limit', '100000');

if (!function_exists('idn_to_ascii')) {
    die('<p style="font-family:sans-serif;color:red">Error: PHP <code>intl</code> extension is missing.</p>');
}

require_once __DIR__ . '/whois_core.php';
require_once __DIR__ . '/languages.php';

// ── DNS AJAX endpoint ──────────────────────────────────────────────────
if (isset($_GET['dns'])) {
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Origin: *');
    header('Cache-Control: max-age=300');
    $dnsDomain = sanitizeQuery($_GET['dns']);
    if ($dnsDomain === '' || classifyQuery($dnsDomain) !== 'domain') {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid domain.'], JSON_UNESCAPED_UNICODE);
        exit();
    }
    $dnsResult = lookupDNSRecords($dnsDomain);
    echo json_encode($dnsResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit();
}

// Security headers
foreach ([
    'X-Content-Type-Options: nosniff',
    'X-Frame-Options: SAMEORIGIN',
    'Referrer-Policy: no-referrer-when-downgrade',
    'Permissions-Policy: clipboard-write=(self)',
] as $h) header($h);

// Redirect bare request to lang-qualified URL
if (empty($_SERVER['QUERY_STRING']) && empty($_POST)) {
    $dl = $_COOKIE['lang'] ?? 'en';
    header('Location: index.php?lang=' . $dl);
    exit();
}

// Language
$supported_langs = ['en', 'zh-cn', 'zh-tw'];
$lang = 'en';
if (isset($_GET['lang'])) {
    $gl = strtolower(trim($_GET['lang']));
    // Backward compatibility: 'zh' → 'zh-cn'
    if ($gl === 'zh') $gl = 'zh-cn';
    if (in_array($gl, $supported_langs, true)) {
        $lang = $gl;
        setcookie('lang', $lang, ['expires'=>time()+86400*30,'path'=>'/','httponly'=>true,'samesite'=>'Lax',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off']);
    }
} elseif (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $supported_langs, true)) {
    $lang = $_COOKIE['lang'];
} elseif (isset($_COOKIE['lang']) && $_COOKIE['lang'] === 'zh') {
    $lang = 'zh-cn';
}
$T = get_language_strings($lang);

enforceRateLimit('web');

// Query
$current_query = '';
if (!empty($_POST['query']))    $current_query = sanitizeQuery($_POST['query']);
elseif (!empty($_GET['query'])) $current_query = sanitizeQuery($_GET['query']);

// ── Blocked/Restricted WHOIS detection ───────────────────────────────────

function renderDenialCard(string $domain, string $server, string $msg, ?string $webUrl,
                          array $censored, array $T, string $lang, int $ms, string $method = 'whois'): string {
    $h   = fn($s) => htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
    $parts = explode('.', $domain);
    $tld = strtoupper(end($parts));

    $o  = '<div class="result-card status-restricted">';
    $o .= '<div class="rc-header">';
    $o .= '<div class="rc-domain">' . $h(strtoupper($domain)) . '</div>';
    $o .= '<div class="rc-badges"><span class="badge badge-restricted">'
        . $T['status_restricted'] . '</span></div>';
    $o .= '<div class="rc-meta"><span class="rc-server">' . $h($server) . '</span>';
    $o .= '<span class="rc-time">' . $ms . 'ms · ' . $h($method) . '</span></div>';
    $o .= '</div>'; // rc-header

    $o .= '<div class="denial-body">';
    $icon = '🔒';
    $headline = $T['denial_headline'];
    $sub = $T['denial_sub'];
    $o .= "<div class=\"denial-icon\">$icon</div>";
    $o .= '<div class="denial-headline">' . $h($headline) . '</div>';
    $o .= '<div class="denial-sub">' . $h($sub) . '</div>';
    if ($webUrl) {
        $btnLabel = $T['denial_btn_label'] . ' .' . $tld;
        $o .= '<a href="' . $h($webUrl) . '?q=' . urlencode($domain) . '" target="_blank" rel="noopener" class="denial-btn">'
            . $h($btnLabel) . ' →</a>';
    }
    if ($msg) {
        $o .= '<div class="denial-raw-msg">' . $h($msg) . '</div>';
    }
    $o .= '</div>'; // denial-body
    $o .= buildRawBlock($censored, $T);
    $o .= '</div>';
    return $o;
}

// ── Result Rendering Functions ─────────────────────────────────────────────

function renderDomainResult(string $domain, array $T, string $lang): void {
    require_once __DIR__ . '/whois_servers.php';
    $domainAscii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($domainAscii === false) {
        echo renderErrorCard($T['invalid_query']); return;
    }
    $apexSuggestion = detectApexDomain($domain);

    $t0     = microtime(true);
    $result = lookupDomain($domainAscii, $whoisServers);
    $elapsed = round((microtime(true) - $t0) * 1000);

    appendLog('domain_lookup', [
        'query'  => $domain,
        'server' => $result['server'] ?? '',
        'method' => $result['method'] ?? '',
        'status' => $result['status'] ?? '',
        'ms'     => $elapsed,
    ]);

    if ($apexSuggestion) echo renderApexHint($apexSuggestion, $lang, $T);

    switch ($result['status'] ?? 'error') {
        case 'available':
            $raw = censorIPs($result['raw'] ?? []);
            echo renderAvailableCard($domain, $result['server'], $raw, $T, $lang, $elapsed, $result['method'] ?? 'rdap');
            return;

        case 'registered':
            $raw = censorIPs($result['raw'] ?? []);
            // Detect held status
            $held = false;
            foreach (($result['raw'] ?? []) as $line) {
                $t = strtolower(trim($line));
                if (preg_match('/^(?:domain\s+)?status\s*:/i', $t) &&
                    (str_contains($t,'serverhold')||str_contains($t,'clienthold')||
                     str_contains($t,'registry lock')||str_contains($t,'pendingdelete'))) {
                    $held = true; break;
                }
            }
            echo renderRegisteredCard($domain, $result['server'], $result['parsed'], $raw, $T, $lang, $elapsed, $held, $result['method'] ?? 'rdap');
            return;

        case 'restricted':
            $raw = censorIPs($result['raw'] ?? []);
            $webUrl = $result['web_url'] ?? whoisGetWebLookupUrl(explode('.', $domainAscii)[count(explode('.', $domainAscii))-1] ?? '');
            $routeSuffix = $result['route_suffix'] ?? null;
            if ($webUrl === null && $routeSuffix !== null) {
                $webUrl = whoisGetWebLookupUrl($routeSuffix);
            }
            $msg = $T['special_route_msg'];
            echo renderDenialCard($domain, $result['server'], $msg, $webUrl, $raw, $T, $lang, $elapsed, $result['method'] ?? 'special');
            return;

        default: // error
            echo renderErrorCard($T['no_info_found']);
            return;
    }
}

function renderIPResult(string $ip, array $T, string $lang): void {
    $server = getRIRServer($ip);
    $t0     = microtime(true);
    $raw    = queryWhoisServer($server, $ip);
    $elapsed = round((microtime(true) - $t0) * 1000);
    appendLog('ip_lookup', ['query' => $ip, 'server' => $server, 'ms' => $elapsed]);
    $censored = censorIPs($raw);
    $h = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    echo '<div class="result-card">';
    if (count($censored) > 3) {
        echo '<div class="rc-header">';
        echo '<div class="rc-domain">' . $h($ip) . '</div>';
        echo '<div class="rc-meta"><span class="rc-server">' . $T['searched_from'] . ': ' . $h($server) . '</span>';
        echo '<span class="rc-time">' . $elapsed . 'ms · whois</span></div></div>';
        echo '<div class="raw-data-wrapper"><pre>' . $h(implode("\n", $censored)) . '</pre></div>';
    } else {
        echo '<p class="error-msg">' . $T['no_info_found'] . '</p>';
    }
    echo '</div>';
}

function renderASNResult(string $asn, array $T, string $lang): void {
    $server  = 'whois.arin.net';
    $t0      = microtime(true);
    $raw     = queryWhoisServer($server, strtoupper($asn));
    $elapsed = round((microtime(true) - $t0) * 1000);
    appendLog('asn_lookup', ['query' => $asn, 'server' => $server, 'ms' => $elapsed]);
    $censored = censorIPs($raw);
    $h = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    echo '<div class="result-card">';
    if (count($censored) > 3) {
        echo '<div class="rc-header">';
        echo '<div class="rc-domain">' . $h(strtoupper($asn)) . '</div>';
        echo '<div class="rc-meta"><span class="rc-server">' . $T['searched_from'] . ': ' . $h($server) . '</span>';
        echo '<span class="rc-time">' . $elapsed . 'ms · whois</span></div></div>';
        echo '<div class="raw-data-wrapper"><pre>' . $h(implode("\n", $censored)) . '</pre></div>';
    } else {
        echo '<p class="error-msg">' . $T['no_info_found'] . '</p>';
    }
    echo '</div>';
}

function renderErrorCard(string $msg): string {
    return '<div class="result-card"><p class="error-msg">' . htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') . '</p></div>';
}

function renderApexHint(string $apex, string $lang, array $T): string {
    $url = htmlspecialchars('?lang=' . $lang . '&query=' . urlencode($apex), ENT_QUOTES, 'UTF-8');
    $h   = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    return '<div class="subdomain-hint">'
        . '<span class="sh-icon">💡</span>'
        . '<span>' . $h($T['subdomain_hint']) . ' <a href="' . $url . '" class="sh-link">' . $h($apex) . '</a>' . $h($T['subdomain_hint_suffix']) . '</span>'
        . '<a href="' . $url . '" class="sh-btn">' . $h($T['subdomain_search_btn']) . '</a>'
        . '</div>';
}

function renderAvailableCard(string $domain, string $server, array $censored, array $T, string $lang, int $ms, string $method = 'whois'): string {
    $h   = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    $url = '?lang=' . $lang . '&query=' . urlencode($domain);
    $o   = '<div class="result-card status-available">';
    $o  .= '<div class="rc-header">';
    $o  .= '<div class="rc-domain">' . $h(strtoupper($domain)) . '</div>';
    $o  .= '<div class="rc-badges"><span class="badge badge-avail">' . $T['domain_available_badge'] . '</span></div>';
    $o  .= '<div class="rc-meta"><span class="rc-server">' . $T['searched_from'] . ': ' . $h($server) . '</span>';
    $o  .= '<span class="rc-time">' . $ms . 'ms · ' . $h($method) . '</span></div></div>';
    $o  .= '<p class="status-text-avail">✓ ' . $T['domain_available'] . '</p>';
    $o  .= buildCopyBtn($url, $T);
    // DNS Records button (even for available domains, shows if DNS exists)
    $o .= '<div class="dns-section">';
    $o .= '<button class="dns-btn" onclick="loadDNS(\'' . $h($domain) . '\', this)">';
    $o .= '<i class="fa-solid fa-server"></i> ';
    $o .= $T['dns_records'];
    $o .= '</button>';
    $o .= '<div class="dns-results" id="dns-results-' . $h($domain) . '"></div>';
    $o .= '</div>';
    $o  .= buildRawBlock($censored, $T);
    $o  .= '</div>';
    return $o;
}

function renderRegisteredCard(string $domain, string $server, array $p, array $censored, array $T, string $lang, int $ms, bool $held, string $method = 'whois'): string {
    $h   = fn($s) => htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
    $url = '?lang=' . $lang . '&query=' . urlencode($domain);

    // Expiry badge
    $expiryBadge = '';
    if (!empty($p['expiration_date'])) {
        $ts = strtotime($p['expiration_date']);
        if ($ts !== false && $ts > 0) {
            $diff = $ts - time();
            if ($diff < 0) {
                $expiryBadge = '<span class="badge badge-expired">' . $T['expired_badge'] . '</span>';
            } elseif ($diff < 60 * 86400) {
                $expiryBadge = '<span class="badge badge-expiring">' . $T['expiring_badge'] . '</span>';
            }
        }
    }

    $o = '<div class="result-card' . ($held ? ' status-held' : '') . '">';

    // ── Header ──
    $o .= '<div class="rc-header">';
    $o .= '<div class="rc-domain">' . $h(strtoupper($domain)) . '</div>';
    $o .= '<div class="rc-badges">';
    if ($expiryBadge) $o .= $expiryBadge;
    if ($held)        $o .= '<span class="badge badge-held">' . $T['held_badge'] . '</span>';
    $o .= '</div>';
    $o .= '<div class="rc-meta">';
    if (!empty($p['registrar_iana_id'])) $o .= '<span class="badge-iana">IANA: ' . $h($p['registrar_iana_id']) . '</span>';
    $o .= '<span class="rc-server">' . $h($server) . '</span>';
    $o .= '<span class="rc-time">' . $ms . 'ms · ' . $h($method) . '</span>';
    $o .= '</div>';
    $o .= '</div>'; // rc-header

    // ── Copy link ──
    $o .= buildCopyBtn($url, $T);

    // ── If $p is empty, show a notice and skip the structured columns ──
    if (empty($p)) {
        $notice = '⚠️ ' . $T['parse_failed_notice'];
        $o .= '<p style="text-align:center;color:var(--clr-warning);font-size:14px;padding:18px 24px;">' . $h($notice) . '</p>';
        $o .= buildRawBlock($censored, $T);
        $o .= '</div>';
        return $o;
    }

    // ── Two-column body ──
    $o .= '<div class="rc-body">';

    // Left column
    $o .= '<div class="rc-left">';

    // Dates
    $dateFields = [
        'creation_date'   => $T['date_created'],
        'expiration_date' => $T['date_expires'],
        'updated_date'    => $T['date_updated'],
    ];
    $hasDate = array_intersect_key($p, $dateFields);
    if (!empty($hasDate)) {
        $o .= '<div class="rc-dates-row">';
        foreach ($dateFields as $key => $label) {
            if (!isset($p[$key])) continue;
            $rel = relativeTime($p[$key], $lang);
            $o .= '<div class="rc-date-cell">';
            $o .= '<div class="rc-date-label">' . $h($label) . '</div>';
            $o .= '<div class="rc-date-value">' . $h(substr($p[$key], 0, 10)) . '</div>';
            if ($rel) $o .= '<div class="rc-date-rel">' . $h($rel) . '</div>';
            $o .= '</div>';
        }
        $o .= '</div>';
    }

    // Contact row (phone + email)
    $showContact = !empty($p['registrant_phone']) || !empty($p['abuse_email']);
    if ($showContact) {
        $o .= '<div class="rc-contact-row">';
        if (!empty($p['registrant_phone'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_phone'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['registrant_phone']) . '</div>';
            $o .= '</div>';
        }
        if (!empty($p['abuse_email'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_abuse_email'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['abuse_email']) . '</div>';
            $o .= '</div>';
        }
        $o .= '</div>';
    }

    // Registrant info row (name, org, email)
    $showRegistrant = !empty($p['registrant_name']) || !empty($p['registrant_org'])
                   || !empty($p['registrant_email']) || !empty($p['admin_email'])
                   || !empty($p['tech_email']);
    if ($showRegistrant) {
        $o .= '<div class="rc-contact-row">';
        if (!empty($p['registrant_name'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_registrant'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['registrant_name']) . '</div>';
            $o .= '</div>';
        }
        if (!empty($p['registrant_org'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_organization'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['registrant_org']) . '</div>';
            $o .= '</div>';
        }
        $o .= '</div>';
        // Email row
        $emails = [];
        if (!empty($p['registrant_email'])) $emails[] = $p['registrant_email'];
        if (!empty($p['admin_email'])) $emails[] = $p['admin_email'];
        if (!empty($p['tech_email'])) $emails[] = $p['tech_email'];
        if (!empty($emails)) {
            $o .= '<div class="rc-contact-row">';
            $o .= '<div class="rc-contact-cell" style="flex:2">';
            $o .= '<div class="rc-contact-label">' . $T['contact_emails'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h(implode(' · ', array_unique($emails))) . '</div>';
            $o .= '</div>';
            $o .= '</div>';
        }
    }

    $o .= '</div>'; // rc-left

    // Right column — Registrar panel
    $hasReg = !empty($p['registrar']) || !empty($p['registrar_iana_id']) || !empty($p['registrant_country'])
           || !empty($p['registrar_whois']) || !empty($p['abuse_phone']) || !empty($p['abuse_email']);
    $o .= '<div class="rc-right">';
    $o .= '<div class="registrar-panel">';
    $o .= '<div class="rp-heading">🏦 ' . $T['registrar_heading'] . '</div>';
    if ($hasReg) {
        if (!empty($p['registrar_iana_id'])) {
            $o .= '<div class="rp-iana"><span class="badge-iana">IANA: ' . $h($p['registrar_iana_id']) . '</span></div>';
        }
        if (!empty($p['registrar'])) {
            $o .= '<div class="rp-name">🔺 ' . $h($p['registrar']) . '</div>';
        }
        if (!empty($p['registrant_country'])) {
            $flag = countryFlag($p['registrant_country']);
            $o .= '<div class="rp-row">' . $flag . ' ' . $h($p['registrant_country']) . '</div>';
        }
        if (!empty($p['registrar_whois'])) {
            $o .= '<div class="rp-row">🌐 ' . $h($p['registrar_whois']) . '</div>';
        }
        if (!empty($p['abuse_phone'])) {
            $o .= '<div class="rp-row">📞 ' . $h($p['abuse_phone']) . '</div>';
        }
        if (!empty($p['abuse_email'])) {
            $o .= '<div class="rp-row">✉️ ' . $h($p['abuse_email']) . '</div>';
        }
    } else {
        $o .= '<div class="rp-row" style="color:var(--clr-text-muted);font-size:13px;">'
            . $T['privacy_protected'] . '</div>';
    }
    $o .= '</div>'; // registrar-panel
    $o .= '</div>'; // rc-right

    $o .= '</div>'; // rc-body

    // ── Status + Nameservers row ──
    $hasStatus = !empty($p['status']);
    $hasNS     = !empty($p['nameservers']);
    $dnssecVal = $p['dnssec'] ?? null;
    if ($hasStatus || $hasNS || $dnssecVal !== null) {
        $o .= '<div class="rc-bottom">';

        if ($hasStatus) {
            $o .= '<div class="rc-section">';
            $o .= '<div class="rc-section-title">⚡ ' . $T['group_status'] . '</div>';
            foreach ($p['status'] as $s) {
                // Extract just the status code (before the URL)
                $code = trim(explode(' ', trim($s))[0]);
                $url2 = (str_contains($s, 'http')) ? trim(substr($s, strpos($s, 'http'))) : null;
                $o .= '<div class="rc-status-item">';
                $o .= '<span class="status-dot"></span>';
                if ($url2) {
                    $o .= '<a href="' . $h($url2) . '" target="_blank" rel="noopener" class="status-link">' . $h($code) . '</a>';
                } else {
                    $o .= $h($code);
                }
                // Status description
                $desc = getStatusDescription($code, $lang);
                if ($desc) $o .= '<span class="status-desc"> — ' . $h($desc) . '</span>';
                $o .= '</div>';
            }
            $o .= '</div>';
        }

        if ($hasNS || $dnssecVal !== null) {
            $o .= '<div class="rc-section">';
            $o .= '<div class="rc-section-title">📡 ' . $T['group_nameservers'] . '</div>';
            if ($hasNS) {
                foreach ($p['nameservers'] as $ns) {
                    $provider = detectNSProvider($ns);
                    $o .= '<div class="rc-ns-item">';
                    $o .= '<span class="ns-dot">●</span> ' . $h($ns);
                    if ($provider) $o .= ' <span class="ns-badge">' . $h($provider) . '</span>';
                    $o .= '</div>';
                }
            }
            // DNSSEC merged into nameserver section
            if ($dnssecVal !== null) {
                $isSigned = strtolower($dnssecVal) === 'signed';
                $dnssecLabel = $isSigned
                    ? ($lang === 'zh-cn' ? '已签名' : ($lang === 'zh-tw' ? '已簽署' : 'Signed'))
                    : ($lang === 'zh-cn' ? '未签名' : ($lang === 'zh-tw' ? '未簽署' : 'Unsigned'));
                $badgeClass = $isSigned ? 'dnssec-badge dnssec-signed' : 'dnssec-badge dnssec-unsigned';
                $o .= '<div class="rc-ns-item" style="margin-top:8px;padding-top:8px;border-top:1px solid var(--clr-border-light);">';
                $o .= '<span class="' . $badgeClass . '">🔒 DNSSEC: ' . $h($dnssecLabel) . '</span>';
                $o .= '</div>';
            }
            $o .= '</div>';
        }

        $o .= '</div>'; // rc-bottom
    }

    // ── DNS Records button ──
    $o .= '<div class="dns-section">';
    $o .= '<button class="dns-btn" onclick="loadDNS(\'' . $h($domain) . '\', this)">';
    $o .= '<i class="fa-solid fa-server"></i> ';
    $o .= $T['dns_records'];
    $o .= '</button>';
    $o .= '<div class="dns-results" id="dns-results-' . $h($domain) . '"></div>';
    $o .= '</div>';

    $o .= buildRawBlock($censored, $T);
    $o .= '</div>'; // result-card
    return $o;
}

function getStatusDescription(string $code, string $lang): string {
    $map = [
        'clientTransferProhibited' => ['en' => 'Registrar has locked the domain to prevent transfer to another registrar.', 'zh' => '注册商已锁定域名以防止转移至其他注册商。'],
        'clientDeleteProhibited'   => ['en' => 'Registrar has locked to prevent deletion.', 'zh' => '注册商已锁定以防止删除。'],
        'clientUpdateProhibited'   => ['en' => 'Registrar has locked to prevent updates.', 'zh' => '注册商已锁定以防止更新。'],
        'serverTransferProhibited' => ['en' => 'Registry locked — transfer prohibited.', 'zh' => '注册局锁定 — 禁止转移。'],
        'serverDeleteProhibited'   => ['en' => 'Registry locked — deletion prohibited.', 'zh' => '注册局锁定 — 禁止删除。'],
        'serverUpdateProhibited'   => ['en' => 'Registry locked — updates prohibited.', 'zh' => '注册局锁定 — 禁止更新。'],
        'pendingDelete'            => ['en' => 'Domain is pending deletion.', 'zh' => '域名待删除中。'],
        'pendingTransfer'          => ['en' => 'Domain is pending transfer.', 'zh' => '域名待转移中。'],
        'active'                   => ['en' => 'Domain is active.', 'zh' => '域名处于活跃状态。'],
        'ok'                       => ['en' => 'Domain is in normal status.', 'zh' => '域名状态正常。'],
    ];
    $code = strtolower($code);
    foreach ($map as $k => $v) {
        if (strtolower($k) === $code) return $v[$lang] ?? $v['en'];
    }
    return '';
}

function buildCopyBtn(string $url, array $T): string {
    $esc = htmlspecialchars(json_encode($url), ENT_QUOTES, 'UTF-8');
    return '<div class="copy-row">'
        . '<button class="copy-link-btn" onclick="copyToClipboard(' . $esc . ', this)">'
        . '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>'
        . ' ' . htmlspecialchars($T['copy_link_button'], ENT_QUOTES, 'UTF-8')
        . '</button></div>';
}

function buildRawBlock(array $lines, array $T): string {
    return '<div class="raw-data-container">'
        . '<button class="details-toggle" onclick="toggleDetails(this)">'
        . htmlspecialchars($T['show_raw_data'], ENT_QUOTES, 'UTF-8')
        . '</button>'
        . '<div class="details-content"><pre>'
        . htmlspecialchars(implode("\n", $lines), ENT_QUOTES, 'UTF-8')
        . '</pre></div></div>';
}

?><!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
<meta charset="UTF-8">
<title><?php echo htmlspecialchars($T['page_title'], ENT_QUOTES, 'UTF-8'); ?></title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="<?php echo htmlspecialchars($T['meta_description'], ENT_QUOTES, 'UTF-8'); ?>">
<link rel="stylesheet" href="./style.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>
<body>

<header>
  <div class="header-content">
    <h2><i class="fa-solid fa-globe"></i> <?php echo htmlspecialchars($T['header_title'], ENT_QUOTES, 'UTF-8'); ?></h2>
    <div class="header-actions">
      <button id="theme-toggle" class="icon-btn" aria-label="Toggle dark mode">
        <i class="fa-solid fa-moon" id="theme-icon"></i>
      </button>
      <div class="language-switcher">
        <?php $qs = !empty($current_query) ? '&query=' . urlencode($current_query) : ''; ?>
        <a href="<?php echo htmlspecialchars('?lang=en' . $qs); ?>" <?php if ($lang==='en') echo 'class="active"'; ?>>EN</a>
        <a href="<?php echo htmlspecialchars('?lang=zh-cn' . $qs); ?>" <?php if ($lang==='zh-cn') echo 'class="active"'; ?>>简体</a>
        <a href="<?php echo htmlspecialchars('?lang=zh-tw' . $qs); ?>" <?php if ($lang==='zh-tw') echo 'class="active"'; ?>>繁體</a>
      </div>
      <a href="api.php?lang=<?php echo $lang; ?>" class="api-badge" target="_blank" rel="noopener">
        <i class="fa-solid fa-code"></i> API
      </a>
    </div>
  </div>
</header>

<main>
  <div class="search-card">
    <form method="post" action="?lang=<?php echo $lang; ?>" autocomplete="off" id="search-form">
      <div class="input-wrapper">
        <i class="fa-regular fa-clock input-icon-left"></i>
        <input type="text" name="query" id="query-input"
               placeholder="<?php echo htmlspecialchars($T['placeholder'], ENT_QUOTES, 'UTF-8'); ?>"
               required spellcheck="false" maxlength="253"
               value="<?php echo htmlspecialchars($current_query, ENT_QUOTES, 'UTF-8'); ?>"
               autocomplete="off">
        <div id="autocomplete-dropdown" class="ac-dropdown" role="listbox"></div>
      </div>
      <button type="submit" class="submit-button" id="submit-btn">
        <i class="fa-solid fa-location-arrow" id="submit-icon"></i>
      </button>
    </form>
  </div>

  <?php
  if ($current_query !== '') {
    $qtype = classifyQuery($current_query);
    switch ($qtype) {
      case 'ipv4': case 'ipv6': renderIPResult($current_query, $T, $lang); break;
      case 'asn':  renderASNResult($current_query, $T, $lang); break;
      case 'domain': renderDomainResult($current_query, $T, $lang); break;
      default: echo renderErrorCard($T['invalid_query']);
    }
  }
  ?>

  <div id="guides-container" class="illustrate-card">
    <div class="card-header">
      <h3><?php echo htmlspecialchars($T['guide_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
      <button id="toggle-guides-btn" class="btn-ghost btn-sm"></button>
    </div>
    <div id="guides-body">
      <ol>
        <li><?php echo $T['guide_step1']; ?></li>
        <li><?php echo $T['guide_step2']; ?></li>
        <li><?php echo $T['guide_step3']; ?></li>
        <li><?php echo $T['guide_step4']; ?></li>
        <li><?php echo $T['guide_step5']; ?></li>
        <li><?php echo $T['guide_step6']; ?></li>
      </ol>
    </div>
  </div>

  <div class="history-card">
    <div class="history-header">
      <h3><?php echo htmlspecialchars($T['history_records_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
      <button class="clear-button" onclick="clearHistory()">
        <?php echo htmlspecialchars($T['clear_history_button'], ENT_QUOTES, 'UTF-8'); ?>
      </button>
    </div>
    <p class="history-info"><?php echo htmlspecialchars($T['history_info'], ENT_QUOTES, 'UTF-8'); ?></p>
    <ul id="history-list"></ul>
  </div>
</main>

<footer>
  <p><?php echo $T['footer_text']; ?>
    | <a href="api.php?lang=<?php echo $lang; ?>"><?php echo $T['footer_api_link']; ?></a>
    | <a href="https://github.com/iezx/Super-Whois" target="_blank" rel="noopener noreferrer"><?php echo $T['footer_github']; ?></a>
  </p>
</footer>

<script>
(function(){
  // ── Theme ──────────────────────────────────────────────────────────────
  const TK = 'swTheme';
  const btn = document.getElementById('theme-toggle');
  const ico = document.getElementById('theme-icon');
  function applyTheme(dark) {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    ico.className = dark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    try { localStorage.setItem(TK, dark ? 'dark' : 'light'); } catch(e){}
  }
  (() => {
    let s; try { s = localStorage.getItem(TK); } catch(e){}
    applyTheme(s ? s==='dark' : window.matchMedia('(prefers-color-scheme: dark)').matches);
  })();
  btn.addEventListener('click', () =>
    applyTheme(document.documentElement.getAttribute('data-theme') !== 'dark'));

  // ── Autocomplete TLD Suggestions ──────────────────────────────────────
  // Ordered by popularity — first 8 shown; rest available when user types a dot
  const ALL_TLDS   = ['com','net','org','io','co','app','dev','ai','me','info','biz','xyz','online','shop','tech','cloud','store'];
  const TOP_TLDS   = ALL_TLDS.slice(0, 8);
  const input      = document.getElementById('query-input');
  const dropdown   = document.getElementById('autocomplete-dropdown');
  let acActive = -1, acItems = [];

  // Dim overlay so dropdown visually separates from page content
  const overlay = document.createElement('div');
  overlay.id = 'ac-overlay';
  overlay.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,.15);z-index:49;';
  document.body.appendChild(overlay);
  overlay.addEventListener('mousedown', e => { e.preventDefault(); hideAC(); });

  /**
   * Extract the registrable base name:
   *   "example"       → "example"
   *   "example.com"   → "example"
   *   "sub.example.com" → "example"  (skip sub-labels)
   */
  function getBaseName(val) {
    val = val.trim().replace(/^https?:\/\//i, '').split('/')[0];
    const parts = val.split('.').filter(Boolean);
    if (parts.length === 0) return '';
    if (parts.length === 1) return parts[0];              // no dot
    // Take the second-to-last label as the registrable base
    return parts[parts.length - 2];
  }

  function showAC(val) {
    val = val.trim();
    if (!val || val.includes(' ')) { hideAC(); return; }
    const base = getBaseName(val);
    if (!base || base.length < 2) { hideAC(); return; }

    // If the user typed a dot, show ALL TLDs; otherwise show TOP 8
    const pool = val.includes('.') ? ALL_TLDS : TOP_TLDS;
    // Current TLD the user has typed (if any), to mark it active
    const typedTLD = val.includes('.') ? val.split('.').slice(1).join('.').toLowerCase() : null;

    acItems = pool.map(tld => base + '.' + tld);
    // If the typed TLD isn't in pool, prepend the literal typed value
    if (typedTLD && !pool.includes(typedTLD)) {
      acItems.unshift(val.toLowerCase());
    }

    dropdown.innerHTML = '';
    acActive = -1;
    acItems.forEach((item) => {
      const li = document.createElement('div');
      const isCurrent = (item === val.toLowerCase());
      li.className = 'ac-item' + (isCurrent ? ' ac-current' : '');
      li.setAttribute('role', 'option');
      li.innerHTML = '<span class="ac-icon">🌐</span>'
        + '<span class="ac-text">' + escHtml(item) + '</span>'
        + '<span class="ac-badge">DOMAIN</span>';
      li.addEventListener('mousedown', e => {
        e.preventDefault();
        input.value = item;
        hideAC();
        document.getElementById('search-form').submit();
      });
      dropdown.appendChild(li);
    });
    dropdown.style.display = 'block';
    overlay.style.display  = 'block';
  }

  function hideAC() {
    dropdown.style.display = 'none';
    overlay.style.display  = 'none';
    acActive = -1;
  }

  function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  input.addEventListener('input', () => showAC(input.value));
  input.addEventListener('focus', () => { if (input.value) showAC(input.value); });
  document.addEventListener('click', e => { if (!e.target.closest('.input-wrapper')) hideAC(); });

  input.addEventListener('keydown', e => {
    const items = dropdown.querySelectorAll('.ac-item');
    if (!items.length || dropdown.style.display === 'none') return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      acActive = Math.min(acActive + 1, items.length - 1);
      items.forEach((el,i) => el.classList.toggle('ac-hover', i===acActive));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      acActive = Math.max(acActive - 1, -1);
      items.forEach((el,i) => el.classList.toggle('ac-hover', i===acActive));
    } else if (e.key === 'Enter' && acActive >= 0) {
      e.preventDefault();
      input.value = acItems[acActive];
      hideAC();
      document.getElementById('search-form').submit();
    } else if (e.key === 'Escape') {
      hideAC();
    }
  });

  // ── Guides toggle ─────────────────────────────────────────────────────
  const guideContainer = document.getElementById('guides-container');
  const toggleBtn      = document.getElementById('toggle-guides-btn');
  const guideBody      = document.getElementById('guides-body');
  const showTxt = <?php echo json_encode($T['toggle_guides_button']); ?>;
  const hideTxt = <?php echo json_encode($T['hide_guides_button']); ?>;
  let guideOpen = false;
  guideBody.style.display = 'none';
  toggleBtn.textContent = showTxt;
  toggleBtn.addEventListener('click', () => {
    guideOpen = !guideOpen;
    guideBody.style.display = guideOpen ? 'block' : 'none';
    toggleBtn.textContent = guideOpen ? hideTxt : showTxt;
  });

  // ── History ───────────────────────────────────────────────────────────
  const HK = 'swHistory_v3';
  const noHistTxt = <?php echo json_encode($T['no_history']); ?>;
  const clickHint = <?php echo json_encode($T['history_click_hint']); ?>;
  const histList  = document.getElementById('history-list');
  const form      = document.getElementById('search-form');

  function loadHistory() {
    let h = []; try { h = JSON.parse(localStorage.getItem(HK)||'[]'); } catch(e){}
    if (!Array.isArray(h)) h = [];
    histList.innerHTML = '';
    if (!h.length) { histList.innerHTML = '<li class="no-history">' + noHistTxt + '</li>'; return; }
    h.slice(-10).reverse().forEach(item => {
      const li = document.createElement('li');
      li.className = 'history-item';
      li.textContent = item;
      li.title = clickHint;
      li.onclick = () => { input.value = item; saveHistory(item); form.submit(); };
      histList.appendChild(li);
    });
  }

  function saveHistory(q) {
    q = q.trim().toLowerCase();
    if (!q) return;
    let h = []; try { h = JSON.parse(localStorage.getItem(HK)||'[]'); } catch(e){}
    if (!Array.isArray(h)) h = [];
    h = h.filter(i => i !== q); h.push(q);
    if (h.length > 20) h.splice(0, h.length - 20);
    try { localStorage.setItem(HK, JSON.stringify(h)); } catch(e){}
  }

  form.addEventListener('submit', () => {
    const q = input.value.trim();
    if (q) saveHistory(q);
    // Loading spinner
    const btn = document.getElementById('submit-btn');
    const ico = document.getElementById('submit-icon');
    btn.disabled = true;
    ico.className = 'fa-solid fa-spinner fa-spin';
  });

  window.clearHistory = () => {
    try { localStorage.removeItem(HK); } catch(e){}
    loadHistory();
  };

  loadHistory();

  // ── Copy link ─────────────────────────────────────────────────────────
  const copiedTxt = <?php echo json_encode($T['copied_feedback']); ?>;
  const copyFailTxt = <?php echo json_encode($T['copy_failed']); ?>;

  window.copyToClipboard = (path, btn2) => {
    const url = new URL(path, window.location.href).href;
    const orig = btn2.innerHTML;
    const ok = () => {
      btn2.textContent = copiedTxt; btn2.disabled = true;
      setTimeout(() => { btn2.innerHTML = orig; btn2.disabled = false; }, 2000);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(url).then(ok).catch(() => fbCopy(url, ok));
    } else { fbCopy(url, ok); }
  };

  function fbCopy(text, onOk) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { if (document.execCommand('copy')) onOk(); else alert(copyFailTxt+'\n'+text); }
    catch(e) { alert(copyFailTxt+'\n'+text); }
    document.body.removeChild(ta);
  }

  // ── DNS Records ───────────────────────────────────────────────────
  window.loadDNS = (domain, btn) => {
    const container = document.getElementById('dns-results-' + domain);
    if (!container) return;
    // Toggle if already loaded
    if (container.style.display === 'block') {
      container.style.display = 'none';
      btn.classList.remove('dns-btn-active');
      return;
    }
    if (container.dataset.loaded) {
      container.style.display = 'block';
      btn.classList.add('dns-btn-active');
      return;
    }
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Loading…';
    fetch('?dns=' + encodeURIComponent(domain))
      .then(r => r.json())
      .then(data => {
        container.innerHTML = renderDNS(data, domain);
        container.style.display = 'block';
        container.dataset.loaded = '1';
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-server"></i> ' + (data.error ? 'DNS' : 'DNS Records');
        btn.classList.add('dns-btn-active');
      })
      .catch(() => {
        container.innerHTML = '<div class="dns-error">Failed to load DNS records.</div>';
        container.style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-server"></i> DNS';
      });
  };

  function renderDNS(data, domain) {
    if (data.error && !data.records) {
      return '<div class="dns-error">' + escHtml(data.error) + '</div>';
    }
    const recs = data.records || {};
    const types = ['A','AAAA','MX','TXT','NS','CNAME'];
    let html = '<div class="dns-card">';
    html += '<div class="dns-title"><i class="fa-solid fa-server"></i> DNS Records — ' + escHtml(domain.toUpperCase()) + '</div>';
    let hasRecords = false;
    types.forEach(type => {
      if (!recs[type] || recs[type].length === 0) return;
      hasRecords = true;
      html += '<div class="dns-type-block">';
      html += '<div class="dns-type-header"><span class="dns-type-badge">' + type + '</span></div>';
      html += '<div class="dns-records-list">';
      recs[type].forEach(r => {
        html += '<div class="dns-record-row">';
        if (type === 'A') {
          html += '<span class="dns-val">' + escHtml(r.ip) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'AAAA') {
          html += '<span class="dns-val">' + escHtml(r.ipv6) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'MX') {
          html += '<span class="dns-pri">' + r.priority + '</span>';
          html += '<span class="dns-val">' + escHtml(r.host) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'TXT') {
          html += '<span class="dns-val dns-txt">' + escHtml(r.txt) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'NS' || type === 'CNAME') {
          html += '<span class="dns-val">' + escHtml(r.target) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        }
        html += '</div>';
      });
      html += '</div></div>';
    });
    if (!hasRecords) {
      html += '<div class="dns-empty">No DNS records found.</div>';
    }
    html += '</div>';
    return html;
  }

  // ── Raw data toggle ─────────────────────────────────────────────────────
  const showRawTxt = <?php echo json_encode($T['show_raw_data']); ?>;
  const hideRawTxt = <?php echo json_encode($T['hide_raw_data']); ?>;
  window.toggleDetails = btn3 => {
    const c = btn3.nextElementSibling;
    const v = c.style.display === 'block';
    c.style.display = v ? 'none' : 'block';
    btn3.textContent = v ? showRawTxt : hideRawTxt;
  };
})();
</script>
</body>
</html>
