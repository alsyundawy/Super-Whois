<?php
/**
 * api.php — Super Whois v2.2.1
 * Uses whois_core.php for all shared logic.
 */
define('RATE_LIMIT',  60);
define('RATE_WINDOW', 3600);
define('RATE_STORE',  __DIR__ . '/rate_store');
define('TRUST_PROXY', true);
define('LOG_DIR',     __DIR__ . '/logs');
define('LOG_KEEP_DAYS', 30);
define('API_VERSION',               '2.1');
define('API_MAX_QUERY_LENGTH',      253);
define('API_ALLOW_UNAUTHENTICATED', true);
define('API_KEYS_FILE',             __DIR__ . '/api_keys.php');

ini_set('pcre.backtrack_limit', '100000');

if (!function_exists('idn_to_ascii')) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Server error: intl extension missing.', 'code' => 500]);
    exit();
}

require_once __DIR__ . '/whois_core.php';
require_once __DIR__ . '/languages.php';
require_once __DIR__ . '/whois_servers.php';

// ── Language ───────────────────────────────────────────────────────────────
$supported_langs = ['en', 'zh-cn', 'zh-tw'];
$lang = 'en';
if (isset($_GET['lang'])) {
    $gl = strtolower(trim($_GET['lang']));
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

// ── Route: no query → render API docs ────────────────────────────────────
if (!isset($_GET['q']) || trim($_GET['q']) === '') {
    header('Content-Type: text/html; charset=UTF-8');
    renderApiDocs($T, $lang);
    exit();
}

// ── API response mode ─────────────────────────────────────────────────────
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');
header('Cache-Control: no-store');

// ── Auth ──────────────────────────────────────────────────────────────────
$providedKey     = isset($_GET['key']) ? trim($_GET['key']) : '';
$isAuthenticated = false;
if ($providedKey !== '' && file_exists(API_KEYS_FILE)) {
    $apiKeys = [];
    require API_KEYS_FILE;
    if (in_array($providedKey, $apiKeys, true)) $isAuthenticated = true;
}
if (!$isAuthenticated && !API_ALLOW_UNAUTHENTICATED) {
    apiError(401, 'Unauthorized. A valid API key is required.');
}

// ── Rate limit (unauthenticated only) ─────────────────────────────────────
$rlHeaders = [];
if (!$isAuthenticated) {
    $rlHeaders = enforceRateLimit('api');
    foreach ($rlHeaders as $k => $v) header("$k: $v");
}

// ── Query ─────────────────────────────────────────────────────────────────
$rawQ = trim(substr($_GET['q'], 0, 10000));

// Batch mode: split by comma or newline
$queries = preg_split('/[,\n]+/', $rawQ);
$queries = array_filter(array_map('trim', $queries));
$queries = array_values($queries);

if (empty($queries)) apiError(400, 'Invalid or empty query.');

$dnsFlag = !empty($_GET['dns']) && $_GET['dns'] === 'true';

if (count($queries) === 1) {
    // Single query — backward-compatible response (flat JSON)
    $query = sanitizeQuery($queries[0]);
    if ($query === '') apiError(400, 'Invalid or empty query.');

    $result = dispatchApiQuery($query, $whoisServers);

    if ($dnsFlag && $result['query_type'] === 'domain') {
        $dnsQ = sanitizeQuery($result['query']);
        if ($dnsQ !== '' && classifyQuery($dnsQ) === 'domain') {
            $result['dns_records'] = lookupDNSRecords($dnsQ);
        }
    }

    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} else {
    // Batch mode — array response
    $results = [];
    foreach ($queries as $q) {
        $q = sanitizeQuery($q);
        if ($q === '') {
            $results[] = ['query' => $q, 'status' => 'error', 'error' => 'Invalid query.'];
            continue;
        }
        $result = dispatchApiQuery($q, $whoisServers);
        if ($dnsFlag && ($result['query_type'] ?? '') === 'domain') {
            $dnsQ = sanitizeQuery($result['query']);
            if ($dnsQ !== '' && classifyQuery($dnsQ) === 'domain') {
                $result['dns_records'] = lookupDNSRecords($dnsQ);
            }
        }
        $results[] = $result;
    }

    echo json_encode([
        'batch'       => true,
        'count'       => count($results),
        'api_version' => API_VERSION,
        'timestamp'   => gmdate('Y-m-d\TH:i:s\Z'),
        'results'     => $results,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}
exit();

// ── Helpers ───────────────────────────────────────────────────────────────

function apiError(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['error' => $message, 'code' => $code,
        'timestamp' => gmdate('Y-m-d\TH:i:s\Z')], JSON_UNESCAPED_UNICODE);
    exit();
}

function dispatchApiQuery(string $query, array $whoisServers): array {
    $base = [
        'query'        => $query,
        'query_type'   => '',
        'query_method' => '',
        'whois_server' => null,
        'status'       => '',
        'timestamp'    => gmdate('Y-m-d\TH:i:s\Z'),
        'api_version'  => API_VERSION,
    ];
    $type = classifyQuery($query);
    $t0   = microtime(true);

    if ($type === 'ipv4' || $type === 'ipv6') {
        $base['query_type'] = $type;
        $server             = getRIRServer($query);
        $raw                = queryWhoisServer($server, $query);
        $elapsed            = round((microtime(true) - $t0) * 1000);
        appendLog('api_ip_lookup', ['query' => $query, 'server' => $server, 'ms' => $elapsed]);
        if (count($raw) < 3) { $base['status'] = 'error'; $base['error'] = 'No data returned.'; return $base; }
        $base['status']       = 'found';
        $base['query_method'] = 'whois';
        $base['whois_server'] = $server;
        $base['query_ms']     = $elapsed;
        $base['raw']          = implode("\n", censorIPs($raw));
        return $base;

    } elseif ($type === 'asn') {
        $base['query_type'] = 'asn';
        $server             = 'whois.arin.net';
        $raw                = queryWhoisServer($server, strtoupper($query));
        $elapsed            = round((microtime(true) - $t0) * 1000);
        appendLog('api_asn_lookup', ['query' => $query, 'server' => $server, 'ms' => $elapsed]);
        if (count($raw) < 3) { $base['status'] = 'error'; $base['error'] = 'No data returned.'; return $base; }
        $base['status']       = 'found';
        $base['query_method'] = 'whois';
        $base['whois_server'] = $server;
        $base['query_ms']     = $elapsed;
        $base['raw']          = implode("\n", censorIPs($raw));
        return $base;

    } elseif ($type === 'domain') {
        $base['query_type'] = 'domain';
        $asciiQ   = idn_to_ascii($query, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        $apex     = detectApexDomain($query);
        if ($apex) $base['subdomain_suggestion'] = $apex;

        $result = lookupDomain($asciiQ, $whoisServers);
        $elapsed = round((microtime(true) - $t0) * 1000);

        appendLog('api_domain_lookup', [
            'query'  => $query,
            'server' => $result['server'] ?? '',
            'method' => $result['method'] ?? '',
            'status' => $result['status'] ?? '',
            'ms'     => $elapsed,
        ]);

        $base['whois_server'] = $result['server'] ?? '';
        $base['query_method'] = $result['method'] ?? '';
        $base['query_ms']     = $elapsed;
        $base['status']       = $result['status'] ?? 'error';

        if (!empty($result['route_provider'])) {
            $base['route_provider'] = $result['route_provider'];
            $base['route_suffix']   = $result['route_suffix'];
        }
        if (!empty($result['web_url'])) {
            $base['web_lookup_url'] = $result['web_url'];
        }

        if ($result['status'] === 'registered') {
            $parsed = $result['parsed'];
            $apiData = [];
            foreach (['creation_date','expiration_date','updated_date'] as $df) {
                if (!empty($parsed[$df])) {
                    $ts = strtotime($parsed[$df]);
                    $apiData[$df] = ($ts > 0) ? gmdate('Y-m-d\TH:i:s\Z', $ts) : $parsed[$df];
                }
            }
            foreach (['registrar','registrar_iana_id','registrar_whois','abuse_email','abuse_phone',
                      'registrant_name','registrant_org','registrant_country','registrant_email',
                      'registrant_phone','admin_email','tech_email',
                      'nameservers','status','dnssec'] as $f) {
                if (!empty($parsed[$f])) $apiData[$f] = $parsed[$f];
            }
            $base['data'] = $apiData;
        }

        if ($result['status'] === 'error') {
            $base['error'] = ($result['raw'][0] ?? 'Unknown error');
        }
        if ($result['status'] === 'restricted') {
            $base['error'] = 'WHOIS access denied.';
            $webUrl = $result['web_url'] ?? whoisGetWebLookupUrl(explode('.', $asciiQ)[count(explode('.', $asciiQ))-1] ?? '');
            if ($webUrl !== null) $base['web_lookup_url'] = $webUrl;
        }

        $base['raw'] = implode("\n", censorIPs($result['raw'] ?? []));
        return $base;

    } else {
        apiError(400, 'Invalid query. Please supply a valid domain, IP address, or ASN (e.g. AS15169).');
    }
}

// ── API Documentation Page ─────────────────────────────────────────────────

function renderApiDocs(array $T, string $lang): void {
    $h        = fn(string $s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    $authNote = API_ALLOW_UNAUTHENTICATED ? $T['api_auth_public'] : $T['api_auth_protected'];
    $rateNote = sprintf($T['api_rate_note'], RATE_LIMIT);
    $scheme   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host     = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $host     = preg_replace('/:(80|443)$/', '', $host);
    if (!preg_match('/^[a-zA-Z0-9\[\]:\.\-]+$/', $host)) $host = 'your-domain.com';
    $basePath = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/\\');
    $baseUrl  = $scheme . '://' . $host . ($basePath !== '' && $basePath !== '/' ? $basePath : '') . '/api.php';
?>
<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo $h($T['api_page_title']); ?></title>
<link rel="stylesheet" href="./style.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
<style>
.api-hero{text-align:center;padding:40px 0 20px}
.api-hero h1{font-size:32px;font-weight:800;color:var(--clr-primary);letter-spacing:-.03em}
.api-hero p{color:var(--clr-text-secondary);margin-top:8px;font-size:15px}
.api-version-badge{display:inline-flex;align-items:center;gap:8px;background:var(--clr-primary);
  color:#fff;padding:6px 16px;border-radius:99px;font-size:13px;font-weight:700;
  letter-spacing:.04em;margin-top:12px;text-decoration:none}
.doc-section{margin-top:6px}
.doc-section .card-header h2{font-size:15px;font-weight:700;color:var(--clr-text);
  border-bottom:2px solid var(--clr-border);padding-bottom:8px;margin-bottom:14px}
.endpoint-box{background:var(--clr-code-bg);border:1px solid var(--clr-border);
  border-radius:var(--radius-md);padding:14px 18px;font-family:var(--font-mono);
  font-size:13px;margin-bottom:10px;overflow-x:auto;color:var(--clr-text-secondary)}
.endpoint-box .method{color:var(--clr-primary);font-weight:700;margin-right:10px}
.param-table{width:100%;border-collapse:collapse;font-size:14px}
.param-table th{text-align:left;padding:8px 12px;font-size:11px;font-weight:700;letter-spacing:.06em;
  text-transform:uppercase;color:var(--clr-text-muted);background:var(--clr-code-bg);
  border-bottom:1px solid var(--clr-border)}
.param-table td{padding:9px 12px;border-bottom:1px solid var(--clr-border-light);vertical-align:top}
.param-table tr:last-child td{border-bottom:none}
.badge-req{background:#fee2e2;color:#b91c1c;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
.badge-opt{background:#e0f2fe;color:#0369a1;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
.json-block{background:var(--clr-code-bg);border:1px solid var(--clr-border);
  border-radius:var(--radius-md);padding:14px 18px;font-family:var(--font-mono);
  font-size:12.5px;line-height:1.75;overflow-x:auto;white-space:pre;
  color:var(--clr-text-secondary);max-height:420px;overflow-y:auto}
.try-box{display:flex;gap:10px;flex-wrap:wrap}
.try-input{flex:1;min-width:180px;height:42px;padding:0 14px;border:1.5px solid var(--clr-border);
  border-radius:var(--radius-sm);font-size:14px;background:var(--clr-surface);color:var(--clr-text);
  font-family:var(--font-mono);outline:none;transition:border-color .2s}
.try-input:focus{border-color:var(--clr-primary)}
.try-btn{height:42px;padding:0 20px;background:var(--clr-primary);color:#fff;border:none;
  border-radius:var(--radius-sm);font-weight:700;cursor:pointer;font-size:14px;
  transition:background .18s}
.try-btn:hover{background:var(--clr-primary-dark)}
#try-result{margin-top:10px;display:none}
.response-status{font-size:12px;font-weight:700;margin-bottom:6px}
.status-ok{color:var(--clr-success)}.status-err{color:var(--clr-danger)}
.back-link{display:inline-flex;align-items:center;gap:6px;color:var(--clr-text-secondary);
  text-decoration:none;font-size:13px;font-weight:500;margin-bottom:14px}
.back-link:hover{color:var(--clr-primary)}
.sub-heading{font-size:14px;font-weight:700;margin:14px 0 6px;color:var(--clr-text)}
</style>
</head>
<body>
<header>
  <div class="header-content">
    <h2><i class="fa-solid fa-globe"></i> <?php echo $h($T['header_title']); ?></h2>
    <div class="header-actions">
      <button id="theme-toggle" class="icon-btn" aria-label="Toggle dark mode">
        <i class="fa-solid fa-moon" id="theme-icon"></i>
      </button>
      <div class="language-switcher">
        <a href="?lang=en" <?php if ($lang==='en') echo 'class="active"'; ?>>EN</a>
        <a href="?lang=zh-cn" <?php if ($lang==='zh-cn') echo 'class="active"'; ?>>简体</a>
        <a href="?lang=zh-tw" <?php if ($lang==='zh-tw') echo 'class="active"'; ?>>繁體</a>
      </div>
    </div>
  </div>
</header>
<main>
  <a href="index.php?lang=<?php echo $lang; ?>" class="back-link">
    <i class="fa-solid fa-arrow-left"></i> <?php echo $h($T['api_back_link']); ?>
  </a>
  <div class="api-hero">
    <h1><?php echo $h($T['api_hero_title']); ?></h1>
    <p><?php echo $h($T['api_hero_subtitle']); ?></p>
    <span class="api-version-badge"><i class="fa-solid fa-code"></i> v<?php echo API_VERSION; ?></span>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_base_url']); ?></h2></div>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?></div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_auth']); ?></h2></div>
    <p style="font-size:14px;margin-bottom:12px"><?php echo $authNote; ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=google.com&amp;key=YOUR_API_KEY</div>
    <p style="font-size:13px;color:var(--clr-text-muted);margin-bottom:6px"><?php echo $T['api_auth_keys_note']; ?></p>
    <div class="json-block">&lt;?php
$apiKeys = [
    'sk_live_your_secret_key_here',
];</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_rate']); ?></h2></div>
    <p style="font-size:14px;margin-bottom:12px"><?php echo $rateNote; ?></p>
    <table class="param-table">
      <tr><th><?php echo $h($T['api_rate_header_name']); ?></th><th><?php echo $h($T['api_rate_header_desc']); ?></th></tr>
      <tr><td><code>X-RateLimit-Limit</code></td><td><?php echo $h($T['api_rate_limit_label']); ?></td></tr>
      <tr><td><code>X-RateLimit-Remaining</code></td><td><?php echo $h($T['api_rate_remaining_label']); ?></td></tr>
      <tr><td><code>X-RateLimit-Reset</code></td><td><?php echo $h($T['api_rate_reset_label']); ?></td></tr>
    </table>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_params']); ?></h2></div>
    <table class="param-table">
      <tr><th><?php echo $h($T['api_param_name']); ?></th><th><?php echo $h($T['api_param_required']); ?></th><th><?php echo $h($T['api_param_desc']); ?></th></tr>
      <tr>
        <td><code>q</code></td>
        <td><span class="badge-req"><?php echo $h($T['api_param_required']); ?></span></td>
        <td><?php echo $T['api_param_q_desc']; ?> <?php echo $T['api_batch_param_desc'] ?? 'Separate multiple queries with commas or newlines for batch mode.'; ?></td>
      </tr>
      <tr>
        <td><code>key</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_param_key_desc']; ?></td>
      </tr>
      <tr>
        <td><code>dns</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_dns_param_desc']; ?></td>
      </tr>
      <tr>
        <td><code>lang</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_lang_param_desc']; ?></td>
      </tr>
    </table>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_endpoints']); ?></h2></div>
    <p class="sub-heading"><?php echo $h($T['api_endpoint_domain']); ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=google.com</div>
    <p class="sub-heading"><?php echo $h($T['api_endpoint_ip']); ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=8.8.8.8</div>
    <p class="sub-heading"><?php echo $h($T['api_endpoint_asn']); ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=AS15169</div>
    <p class="sub-heading"><?php echo $h($T['api_endpoint_dns']); ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=google.com&amp;dns=true</div>
    <p class="sub-heading"><?php echo $h($T['api_endpoint_batch'] ?? 'Batch lookup'); ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=google.com,github.com,cloudflare.com</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_response']); ?></h2></div>
    <table class="param-table">
      <tr><th><?php echo $h($T['api_col_field']); ?></th><th><?php echo $h($T['api_col_type']); ?></th><th><?php echo $h($T['api_col_desc']); ?></th></tr>
      <tr><td><code>query</code></td><td>string</td><td><?php echo $h($T['api_field_query']); ?></td></tr>
      <tr><td><code>query_type</code></td><td>string</td><td><?php echo $T['api_field_query_type']; ?></td></tr>
      <tr><td><code>status</code></td><td>string</td><td><?php echo $T['api_field_status']; ?></td></tr>
      <tr><td><code>whois_server</code></td><td>string</td><td><?php echo $T['api_field_whois_server']; ?></td></tr>
      <tr><td><code>timestamp</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_timestamp']); ?></td></tr>
      <tr><td><code>query_ms</code></td><td>integer</td><td><?php echo $h($T['api_field_query_ms']); ?></td></tr>
      <tr><td><code>api_version</code></td><td>string</td><td><?php echo $h($T['api_field_api_version']); ?></td></tr>
      <tr><td><code>data</code></td><td>object</td><td><?php echo $T['api_field_data']; ?></td></tr>
      <tr><td><code>data.creation_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_creation']); ?></td></tr>
      <tr><td><code>data.expiration_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_expiration']); ?></td></tr>
      <tr><td><code>data.updated_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_updated']); ?></td></tr>
      <tr><td><code>data.registrar</code></td><td>string</td><td><?php echo $h($T['api_field_registrar']); ?></td></tr>
      <tr><td><code>data.registrar_iana_id</code></td><td>string</td><td><?php echo $h($T['api_field_iana_id']); ?></td></tr>
      <tr><td><code>data.nameservers</code></td><td>array</td><td><?php echo $h($T['api_field_nameservers']); ?></td></tr>
      <tr><td><code>data.status</code></td><td>array</td><td><?php echo $h($T['api_field_statuses']); ?></td></tr>
      <tr><td><code>data.dnssec</code></td><td>string</td><td><?php echo $h($T['api_field_dnssec']); ?></td></tr>
      <tr><td><code>subdomain_suggestion</code></td><td>string?</td><td><?php echo $h($T['api_field_subdomain']); ?></td></tr>
      <tr><td><code>raw</code></td><td>string</td><td><?php echo $h($T['api_field_raw']); ?></td></tr>
    </table>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_sample']); ?> — <code>api.php?q=google.com</code></h2></div>
    <div class="json-block">{
  "query": "google.com",
  "query_type": "domain",
  "whois_server": "whois.markmonitor.com",
  "status": "registered",
  "timestamp": "2025-01-15T10:23:45Z",
  "query_ms": 320,
  "api_version": "<?php echo API_VERSION; ?>",
  "data": {
    "creation_date": "1997-09-15T04:00:00Z",
    "expiration_date": "2028-09-14T04:00:00Z",
    "updated_date": "2019-09-09T15:39:04Z",
    "registrar": "MarkMonitor Inc.",
    "registrar_iana_id": "292",
    "registrar_whois": "whois.markmonitor.com",
    "nameservers": ["ns1.google.com","ns2.google.com","ns3.google.com","ns4.google.com"],
    "status": ["clientDeleteProhibited","clientTransferProhibited"],
    "dnssec": "unsigned"
  },
  "raw": "Domain Name: GOOGLE.COM\r\n..."
}</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_batch_sample_title'] ?? 'Batch Response — <code>api.php?q=google.com,github.com</code>'); ?></h2></div>
    <div class="json-block">{
  "batch": true,
  "count": 2,
  "api_version": "<?php echo API_VERSION; ?>",
  "timestamp": "2025-01-15T10:23:45Z",
  "results": [
    { "query": "google.com", "query_type": "domain", "status": "registered", "..." : "..." },
    { "query": "github.com", "query_type": "domain", "status": "registered", "..." : "..." }
  ]
}</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_errors']); ?></h2></div>
    <table class="param-table">
      <tr><th>HTTP</th><th><?php echo $h($T['api_error_meaning']); ?></th></tr>
      <tr><td><code>400</code></td><td><?php echo $T['api_error_400']; ?></td></tr>
      <tr><td><code>401</code></td><td><?php echo $T['api_error_401']; ?></td></tr>
      <tr><td><code>429</code></td><td><?php echo $T['api_error_429']; ?></td></tr>
      <tr><td><code>500</code></td><td><?php echo $T['api_error_500']; ?></td></tr>
    </table>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_try']); ?></h2></div>
    <div class="try-box">
      <input type="text" class="try-input" id="try-input" placeholder="google.com, 8.8.8.8, AS15169 (comma = batch)" value="google.com">
      <button class="try-btn" onclick="runTry()">
        <i class="fa-solid fa-play"></i> <?php echo $h($T['api_try_send']); ?>
      </button>
    </div>
    <div id="try-result">
      <p class="response-status" id="try-status"></p>
      <div class="json-block" id="try-output"></div>
    </div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_examples']); ?></h2></div>
    <p class="sub-heading"><?php echo $h($T['api_example_js']); ?></p>
    <div class="json-block">fetch(<?php echo json_encode($baseUrl . '?q=google.com'); ?>)
  .then(r => r.json())
  .then(data => {
    console.log(data.status);               // "registered"
    console.log(data.data.registrar);       // "MarkMonitor Inc."
    console.log(data.data.expiration_date); // "2028-09-14T04:00:00Z"
  });</div>
    <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_python']); ?></p>
    <div class="json-block">import requests
resp = requests.get(<?php echo json_encode($baseUrl); ?>, params={'q': 'google.com'})
data = resp.json()
print(data['status'])
print(data['data']['registrar'])</div>
    <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_curl']); ?></p>
    <div class="json-block">curl "<?php echo $h($baseUrl); ?>?q=google.com" | python3 -m json.tool</div>
    <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_batch'] ?? 'Batch Query (cURL)'); ?></p>
    <div class="json-block">curl "<?php echo $h($baseUrl); ?>?q=google.com,github.com,cloudflare.com" | python3 -m json.tool</div>
  </div>
</main>

<footer>
  <p><?php echo $T['footer_text']; ?>
    | <a href="index.php?lang=<?php echo $lang; ?>"><?php echo $h($T['api_footer_lookup']); ?></a>
    | <a href="https://github.com/iezx/Super-Whois" target="_blank" rel="noopener noreferrer"><?php echo $h($T['footer_github']); ?></a>
  </p>
</footer>

<script>
const TK='swTheme',b=document.getElementById('theme-toggle'),i=document.getElementById('theme-icon');
function applyTheme(d){document.documentElement.setAttribute('data-theme',d?'dark':'light');i.className=d?'fa-solid fa-sun':'fa-solid fa-moon';try{localStorage.setItem(TK,d?'dark':'light')}catch(e){}}
(()=>{let s;try{s=localStorage.getItem(TK)}catch(e){}applyTheme(s?s==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches)})();
b.addEventListener('click',()=>applyTheme(document.documentElement.getAttribute('data-theme')!=='dark'));

const loadTxt=<?php echo json_encode($T['api_try_loading']); ?>, errTxt=<?php echo json_encode($T['api_try_network_error']); ?>;
function runTry(){
  const q=document.getElementById('try-input').value.trim(); if(!q) return;
  const sEl=document.getElementById('try-status'),oEl=document.getElementById('try-output');
  document.getElementById('try-result').style.display='block';
  sEl.textContent=loadTxt; sEl.className='response-status'; oEl.textContent='';
  fetch('api.php?q='+encodeURIComponent(q))
    .then(r=>{const sc=r.status,ok=r.ok;return r.json().then(d=>({ok,sc,d}))})
    .then(({ok,sc,d})=>{
      sEl.textContent='HTTP '+sc+(ok?' OK':' Error');
      sEl.className='response-status '+(ok?'status-ok':'status-err');
      oEl.textContent=JSON.stringify(d,null,2);
    }).catch(e=>{sEl.textContent=errTxt;sEl.className='response-status status-err';oEl.textContent=String(e)});
}
document.getElementById('try-input').addEventListener('keydown',e=>{if(e.key==='Enter')runTry()});
</script>
</body>
</html>
<?php
}
