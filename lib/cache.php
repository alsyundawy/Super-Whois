<?php
/** lib/cache.php — JSON file cache with TTL */

// ── Constants (may be overridden by including file before require) ─────────
if (!defined('RATE_LIMIT'))  define('RATE_LIMIT',  30);
if (!defined('RATE_WINDOW')) define('RATE_WINDOW', 3600);
if (!defined('RATE_STORE'))  define('RATE_STORE',  __DIR__ . '/rate_store');
if (!defined('TRUST_PROXY')) define('TRUST_PROXY', true);
if (!defined('LOG_DIR'))     define('LOG_DIR',     __DIR__ . '/logs');
if (!defined('LOG_KEEP_DAYS')) define('LOG_KEEP_DAYS', 30);
if (!defined('CACHE_DIR'))   define('CACHE_DIR',   __DIR__ . '/cache');
if (!defined('CACHE_TTL_RDAP'))  define('CACHE_TTL_RDAP',  86400);
if (!defined('CACHE_TTL_WHOIS')) define('CACHE_TTL_WHOIS', 120);
if (!defined('CACHE_TTL_IANA'))  define('CACHE_TTL_IANA',  604800);

// ── Cache ──────────────────────────────────────────────────────────────────

function ensureCacheDir(): void {
    $dir = CACHE_DIR;
    if (!is_dir($dir)) @mkdir($dir, 0750, true);
}

/**
 * Read from a JSON cache file if fresh; otherwise call $fetch callback and cache.
 * @return mixed  Decoded JSON data, or null on failure.
 */
function cacheGetOrFetch(string $key, int $ttl, callable $fetch): mixed {
    ensureCacheDir();
    $file = CACHE_DIR . '/' . preg_replace('/[^a-z0-9_.-]/i', '_', $key) . '.json';
    $now  = time();
    if (file_exists($file) && ($now - filemtime($file)) < $ttl) {
        $raw = @file_get_contents($file);
        if ($raw !== false) {
            $data = json_decode($raw, true);
            if ($data !== null) {
                appendLog('cache_hit', ['key' => $key, 'file' => basename($file)]);
                return $data;
            }
        }
    }
    $data = $fetch();
    if ($data !== null) {
        $fp = @fopen($file, 'w');
        if ($fp) {
            flock($fp, LOCK_EX);
            fwrite($fp, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }
    return $data;
}
