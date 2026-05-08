<?php
// lib/log.php — Structured JSON logging with auto-cleanup

/**
 * Append a structured JSON line to today's log file.
 * All logging funnels through here — no more per-IP fragmented files.
 */
function appendLog(string $event, array $context = []): void {
    $dir = LOG_DIR;
    if (!is_dir($dir)) { @mkdir($dir, 0750, true); }
    $file = $dir . '/' . gmdate('Y-m-d') . '.log';
    $entry = json_encode(array_merge([
        'ts'    => gmdate('Y-m-d\TH:i:s\Z'),
        'event' => $event,
        'ip'    => getClientIP(),
    ], $context), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    $fp = @fopen($file, 'a');
    if ($fp) { fwrite($fp, $entry); fclose($fp); }
    // Cleanup old logs roughly 1% of the time to avoid overhead
    if (mt_rand(1, 100) === 1) cleanOldLogs();
}

/**
 * Delete log files older than LOG_KEEP_DAYS days.
 */
function cleanOldLogs(): void {
    $dir = LOG_DIR;
    if (!is_dir($dir)) return;
    $cutoff = time() - (LOG_KEEP_DAYS * 86400);
    foreach (glob($dir . '/*.log') ?: [] as $f) {
        if (filemtime($f) < $cutoff) @unlink($f);
    }
}
