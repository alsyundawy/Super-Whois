<?php
/**
 * whois_core.php — Super Whois v2.2.1 shared library (entry point)
 *
 * Loads modular components from lib/. No functions defined here.
 * index.php and api.php require this file as before — no changes needed.
 *
 * Module dependency order matters:
 *   cache → log → network → rdap → whois → dns → parse → utils
 */

$libDir = __DIR__ . '/lib';

// Order: network (IP) → log (needs getClientIP) → cache (needs appendLog)
//      → parse (no deps) → rdap → whois (needs parse, rdap) → dns → utils
require_once $libDir . '/network.php';
require_once $libDir . '/log.php';
require_once $libDir . '/cache.php';
require_once $libDir . '/parse.php';
require_once $libDir . '/rdap.php';
require_once $libDir . '/whois.php';
require_once $libDir . '/dns.php';
require_once $libDir . '/utils.php';
