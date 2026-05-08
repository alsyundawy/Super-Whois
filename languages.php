<?php
// languages.php

function get_language_strings(string $lang = 'en'): array {

    // ── English (base / fallback) ────────────────────────────────────────────
    $strings['en'] = [
        // Page meta
        'page_title'        => 'Super Whois - Modern WHOIS Lookup',
        'meta_description'  => 'Fast and modern WHOIS lookup for domains, IPs, and ASNs. Clean, readable, structured results.',
        'header_title'      => 'Super Whois',

        // Search form
        'placeholder'       => 'e.g. google.com,  8.8.8.8,  or  AS15169',
        'search_button'     => 'Search',

        // Result card
        'whois_information'  => 'WHOIS Information',
        'searched_from'      => 'Queried from',
        'domain_registered'  => 'is already registered.',
        'domain_available'       => 'Congratulations! This domain is available for registration.',
        'domain_available_badge' => 'Available',
        'domain_reserved'        => 'This domain is reserved by the registry or is invalid.',
        'show_raw_data'      => 'Show Raw Data',
        'hide_raw_data'      => 'Hide Raw Data',
        'copy_link_button'   => 'Copy Link',
        'copied_feedback'    => 'Copied!',
        'copy_failed'        => 'Failed to copy!',

        // Subdomain suggestion
        'subdomain_hint'        => 'Did you mean to look up',
        'subdomain_hint_suffix' => '?',
        'subdomain_search_btn'  => 'Search',

        // Parsed field group headings
        'group_dates'             => 'Important Dates',
        'group_registrar_contact' => 'Registrar & Contact',
        'group_nameservers'       => 'Nameservers',
        'group_status'            => 'Domain Status',
        'group_dnssec'            => 'DNSSEC',

        // DNS records
        'dns_records'             => 'DNS Records',
        'dns_no_records'          => 'No DNS records found.',
        'dns_error'               => 'Failed to load DNS records.',

        // Result card inline strings
        'status_restricted'       => 'Restricted',
        'denial_headline'         => 'The WHOIS server does not allow direct port-43 access',
        'denial_sub'              => 'This registry restricts automated queries. Use the official web WHOIS tool instead.',
        'denial_btn_label'        => 'Look up on official site',
        'special_route_msg'       => 'This suffix requires a special lookup route.',
        'expired_badge'           => 'Expired',
        'expiring_badge'          => 'Expiring Soon',
        'held_badge'              => 'Held',
        'parse_failed_notice'     => 'Structured parsing unavailable — see raw data below.',
        'date_created'            => 'Created',
        'date_expires'            => 'Expires',
        'date_updated'            => 'Updated',
        'contact_phone'           => 'Phone',
        'contact_abuse_email'     => 'Abuse Email',
        'contact_registrant'      => 'Registrant',
        'contact_organization'    => 'Organization',
        'contact_emails'          => 'Contact Emails',
        'registrar_heading'       => 'Registrar',
        'privacy_protected'       => '(Privacy protected)',

        // Error messages
        'invalid_query'     => 'Invalid query. Please enter a valid Domain, IP, or ASN.',
        'unsupported_tld'   => 'WHOIS lookup for this TLD is not supported.',
        'no_info_found'     => 'Could not retrieve WHOIS information.',

        // Guide toggle
        'toggle_guides_button' => 'Show Guide',
        'hide_guides_button'   => 'Hide Guide',

        // Guide body — step3 (thin/thick technical detail) intentionally removed
        'guide_title'  => 'User Guide',
        'guide_step1'  => 'Enter a <strong>Domain</strong> (e.g. <code>google.com</code>), <strong>IP</strong> (e.g. <code>8.8.8.8</code>), or <strong>ASN</strong> (e.g. <code>AS15169</code>).',
        'guide_step2'  => 'Click <strong>Search</strong> — the system queries the authoritative WHOIS server directly.',
        'guide_step3'  => 'Click <strong>Show Raw Data</strong> to inspect the full unprocessed WHOIS response.',
        'guide_step4'  => 'Click <strong>Copy Link</strong> to share a direct URL to this lookup.',
        'guide_step5'  => 'The <strong>API</strong> button (top-right) opens the programmatic access documentation.',
        'guide_step6'  => 'Use the <i class="fa-solid fa-moon"></i> button to switch between light and dark mode.',

        // History
        'history_records_title' => 'Recent Lookups',
        'history_info'          => 'Your last 10 queries are shown here. Stored locally in your browser.',
        'clear_history_button'  => 'Clear',
        'no_history'            => 'No history yet.',
        'history_click_hint'    => 'Click to search',

        // Footer
        'footer_text'      => '&copy; ' . date('Y') . ' Super Whois',
        'footer_api_link'  => 'API Docs',
        'footer_github'    => 'GitHub',

        // ── API docs page ──────────────────────────────────────────────────
        'api_page_title'           => 'Super Whois — API Documentation',
        'api_hero_title'           => 'Super Whois API',
        'api_hero_subtitle'        => 'Simple, JSON-based WHOIS lookups for domains, IPs, and ASNs.',
        'api_back_link'            => 'Back to lookup',
        'api_section_base_url'     => 'Base URL',
        'api_section_auth'         => 'Authentication',
        'api_auth_public'          => 'The API is publicly accessible without a key. Authenticated requests bypass the rate limit.',
        'api_auth_protected'       => 'The API is key-protected — all requests require a valid API key. Authenticated requests bypass the rate limit.',
        'api_auth_keys_note'       => 'To issue API keys, create <code>api_keys.php</code> in the same directory:',
        'api_section_rate'         => 'Rate Limiting',
        'api_rate_note'            => 'Unauthenticated requests are limited to <strong>%d requests per hour</strong> per IP address.',
        'api_rate_header_name'     => 'Response Header',
        'api_rate_header_desc'     => 'Description',
        'api_rate_limit_label'     => 'Maximum requests per window',
        'api_rate_remaining_label' => 'Requests remaining this window',
        'api_rate_reset_label'     => 'Unix timestamp when window resets',
        'api_section_params'       => 'Query Parameters',
        'api_param_name'           => 'Parameter',
        'api_param_required'       => 'Required',
        'api_param_desc'           => 'Description',
        'api_param_q_desc'         => 'The target to look up. Accepts a domain name (e.g. <code>google.com</code>), IPv4 / IPv6 address, or ASN (e.g. <code>AS15169</code>).',
        'api_param_key_desc'       => 'API key. Bypasses rate limiting when valid.',
        'api_section_endpoints'    => 'Endpoints & Examples',
        'api_endpoint_domain'      => 'Domain lookup',
        'api_endpoint_ip'          => 'IP lookup',
        'api_endpoint_asn'         => 'ASN lookup',
        'api_section_response'     => 'Response Fields',
        'api_section_sample'       => 'Sample Response',
        'api_section_errors'       => 'Error Codes',
        'api_error_meaning'        => 'Meaning',
        'api_error_400'            => 'Bad Request — invalid or missing <code>q</code> parameter',
        'api_error_401'            => 'Unauthorized — API key required but not provided or invalid',
        'api_error_429'            => 'Too Many Requests — rate limit exceeded',
        'api_error_500'            => 'Server Error — PHP extension missing or misconfiguration',
        'api_section_try'          => 'Try It',
        'api_try_send'             => 'Send',
        'api_try_loading'          => 'Loading…',
        'api_try_network_error'    => 'Network error',
        'api_section_examples'     => 'Code Examples',
        'api_example_js'           => 'JavaScript (fetch)',
        'api_example_python'       => 'Python (requests)',
        'api_example_curl'         => 'cURL',
        // response field table
        'api_field_query'          => 'The sanitized input query',
        'api_field_query_type'     => 'domain | ipv4 | ipv6 | asn',
        'api_field_status'         => 'registered | available | found | unsupported_tld | error',
        'api_field_whois_server'   => 'The WHOIS server that provided the data',
        'api_field_timestamp'      => 'UTC time of this API response',
        'api_field_data'           => 'Structured parsed fields (domain queries only, when registered)',
        'api_field_creation'       => 'Domain registration date',
        'api_field_expiration'     => 'Domain expiry date',
        'api_field_updated'        => 'Last updated date',
        'api_field_registrar'      => 'Registrar name',
        'api_field_nameservers'    => 'List of nameservers (lowercase, sorted)',
        'api_field_statuses'       => 'Domain EPP status codes',
        'api_field_dnssec'         => 'signed or unsigned',
        'api_field_raw'            => 'Full raw WHOIS response (IPs redacted)',

        // API docs inline
        'api_optional'             => 'Optional',
        'api_dns_param_desc'       => 'Set to <code>true</code> to include DNS records (A, AAAA, MX, TXT, NS) in domain lookup results',
        'api_lang_param_desc'      => 'Docs language: <code>en</code> (default), <code>zh-cn</code> (Simplified), or <code>zh-tw</code> (Traditional)',
        'api_endpoint_dns'         => 'Domain + DNS Records lookup',
        'api_field_query_ms'       => 'Query time in milliseconds',
        'api_field_api_version'    => 'API version string',
        'api_field_iana_id'        => 'Registrar IANA ID',
        'api_field_subdomain'      => 'If querying a subdomain, the suggested apex domain',
        'api_response_fields'      => 'Response Fields',
        'api_col_field'            => 'Field',
        'api_col_type'             => 'Type',
        'api_col_desc'             => 'Description',
        'api_footer_lookup'        => 'Lookup Tool',
    ];

    // ── Simplified Chinese (zh-cn / zh) ─────────────────────────────────────
    $strings['zh-cn'] = [
        // Page meta
        'page_title'       => 'Super Whois - WHOIS 查询工具',
        'meta_description' => '快速、现代化的域名、IP 及 ASN WHOIS 查询工具，提供清晰、易读的结构化结果。',

        // Search
        'placeholder'  => '例如: google.com、8.8.8.8 或 AS15169',
        'search_button' => '查询',

        // Result
        'whois_information' => 'WHOIS 信息',
        'searched_from'     => '查询自',
        'domain_registered' => '已被注册。',
        'domain_available'       => '恭喜！该域名可以注册。',
        'domain_available_badge' => '可注册',
        'domain_reserved'        => '该域名为注册局保留域名或无效。',
        'show_raw_data'     => '显示原始数据',
        'hide_raw_data'     => '隐藏原始数据',
        'copy_link_button'  => '复制链接',
        'copied_feedback'   => '已复制！',
        'copy_failed'       => '复制失败！',

        // Subdomain suggestion
        'subdomain_hint'        => '您是否想查询',
        'subdomain_hint_suffix' => '？',
        'subdomain_search_btn'  => '查询',

        // Group headings
        'group_dates'             => '重要日期',
        'group_registrar_contact' => '注册商与联系人',
        'group_nameservers'       => '名称服务器',
        'group_status'            => '域名状态',
        'group_dnssec'            => 'DNSSEC',

        // DNS records
        'dns_records'             => 'DNS 记录',
        'dns_no_records'          => '未找到 DNS 记录。',
        'dns_error'               => '加载 DNS 记录失败。',

        // Result card inline strings
        'status_restricted'       => '访问受限',
        'denial_headline'         => '该域名的 WHOIS 服务器不允许直接查询',
        'denial_sub'              => '该 TLD 的注册局限制了自动查询访问。请使用官方 Web WHOIS 工具查询。',
        'denial_btn_label'        => '在官方网站查询',
        'special_route_msg'       => '该后缀需走特殊查询通道。',
        'expired_badge'           => '已过期',
        'expiring_badge'          => '即将过期',
        'held_badge'              => '冻结',
        'parse_failed_notice'     => '结构化解析失败，请查看原始数据。',
        'date_created'            => '创建日期',
        'date_expires'            => '到期日期',
        'date_updated'            => '更新日期',
        'contact_phone'           => '电话',
        'contact_abuse_email'     => '举报邮箱',
        'contact_registrant'      => '注册人',
        'contact_organization'    => '注册组织',
        'contact_emails'          => '联系邮箱',
        'registrar_heading'       => '注册商',
        'privacy_protected'       => '(隐私保护，信息不可用)',

        // Errors
        'invalid_query'    => '无效查询。请输入有效的域名、IP 或 ASN。',
        'unsupported_tld'  => '暂不支持该域名后缀的 WHOIS 查询。',
        'no_info_found'    => '无法获取 WHOIS 信息。',

        // Guide toggle
        'toggle_guides_button' => '显示指南',
        'hide_guides_button'   => '隐藏指南',

        // Guide body
        'guide_title'  => '使用指南',
        'guide_step1'  => '在搜索框输入<strong>域名</strong>（如 <code>google.com</code>）、<strong>IP</strong>（如 <code>8.8.8.8</code>）或 <strong>ASN</strong>（如 <code>AS15169</code>）。',
        'guide_step2'  => '点击<strong>查询</strong>，系统将直接向权威 WHOIS 服务器发起请求。',
        'guide_step3'  => '点击<strong>显示原始数据</strong>可查看完整的原始 WHOIS 响应。',
        'guide_step4'  => '点击<strong>复制链接</strong>可分享本次查询的直达链接。',
        'guide_step5'  => '右上角 <strong>API</strong> 按钮可查看程序化调用文档。',
        'guide_step6'  => '点击 <i class="fa-solid fa-moon"></i> 图标可切换深色 / 浅色模式。',

        // History
        'history_records_title' => '查询历史',
        'history_info'          => '此处显示最近 10 条查询记录，保存在您的本地浏览器中。',
        'clear_history_button'  => '清空',
        'no_history'            => '暂无历史记录。',
        'history_click_hint'    => '点击以查询',

        // Footer
        'footer_api_link' => 'API 文档',
        'footer_github'   => 'GitHub',

        // API docs page
        'api_page_title'           => 'Super Whois — API 文档',
        'api_hero_title'           => 'Super Whois API',
        'api_hero_subtitle'        => '简单易用的 JSON 格式 WHOIS 查询接口，支持域名、IP 及 ASN。',
        'api_back_link'            => '返回查询页',
        'api_section_base_url'     => '基础 URL',
        'api_section_auth'         => '认证',
        'api_auth_public'          => '该 API 无需密钥即可公开访问。使用 API Key 的请求可绕过速率限制。',
        'api_auth_protected'       => '该 API 需要有效的 API Key 才能访问。使用 API Key 的请求可绕过速率限制。',
        'api_auth_keys_note'       => '如需创建 API Key，请在相同目录下新建 <code>api_keys.php</code> 文件：',
        'api_section_rate'         => '速率限制',
        'api_rate_note'            => '未认证请求每小时每个 IP 最多 <strong>%d 次</strong>。',
        'api_rate_header_name'     => '响应头',
        'api_rate_header_desc'     => '说明',
        'api_rate_limit_label'     => '每个时间窗口的最大请求数',
        'api_rate_remaining_label' => '当前窗口剩余请求数',
        'api_rate_reset_label'     => '时间窗口重置的 Unix 时间戳',
        'api_section_params'       => '请求参数',
        'api_param_name'           => '参数',
        'api_param_required'       => '必填',
        'api_param_desc'           => '说明',
        'api_param_q_desc'         => '查询目标。支持域名（如 <code>google.com</code>）、IPv4/IPv6 地址，或 ASN（如 <code>AS15169</code>）。',
        'api_param_key_desc'       => 'API Key，有效时可绕过速率限制。',
        'api_section_endpoints'    => '接口与示例',
        'api_endpoint_domain'      => '域名查询',
        'api_endpoint_ip'          => 'IP 查询',
        'api_endpoint_asn'         => 'ASN 查询',
        'api_section_response'     => '响应字段说明',
        'api_section_sample'       => '响应示例',
        'api_section_errors'       => '错误码',
        'api_error_meaning'        => '含义',
        'api_error_400'            => '请求错误 — <code>q</code> 参数无效或缺失',
        'api_error_401'            => '未授权 — 需要 API Key 但未提供或无效',
        'api_error_429'            => '请求过频 — 超出速率限制',
        'api_error_500'            => '服务器错误 — PHP 扩展缺失或配置错误',
        'api_section_try'          => '在线测试',
        'api_try_send'             => '发送',
        'api_try_loading'          => '加载中…',
        'api_try_network_error'    => '网络错误',
        'api_section_examples'     => '代码示例',
        'api_example_js'           => 'JavaScript (fetch)',
        'api_example_python'       => 'Python (requests)',
        'api_example_curl'         => 'cURL',
        // response field table
        'api_field_query'          => '经过处理的查询输入',
        'api_field_query_type'     => 'domain | ipv4 | ipv6 | asn',
        'api_field_status'         => 'registered | available | found | unsupported_tld | error',
        'api_field_whois_server'   => '实际提供数据的 WHOIS 服务器',
        'api_field_timestamp'      => '本次 API 响应的 UTC 时间',
        'api_field_data'           => '结构化解析字段（仅域名查询且已注册时返回）',
        'api_field_creation'       => '域名注册日期',
        'api_field_expiration'     => '域名到期日期',
        'api_field_updated'        => '最后更新日期',
        'api_field_registrar'      => '注册商名称',
        'api_field_nameservers'    => '域名服务器列表（小写，已排序）',
        'api_field_statuses'       => '域名 EPP 状态码',
        'api_field_dnssec'         => 'signed（已签名）或 unsigned（未签名）',
        'api_field_raw'            => '完整原始 WHOIS 响应（IP 已脱敏）',

        // API docs inline
        'api_optional'             => '可选',
        'api_dns_param_desc'       => '设为 <code>true</code> 时在域名查询结果中附加 DNS 记录（A、AAAA、MX、TXT、NS）',
        'api_lang_param_desc'      => '文档语言：<code>en</code>（默认）、<code>zh-cn</code>（简体）或 <code>zh-tw</code>（繁体）',
        'api_endpoint_dns'         => '域名 + DNS 记录查询',
        'api_field_query_ms'       => '查询耗时（毫秒）',
        'api_field_api_version'    => 'API 版本号',
        'api_field_iana_id'        => '注册商 IANA 编号',
        'api_field_subdomain'      => '若查询的是子域名，建议查询的顶级域名',
        'api_response_fields'      => '响应字段说明',
        'api_col_field'            => '字段',
        'api_col_type'             => '类型',
        'api_col_desc'             => '说明',
        'api_footer_lookup'        => '查询工具',
    ];

    // ── Traditional Chinese (zh-tw) ─────────────────────────────────────────
    $strings['zh-tw'] = [
        // Page meta
        'page_title'       => 'Super Whois - WHOIS 查詢工具',
        'meta_description' => '快速、現代化的域名、IP 及 ASN WHOIS 查詢工具，提供清晰易讀的結構化結果。',

        // Search
        'placeholder'  => '例如: google.com、8.8.8.8 或 AS15169',
        'search_button' => '查詢',

        // Result
        'whois_information' => 'WHOIS 資訊',
        'searched_from'     => '查詢自',
        'domain_registered' => '已被註冊。',
        'domain_available'       => '恭喜！該域名可以註冊。',
        'domain_available_badge' => '可註冊',
        'domain_reserved'        => '該域名為註冊局保留域名或無效。',
        'show_raw_data'     => '顯示原始資料',
        'hide_raw_data'     => '隱藏原始資料',
        'copy_link_button'  => '複製連結',
        'copied_feedback'   => '已複製！',
        'copy_failed'       => '複製失敗！',

        // Subdomain suggestion
        'subdomain_hint'        => '您是否想查詢',
        'subdomain_hint_suffix' => '？',
        'subdomain_search_btn'  => '查詢',

        // Group headings
        'group_dates'             => '重要日期',
        'group_registrar_contact' => '註冊商與聯繫人',
        'group_nameservers'       => '名稱伺服器',
        'group_status'            => '域名狀態',
        'group_dnssec'            => 'DNSSEC',

        // DNS records
        'dns_records'             => 'DNS 記錄',
        'dns_no_records'          => '未找到 DNS 記錄。',
        'dns_error'               => '載入 DNS 記錄失敗。',

        // Result card inline strings
        'status_restricted'       => '存取受限',
        'denial_headline'         => '該域名的 WHOIS 伺服器不允許直接查詢',
        'denial_sub'              => '該 TLD 的註冊局限制了自動查詢存取。請使用官方 Web WHOIS 工具查詢。',
        'denial_btn_label'        => '在官方網站查詢',
        'special_route_msg'       => '該後綴需走特殊查詢通道。',
        'expired_badge'           => '已過期',
        'expiring_badge'          => '即將過期',
        'held_badge'              => '凍結',
        'parse_failed_notice'     => '結構化解析失敗，請查看原始資料。',
        'date_created'            => '建立日期',
        'date_expires'            => '到期日期',
        'date_updated'            => '更新日期',
        'contact_phone'           => '電話',
        'contact_abuse_email'     => '舉報信箱',
        'contact_registrant'      => '註冊人',
        'contact_organization'    => '註冊組織',
        'contact_emails'          => '聯繫信箱',
        'registrar_heading'       => '註冊商',
        'privacy_protected'       => '(隱私保護，資訊不可用)',

        // Errors
        'invalid_query'    => '無效查詢。請輸入有效的域名、IP 或 ASN。',
        'unsupported_tld'  => '暫不支援該域名後綴的 WHOIS 查詢。',
        'no_info_found'    => '無法獲取 WHOIS 資訊。',

        // Guide toggle
        'toggle_guides_button' => '顯示指南',
        'hide_guides_button'   => '隱藏指南',

        // Guide body
        'guide_title'  => '使用指南',
        'guide_step1'  => '在搜尋框輸入<strong>域名</strong>（如 <code>google.com</code>）、<strong>IP</strong>（如 <code>8.8.8.8</code>）或 <strong>ASN</strong>（如 <code>AS15169</code>）。',
        'guide_step2'  => '點擊<strong>查詢</strong>，系統將直接向權威 WHOIS 伺服器發起請求。',
        'guide_step3'  => '點擊<strong>顯示原始資料</strong>可查看完整的原始 WHOIS 回應。',
        'guide_step4'  => '點擊<strong>複製連結</strong>可分享本次查詢的直達連結。',
        'guide_step5'  => '右上角 <strong>API</strong> 按鈕可查看程式化調用文件。',
        'guide_step6'  => '點擊 <i class="fa-solid fa-moon"></i> 圖示可切換深色 / 淺色模式。',

        // History
        'history_records_title' => '查詢歷史',
        'history_info'          => '此處顯示最近 10 條查詢記錄，保存在您的本地瀏覽器中。',
        'clear_history_button'  => '清空',
        'no_history'            => '暫無歷史記錄。',
        'history_click_hint'    => '點擊以查詢',

        // Footer
        'footer_api_link' => 'API 文件',
        'footer_github'   => 'GitHub',

        // API docs page
        'api_page_title'           => 'Super Whois — API 文件',
        'api_hero_title'           => 'Super Whois API',
        'api_hero_subtitle'        => '簡單易用的 JSON 格式 WHOIS 查詢介面，支援域名、IP 及 ASN。',
        'api_back_link'            => '返回查詢頁',
        'api_section_base_url'     => '基礎 URL',
        'api_section_auth'         => '認證',
        'api_auth_public'          => '該 API 無需金鑰即可公開存取。使用 API Key 的請求可繞過速率限制。',
        'api_auth_protected'       => '該 API 需要有效的 API Key 才能存取。使用 API Key 的請求可繞過速率限制。',
        'api_auth_keys_note'       => '如需建立 API Key，請在相同目錄下新增 <code>api_keys.php</code> 檔案：',
        'api_section_rate'         => '速率限制',
        'api_rate_note'            => '未認證請求每小時每個 IP 最多 <strong>%d 次</strong>。',
        'api_rate_header_name'     => '回應標頭',
        'api_rate_header_desc'     => '說明',
        'api_rate_limit_label'     => '每個時間視窗的最大請求數',
        'api_rate_remaining_label' => '當前視窗剩餘請求數',
        'api_rate_reset_label'     => '時間視窗重置的 Unix 時間戳',
        'api_section_params'       => '請求參數',
        'api_param_name'           => '參數',
        'api_param_required'       => '必填',
        'api_param_desc'           => '說明',
        'api_param_q_desc'         => '查詢目標。支援域名（如 <code>google.com</code>）、IPv4/IPv6 位址，或 ASN（如 <code>AS15169</code>）。',
        'api_param_key_desc'       => 'API Key，有效時可繞過速率限制。',
        'api_section_endpoints'    => '介面與範例',
        'api_endpoint_domain'      => '域名查詢',
        'api_endpoint_ip'          => 'IP 查詢',
        'api_endpoint_asn'         => 'ASN 查詢',
        'api_section_response'     => '回應欄位說明',
        'api_section_sample'       => '回應範例',
        'api_section_errors'       => '錯誤碼',
        'api_error_meaning'        => '含義',
        'api_error_400'            => '請求錯誤 — <code>q</code> 參數無效或缺失',
        'api_error_401'            => '未授權 — 需要 API Key 但未提供或無效',
        'api_error_429'            => '請求過頻 — 超出速率限制',
        'api_error_500'            => '伺服器錯誤 — PHP 擴充套件缺失或設定錯誤',
        'api_section_try'          => '線上測試',
        'api_try_send'             => '傳送',
        'api_try_loading'          => '載入中…',
        'api_try_network_error'    => '網路錯誤',
        'api_section_examples'     => '程式碼範例',
        'api_example_js'           => 'JavaScript (fetch)',
        'api_example_python'       => 'Python (requests)',
        'api_example_curl'         => 'cURL',
        // response field table
        'api_field_query'          => '經過處理的查詢輸入',
        'api_field_query_type'     => 'domain | ipv4 | ipv6 | asn',
        'api_field_status'         => 'registered | available | found | unsupported_tld | error',
        'api_field_whois_server'   => '實際提供資料的 WHOIS 伺服器',
        'api_field_timestamp'      => '本次 API 回應的 UTC 時間',
        'api_field_data'           => '結構化解析欄位（僅域名查詢且已註冊時回傳）',
        'api_field_creation'       => '域名註冊日期',
        'api_field_expiration'     => '域名到期日期',
        'api_field_updated'        => '最後更新日期',
        'api_field_registrar'      => '註冊商名稱',
        'api_field_nameservers'    => '域名伺服器列表（小寫，已排序）',
        'api_field_statuses'       => '域名 EPP 狀態碼',
        'api_field_dnssec'         => 'signed（已簽署）或 unsigned（未簽署）',
        'api_field_raw'            => '完整原始 WHOIS 回應（IP 已脫敏）',

        // API docs inline
        'api_optional'             => '可選',
        'api_dns_param_desc'       => '設為 <code>true</code> 時在域名查詢結果中附加 DNS 記錄（A、AAAA、MX、TXT、NS）',
        'api_lang_param_desc'      => '文件語言：<code>en</code>（預設）、<code>zh-cn</code>（簡體）或 <code>zh-tw</code>（繁體）',
        'api_endpoint_dns'         => '域名 + DNS 記錄查詢',
        'api_field_query_ms'       => '查詢耗時（毫秒）',
        'api_field_api_version'    => 'API 版本號',
        'api_field_iana_id'        => '註冊商 IANA 編號',
        'api_field_subdomain'      => '若查詢的是子域名，建議查詢的頂級域名',
        'api_response_fields'      => '回應欄位說明',
        'api_col_field'            => '欄位',
        'api_col_type'             => '類型',
        'api_col_desc'             => '說明',
        'api_footer_lookup'        => '查詢工具',
    ];

    // Backward compatibility: 'zh' maps to 'zh-cn'
    $strings['zh'] = $strings['zh-cn'];

    if ($lang !== 'en' && isset($strings[$lang])) {
        return array_merge($strings['en'], $strings[$lang]);
    }

    return $strings['en'];
}
