<?php
// Конфигурация для проверки хостов
// Локация: Финляндия, Хельсинки

// Настройки локации
$LOCATION_CONFIG = [
    'finland_helsinki' => [
        'name' => 'Хельсинки, Финляндия',
        'country' => 'Финляндия',
        'city' => 'Хельсинки',
        'timezone' => 'Europe/Helsinki',
        'coordinates' => [
            'lat' => 60.1699,
            'lon' => 24.9384
        ],
        'isp_info' => [
            'name' => 'Telia Finland',
            'asn' => 'AS1299',
            'ip_range' => '83.150.0.0/16'
        ]
    ]
];

// Настройки проверок (ускоренные)
$CHECK_CONFIG = [
    'http' => [
        'enabled' => true,
        'timeout' => 3,
        'ports' => [80, 443],
        'user_agent' => 'CheckHost-Finland/1.0'
    ],
    'ping' => [
        'enabled' => true,
        'count' => 2,
        'timeout' => 2,
        'size' => 32
    ],
    'dns' => [
        'enabled' => true,
        'timeout' => 3,
        'types' => ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    ],
    'traceroute' => [
        'enabled' => true,
        'max_hops' => 15,
        'timeout' => 1
    ]
];

// Настройки безопасности (отключены)
$SECURITY_CONFIG = [
    'rate_limit' => [
        'enabled' => false,
        'max_requests' => 100,
        'time_window' => 60
    ],
    'allowed_domains' => [],
    'blocked_ips' => []
];

// Функция для получения конфигурации локации
function getLocationConfig($location_key = 'finland_helsinki') {
    global $LOCATION_CONFIG;
    return isset($LOCATION_CONFIG[$location_key]) ? $LOCATION_CONFIG[$location_key] : null;
}

// Функция для получения конфигурации проверки
function getCheckConfig($check_type) {
    global $CHECK_CONFIG;
    return isset($CHECK_CONFIG[$check_type]) ? $CHECK_CONFIG[$check_type] : null;
}

// Функция для проверки безопасности (всегда разрешает)
function isRequestAllowed($ip, $domain) {
    return true;
}
?> 