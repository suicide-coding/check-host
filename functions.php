<?php
require_once 'config.php';

/**
 * Класс для проверки хостов из локации Финляндия, Хельсинки
 */
class HostChecker {
    private $location_config;
    private $results = [];
    
    public function __construct($location_key = 'finland_helsinki') {
        $this->location_config = getLocationConfig($location_key);
        if (!$this->location_config) {
            throw new Exception("Неизвестная локация: $location_key");
        }
    }
    
    /**
     * Основная функция проверки хоста
     */
    public function checkHost($host, $check_types = ['http', 'ping', 'dns']) {
        $this->results = [];
        $original_host = trim($host);
        
        // Очищаем хост от протокола и пути
        $host = $this->cleanHost($original_host);
        
        // Валидация хоста
        if (!$this->validateHost($host)) {
            throw new Exception("Некорректный формат хоста: $original_host");
        }
        
        // Получение IP адреса
        $ip = $this->resolveIP($host);
        if (!$ip) {
            throw new Exception("Не удалось разрешить IP адрес для: $host");
        }
        
        // Получение информации об IP
        $ip_info = $this->getIPInfo($ip);
        
        // Выполнение проверок
        foreach ($check_types as $check_type) {
            if (getCheckConfig($check_type) && getCheckConfig($check_type)['enabled']) {
                $this->results[$check_type] = $this->performCheck($check_type, $host, $ip, $ip_info);
            }
        }
        
        return $this->formatResults($ip_info);
    }
    
    /**
     * Валидация хоста
     */
    private function validateHost($host) {
        // Проверка на IP адрес
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return true;
        }
        
        // Проверка на домен
        if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $host)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Очистка хоста от протокола и пути
     */
    private function cleanHost($host) {
        // Убираем протокол (http://, https://, ftp:// и т.д.)
        $host = preg_replace('/^https?:\/\//', '', $host);
        $host = preg_replace('/^ftp:\/\//', '', $host);
        
        // Убираем путь после домена (все что после /)
        $host = explode('/', $host)[0];
        
        // Убираем порт если есть
        $host = explode(':', $host)[0];
        
        // Убираем пробелы
        $host = trim($host);
        
        return $host;
    }
    
    /**
     * Разрешение IP адреса
     */
    private function resolveIP($host) {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }
        $ip = gethostbyname($host);
        return ($ip !== $host) ? $ip : null;
    }
    
    /**
     * Получение информации об IP адресе
     */
    private function getIPInfo($ip) {
        $info = [
            'ip' => $ip,
            'country' => 'Unknown',
            'city' => 'Unknown',
            'region' => 'Unknown',
            'isp' => 'Unknown',
            'org' => 'Unknown',
            'timezone' => 'Unknown',
            'latitude' => null,
            'longitude' => null
        ];
        
        try {
            // Используем бесплатный API ipapi.co
            $url = "http://ip-api.com/json/$ip?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting";
            
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 3,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_USERAGENT => 'CheckHost-Finland/1.0'
            ]);
            
            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($http_code === 200 && $response) {
                $data = json_decode($response, true);
                
                if ($data && isset($data['status']) && $data['status'] === 'success') {
                    $info['country'] = $data['country'] ?? 'Unknown';
                    $info['city'] = $data['city'] ?? 'Unknown';
                    $info['region'] = $data['regionName'] ?? 'Unknown';
                    $info['isp'] = $data['isp'] ?? 'Unknown';
                    $info['org'] = $data['org'] ?? 'Unknown';
                    $info['timezone'] = $data['timezone'] ?? 'Unknown';
                    $info['latitude'] = $data['lat'] ?? null;
                    $info['longitude'] = $data['lon'] ?? null;
                    $info['asn'] = $data['as'] ?? 'Unknown';
                    $info['mobile'] = $data['mobile'] ?? false;
                    $info['proxy'] = $data['proxy'] ?? false;
                    $info['hosting'] = $data['hosting'] ?? false;
                }
            }
        } catch (Exception $e) {}
        
        return $info;
    }
    
    /**
     * Выполнение конкретной проверки
     */
    private function performCheck($check_type, $host, $ip, $ip_info) {
        switch ($check_type) {
            case 'http':
                return $this->checkHTTP($host, $ip, $ip_info);
            case 'ping':
                return $this->checkPing($host, $ip, $ip_info);
            case 'dns':
                return $this->checkDNS($host, $ip_info);
            case 'traceroute':
                return $this->checkTraceroute($host, $ip, $ip_info);
            default:
                return ['error' => "Неизвестный тип проверки: $check_type"];
        }
    }
    
    /**
     * HTTP/HTTPS проверка
     */
    private function checkHTTP($host, $ip, $ip_info) {
        $config = getCheckConfig('http');
        $results = [];
        
        foreach ($config['ports'] as $port) {
            $protocol = ($port == 443 || $port == 8443) ? 'https' : 'http';
            $url = "$protocol://$host:$port";
            
            $start_time = microtime(true);
            
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $config['timeout'],
                CURLOPT_CONNECTTIMEOUT => $config['timeout'],
                CURLOPT_USERAGENT => $config['user_agent'],
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_NOBODY => true,
                CURLOPT_HEADER => true
            ]);
            
            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);
            
            $end_time = microtime(true);
            $response_time = round(($end_time - $start_time) * 1000, 2);
            
            // Определяем статус и ответ
            $status = 'success';
            $explanation = '';
            
            if ($error) {
                $status = 'error';
                $explanation = "Ошибка соединения: $error";
            } elseif ($http_code >= 200 && $http_code < 400) {
                $status = 'success';
                $explanation = "HTTP код: $http_code";
            } else {
                $status = 'warning';
                if ($http_code >= 400 && $http_code < 500) {
                    $explanation = "Ошибка клиента (HTTP $http_code)";
                } elseif ($http_code >= 500) {
                    $explanation = "Ошибка сервера (HTTP $http_code)";
                } else {
                    $explanation = "Неожиданный HTTP код: $http_code";
                }
            }
            
            $results[$port] = [
                'protocol' => $protocol,
                'port' => $port,
                'status' => $status,
                'explanation' => $explanation,
                'http_code' => $http_code,
                'response_time' => $response_time,
                'error' => $error,
                'ip' => $ip,
                'ip_info' => $ip_info,
                'location' => $this->location_config['name'],
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }
        
        return $results;
    }
    
    /**
     * Ping проверка
     */
    private function checkPing($host, $ip, $ip_info) {
        $config = getCheckConfig('ping');
        
        if (PHP_OS_FAMILY === 'Windows') {
            $ping_cmd = "ping -n {$config['count']} -w " . ($config['timeout'] * 1000) . " $host";
        } else {
            $ping_cmd = "ping -c {$config['count']} -W {$config['timeout']} $host";
        }
        
        $start_time = microtime(true);
        $output = shell_exec($ping_cmd . " 2>&1");
        $end_time = microtime(true);
        $response_time = round(($end_time - $start_time) * 1000, 2);
        
        if ($output === null) {
            return [
                'host' => $host,
                'ip' => $ip,
                'ip_info' => $ip_info,
                'status' => 'error',
                'explanation' => "Команда ping не выполнилась",
                'response_time' => $response_time,
                'ping_stats' => [
                    'success' => false,
                    'sent' => 0,
                    'received' => 0,
                    'lost' => 0,
                    'packet_loss' => 100,
                    'avg_time' => 0
                ],
                'raw_output' => 'Command failed',
                'location' => $this->location_config['name'],
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }
        
        $ping_stats = $this->parsePingOutput($output);
        $status = 'success';
        $explanation = '';
        
        if (!$ping_stats['success']) {
            $status = 'error';
            $explanation = "Хост недоступен (100% потери пакетов)";
        } elseif ($ping_stats['packet_loss'] > 0) {
            $status = 'warning';
            $explanation = "Потери пакетов: {$ping_stats['packet_loss']}%";
        } else {
            $status = 'success';
            $explanation = "Среднее время: {$ping_stats['avg_time']}ms";
        }
        
        return [
            'host' => $host,
            'ip' => $ip,
            'ip_info' => $ip_info,
            'status' => $status,
            'explanation' => $explanation,
            'response_time' => $response_time,
            'ping_stats' => $ping_stats,
            'raw_output' => substr($output, 0, 500),
            'location' => $this->location_config['name'],
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
    
    /**
     * Парсинг вывода ping
     */
    private function parsePingOutput($output) {
        if (PHP_OS_FAMILY === 'Windows') {
            if (preg_match('/Sent = (\d+), Received = (\d+), Lost = (\d+)/', $output, $matches)) {
                $sent = (int)$matches[1];
                $received = (int)$matches[2];
                $lost = (int)$matches[3];
                $packet_loss = $sent > 0 ? round(($lost / $sent) * 100, 2) : 100;
                preg_match('/Average = (\d+)ms/', $output, $time_matches);
                $avg_time = isset($time_matches[1]) ? (int)$time_matches[1] : 0;
                return [
                    'success' => $received > 0,
                    'sent' => $sent,
                    'received' => $received,
                    'lost' => $lost,
                    'packet_loss' => $packet_loss,
                    'avg_time' => $avg_time
                ];
            }
            
            if (preg_match('/(\d+) packets transmitted, (\d+) received/', $output, $matches)) {
                $sent = (int)$matches[1];
                $received = (int)$matches[2];
                $lost = $sent - $received;
                $packet_loss = $sent > 0 ? round(($lost / $sent) * 100, 2) : 100;
                preg_match('/Average = ([\d.]+)ms/', $output, $time_matches);
                $avg_time = isset($time_matches[1]) ? (float)$time_matches[1] : 0;
                return [
                    'success' => $received > 0,
                    'sent' => $sent,
                    'received' => $received,
                    'lost' => $lost,
                    'packet_loss' => $packet_loss,
                    'avg_time' => $avg_time
                ];
            }
            
            if (preg_match('/time[=<](\d+)ms/', $output, $matches)) {
                $avg_time = (int)$matches[1];
                return [
                    'success' => true,
                    'sent' => 1,
                    'received' => 1,
                    'lost' => 0,
                    'packet_loss' => 0,
                    'avg_time' => $avg_time
                ];
            }
            
            if (preg_match('/Reply from ([^:]+): time=(\d+)ms/', $output, $matches)) {
                $avg_time = (int)$matches[2];
                return [
                    'success' => true,
                    'sent' => 1,
                    'received' => 1,
                    'lost' => 0,
                    'packet_loss' => 0,
                    'avg_time' => $avg_time
                ];
            }
        } else {
            if (preg_match('/(\d+) packets transmitted, (\d+) received/', $output, $matches)) {
                $sent = (int)$matches[1];
                $received = (int)$matches[2];
                $lost = $sent - $received;
                $packet_loss = $sent > 0 ? round(($lost / $sent) * 100, 2) : 100;
                preg_match('/rtt min\/avg\/max\/mdev = [\d.+\/]+ = ([\d.]+)ms/', $output, $time_matches);
                $avg_time = isset($time_matches[1]) ? (float)$time_matches[1] : 0;
                return [
                    'success' => $received > 0,
                    'sent' => $sent,
                    'received' => $received,
                    'lost' => $lost,
                    'packet_loss' => $packet_loss,
                    'avg_time' => $avg_time
                ];
            }
        }
        
        return [
            'success' => false,
            'sent' => 0,
            'received' => 0,
            'lost' => 0,
            'packet_loss' => 100,
            'avg_time' => 0
        ];
    }
    
    /**
     * DNS проверка
     */
    private function checkDNS($host, $ip_info) {
        $config = getCheckConfig('dns');
        $results = [];
        
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            foreach ($config['types'] as $type) {
                $results[$type] = [
                    'host' => $host,
                    'ip' => $host,
                    'ip_info' => $ip_info,
                    'status' => 'warning',
                    'explanation' => "DNS запросы не выполняются для IP адресов",
                    'response_time' => 0,
                    'count' => 0,
                    'formatted_records' => [],
                    'location' => $this->location_config['name'],
                    'timestamp' => date('Y-m-d H:i:s')
                ];
            }
            return $results;
        }
        
        foreach ($config['types'] as $type) {
            $start_time = microtime(true);
            
            $records = @dns_get_record($host, $this->getDNSConstant($type));
            $end_time = microtime(true);
            
            $response_time = round(($end_time - $start_time) * 1000, 2);
            
            if ($records === false) {
                $records = [];
            }
            
            $status = 'success';
            $explanation = '';
            
            if (empty($records)) {
                $status = 'warning';
                $explanation = "DNS записи типа $type не найдены";
            } else {
                $status = 'success';
                $explanation = "Найдено " . count($records) . " записей типа $type";
            }
            
            $formatted_records = [];
            foreach ($records as $record) {
                $formatted_records[] = [
                    'type' => $type,
                    'value' => $this->formatDNSRecord($record, $type)
                ];
            }
            
            $results[$type] = [
                'host' => $host,
                'ip' => $ip_info['ip'],
                'ip_info' => $ip_info,
                'status' => $status,
                'explanation' => $explanation,
                'response_time' => $response_time,
                'count' => count($records),
                'formatted_records' => $formatted_records,
                'location' => $this->location_config['name'],
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }
        
        return $results;
    }
    
    /**
     * Получение DNS константы
     */
    private function getDNSConstant($type) {
        $constants = [
            'A' => DNS_A,
            'AAAA' => DNS_AAAA,
            'MX' => DNS_MX,
            'NS' => DNS_NS,
            'TXT' => DNS_TXT,
            'CNAME' => DNS_CNAME,
            'PTR' => DNS_PTR,
            'SOA' => DNS_SOA
        ];
        
        return isset($constants[$type]) ? $constants[$type] : DNS_ANY;
    }
    
    /**
     * Форматирование DNS записи для отображения
     */
    private function formatDNSRecord($record, $type) {
        switch ($type) {
            case 'A':
                return $record['ip'] ?? 'N/A';
                
            case 'AAAA':
                return $record['ipv6'] ?? 'N/A';
                
            case 'MX':
                $priority = $record['pri'] ?? '';
                $target = $record['target'] ?? 'N/A';
                return "Приоритет: $priority, Цель: $target";
                
            case 'NS':
                return $record['target'] ?? 'N/A';
                
            case 'TXT':
                return $record['txt'] ?? 'N/A';
                
            case 'CNAME':
                return $record['target'] ?? 'N/A';
                
            case 'SOA':
                $mname = $record['mname'] ?? 'N/A';
                $rname = $record['rname'] ?? 'N/A';
                $serial = $record['serial'] ?? 'N/A';
                $refresh = $record['refresh'] ?? 'N/A';
                $retry = $record['retry'] ?? 'N/A';
                $expire = $record['expire'] ?? 'N/A';
                $minimum_ttl = $record['minimum-ttl'] ?? 'N/A';
                return "MNAME: $mname, RNAME: $rname, Serial: $serial, Refresh: $refresh, Retry: $retry, Expire: $expire, TTL: $minimum_ttl";
                
            default:
                return json_encode($record, JSON_UNESCAPED_UNICODE);
        }
    }
    
    /**
     * Traceroute проверка
     */
    private function checkTraceroute($host, $ip, $ip_info) {
        $config = getCheckConfig('traceroute');
        
        if (PHP_OS_FAMILY === 'Windows') {
            $traceroute_cmd = "tracert -h " . min($config['max_hops'], 10) . " -w " . ($config['timeout'] * 1000) . " -d $host";
        } else {
            $traceroute_cmd = "traceroute -m {$config['max_hops']} -w {$config['timeout']} $host";
        }
        
        $start_time = microtime(true);
        
        if (PHP_OS_FAMILY === 'Windows') {
            $output = shell_exec($traceroute_cmd . ' 2>&1');
        } else {
            exec($traceroute_cmd . ' 2>&1', $output_array, $return_var);
            $output = implode("\n", $output_array);
        }
        
        $end_time = microtime(true);
        $response_time = round(($end_time - $start_time) * 1000, 2);
        $hops = $this->parseTracerouteOutput($output);
        $status = 'success';
        $explanation = '';
        if (empty($hops)) {
            $status = 'error';
            $explanation = "Не удалось определить маршрут";
        } elseif (count($hops) < 3) {
            $status = 'warning';
            $explanation = "Короткий маршрут: " . count($hops) . " хопов";
        } else {
            $status = 'success';
            $explanation = "Маршрут определен: " . count($hops) . " хопов";
        }
        return [
            'host' => $host,
            'ip' => $ip,
            'ip_info' => $ip_info,
            'status' => $status,
            'explanation' => $explanation,
            'response_time' => $response_time,
            'hops' => $hops,
            'hop_count' => count($hops),
            'raw_output' => substr($output, 0, 500),
            'location' => $this->location_config['name'],
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
    
    /**
     * Парсинг вывода traceroute
     */
    private function parseTracerouteOutput($output) {
        $hops = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            
            if (PHP_OS_FAMILY === 'Windows') {
                if (preg_match('/^\s*(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\d+)\s+ms\s+([^\s]+)/', $line, $matches)) {
                    $hops[] = [
                        'hop' => (int)$matches[1],
                        'ip' => $matches[5],
                        'times' => [(int)$matches[2], (int)$matches[3], (int)$matches[4]]
                    ];
                }
            } else {
                if (preg_match('/^\s*(\d+)\s+([^\s]+)\s+\(([^)]+)\)\s+([\d.]+)\s+ms/', $line, $matches)) {
                    $hops[] = [
                        'hop' => (int)$matches[1],
                        'hostname' => $matches[2],
                        'ip' => $matches[3],
                        'time' => (float)$matches[4]
                    ];
                }
            }
        }
        return $hops;
    }
    
    /**
     * Форматирование результатов
     */
    private function formatResults($ip_info) {
        $formatted = [
            'location' => $this->location_config['name'],
            'country' => $this->location_config['country'],
            'city' => $this->location_config['city'],
            'timezone' => $this->location_config['timezone'],
            'isp' => $this->location_config['isp_info']['name'],
            'target_info' => [
                'ip' => $ip_info['ip'],
                'country' => $ip_info['country'],
                'city' => $ip_info['city'],
                'region' => $ip_info['region'],
                'isp' => $ip_info['isp'],
                'org' => $ip_info['org'],
                'timezone' => $ip_info['timezone'],
                'asn' => $ip_info['asn'] ?? 'Unknown',
                'mobile' => $ip_info['mobile'] ?? false,
                'proxy' => $ip_info['proxy'] ?? false,
                'hosting' => $ip_info['hosting'] ?? false,
                'coordinates' => [
                    'lat' => $ip_info['latitude'],
                    'lon' => $ip_info['longitude']
                ]
            ],
            'timestamp' => date('Y-m-d H:i:s'),
            'results' => $this->results
        ];
        
        return $formatted;
    }
}



/**
 * Функция для отправки HTTP ответа
 */
function sendJSONResponse($data, $status_code = 200) {
    http_response_code($status_code);
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

/**
 * Функция для валидации входных данных
 */
function validateInput($data) {
    $errors = [];
    
    if (empty($data['host'])) {
        $errors[] = 'Хост не указан';
    }
    
    if (empty($data['check_types']) || !is_array($data['check_types'])) {
        $errors[] = 'Типы проверок не указаны';
    }
    
    return $errors;
}
?> 