<?php
require_once 'functions.php';

// Установка заголовков для CORS и JSON
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Обработка preflight запросов
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Проверка метода запроса
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendJSONResponse([
        'success' => false,
        'message' => 'Метод не поддерживается. Используйте POST.',
        'error' => 'METHOD_NOT_ALLOWED'
    ], 405);
}

// Получение данных запроса
$input = json_decode(file_get_contents('php://input'), true);

if (!$input) {
    $input = $_POST;
}

// Валидация входных данных
if (empty($input['host'])) {
    sendJSONResponse([
        'success' => false,
        'message' => 'Хост не указан',
        'error' => 'HOST_REQUIRED'
    ], 400);
}

$host = trim($input['host']);

// Получение типов проверок
$check_types = [];
if (isset($input['checkTypes'])) {
    if ($input['checkTypes']['http'] ?? false) $check_types[] = 'http';
    if ($input['checkTypes']['ping'] ?? false) $check_types[] = 'ping';
    if ($input['checkTypes']['dns'] ?? false) $check_types[] = 'dns';
    if ($input['checkTypes']['traceroute'] ?? false) $check_types[] = 'traceroute';
}

// Если типы проверок не указаны, используем все доступные
if (empty($check_types)) {
    $check_types = ['http', 'ping', 'dns'];
}

try {
    // Создание экземпляра проверщика хостов для Хельсинки
    $checker = new HostChecker('finland_helsinki');
    
    // Выполнение проверки
    $results = $checker->checkHost($host, $check_types);
    
    // Форматирование результатов для фронтенда
    $formatted_results = [];
    
    // Обработка HTTP результатов
    if (isset($results['results']['http'])) {
        foreach ($results['results']['http'] as $port => $http_result) {
            $formatted_results[] = [
                'id' => uniqid('http_'),
                'type' => 'http',
                'location' => $http_result['location'],
                'status' => $http_result['status'],
                'explanation' => $http_result['explanation'],
                'responseTime' => $http_result['response_time'],
                'ip' => $http_result['ip'],
                'port' => $port,
                'protocol' => $http_result['protocol'],
                'httpCode' => $http_result['http_code'],
                'timestamp' => $http_result['timestamp']
            ];
        }
    }
    
    // Обработка Ping результатов
    if (isset($results['results']['ping'])) {
        $ping_result = $results['results']['ping'];
        $formatted_results[] = [
            'id' => uniqid('ping_'),
            'type' => 'ping',
            'location' => $ping_result['location'],
            'status' => $ping_result['status'],
            'explanation' => $ping_result['explanation'],
            'responseTime' => $ping_result['response_time'],
            'packetLoss' => $ping_result['ping_stats']['packet_loss'],
            'avgTime' => $ping_result['ping_stats']['avg_time'],
            'sent' => $ping_result['ping_stats']['sent'],
            'received' => $ping_result['ping_stats']['received'],
            'timestamp' => $ping_result['timestamp']
        ];
    }
    
    // Обработка DNS результатов
    if (isset($results['results']['dns'])) {
        foreach ($results['results']['dns'] as $type => $dns_result) {
            $formatted_results[] = [
                'id' => uniqid('dns_'),
                'type' => 'dns',
                'location' => $dns_result['location'],
                'status' => $dns_result['status'],
                'explanation' => $dns_result['explanation'],
                'responseTime' => $dns_result['response_time'],
                'records' => $dns_result['count'] . ' записей типа ' . $type,
                'dnsType' => $type,
                'recordCount' => $dns_result['count'],
                'formattedRecords' => $dns_result['formatted_records'],
                'timestamp' => $dns_result['timestamp']
            ];
        }
    }
    
    // Обработка Traceroute результатов
    if (isset($results['results']['traceroute'])) {
        $traceroute_result = $results['results']['traceroute'];
        $formatted_results[] = [
            'id' => uniqid('traceroute_'),
            'type' => 'traceroute',
            'location' => $traceroute_result['location'],
            'status' => $traceroute_result['status'],
            'explanation' => $traceroute_result['explanation'],
            'responseTime' => $traceroute_result['response_time'],
            'hopCount' => $traceroute_result['hop_count'],
            'hops' => $traceroute_result['hops'],
            'rawOutput' => $traceroute_result['raw_output'] ?? '',
            'timestamp' => $traceroute_result['timestamp']
        ];
    }
    
    // Отправка результата
    sendJSONResponse([
        'success' => true,
        'message' => 'Проверка завершена успешно',
        'data' => [
            'host' => $host,
            'location' => $results['location'],
            'country' => $results['country'],
            'city' => $results['city'],
            'isp' => $results['isp'],
            'target_info' => $results['target_info'],
            'timestamp' => $results['timestamp'],
            'results' => $formatted_results
        ]
    ]);
    
} catch (Exception $e) {
    
    // Отправка ошибки
    sendJSONResponse([
        'success' => false,
        'message' => 'Ошибка при выполнении проверки',
        'error' => 'CHECK_FAILED',
        'details' => $e->getMessage()
    ], 500);
}
?> 