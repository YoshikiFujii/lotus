<?php
declare(strict_types=1);
require __DIR__ . '/../config/database.php';

header('Content-Type: application/json; charset=utf-8');

try {
  $pdo = db();
  $alive = $pdo->query('SELECT 1 AS ok')->fetch()['ok'] ?? 0;
  echo json_encode([
    'app' => 'lotus',
    'db'  => $alive ? 'ok' : 'ng',
    'time'=> date('c'),
  ]);
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['error' => $e->getMessage()]);
}
