<?php
declare(strict_types=1);

date_default_timezone_set(getenv('TIMEZONE') ?: 'Asia/Tokyo');
header('Content-Type: application/json; charset=utf-8');

echo json_encode([
  'app' => 'lotus',
  'env' => getenv('APP_ENV') ?: 'local',
  'time' => date('c'),
]);
