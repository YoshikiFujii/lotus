<?php
declare(strict_types=1);

function db(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;

  $host = getenv('DB_HOST') ?: 'db';
  $port = (int)(getenv('DB_PORT') ?: 3306);
  $name = getenv('DB_NAME') ?: 'lotus';
  $user = getenv('DB_USER') ?: 'lotus_user';
  $pass = getenv('DB_PASSWORD') ?: 'lotus_pass';
  $dsn  = "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4";

  $pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
  // タイムゾーン（DBセッション）を固定
  $pdo->exec("SET time_zone = '+09:00'");
  return $pdo;
}