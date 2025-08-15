<?php
declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function jwtKey(): string {
  return getenv('APP_KEY') ?: 'dev-change-me'; // .env の APP_KEY を使うのが本番
}

function issueToken(array $payload, int $ttlSec = 3600): string {
  $now = time();
  $payload = array_merge(['iat'=>$now, 'exp'=>$now+$ttlSec], $payload);
  return JWT::encode($payload, jwtKey(), 'HS256');
}

function requireAuth(): array {
  header('Cache-Control: no-store, no-cache, must-revalidate');
  $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
  if (!preg_match('/^Bearer\s+(.+)$/i', $hdr, $m)) {
    http_response_code(401); echo json_encode(['error'=>'unauthorized']); exit;
  }
  try {
    $data = JWT::decode($m[1], new Key(jwtKey(), 'HS256'));
    return (array)$data;
  } catch (Throwable $e) {
    http_response_code(401); echo json_encode(['error'=>'invalid token']); exit;
  }
}
