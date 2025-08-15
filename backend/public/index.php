<?php
declare(strict_types=1);

/**
 * backend/public/index.php （完全版）
 * - JWTログイン / 認可（org + shops）
 * - プロダクト取得 / 注文作成 / 待ち一覧 / 状態更新
 * - 客用API（session/link/redeem/orders）
 *
 * 依存:
 *  - backend/config/database.php  … PDO接続の db() 関数
 *  - backend/config/auth.php      … JWTの issueToken()/requireAuth()
 *  - vendor/autoload.php          … firebase/php-jwt（Composer）
 */

require __DIR__ . '/../config/database.php';
require __DIR__ . '/../config/auth.php';
$vendor = __DIR__ . '/../vendor/autoload.php';
if (is_file($vendor)) require $vendor;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');

// ---- 小ユーティリティ ----
function json($data, int $code = 200): void {
  http_response_code($code);
  echo json_encode($data, JSON_UNESCAPED_UNICODE);
  exit;
}
function bad(string $msg, int $code = 400): void { json(['error' => $msg], $code); }

// リクエストごとのユーザー文脈（JWTをdecode）
function ctx(): array {
  static $c = null;
  if ($c) return $c;
  $c = requireAuth(); // auth.php
  $c['org']   = (int)($c['org'] ?? 0);
  $c['shops'] = array_map('intval', $c['shops'] ?? []);
  return $c;
}
// このユーザーが shopId にアクセス可能かを確認
function assertShopAllowed(int $shopId): void {
  if ($shopId <= 0) bad('shop_id required', 400);
  $c = ctx();
  if (!in_array($shopId, $c['shops'], true)) bad('forbidden shop', 403);
}

// ---- ルーティング ----
try {

  // 簡易ヘルス（任意）
  if ($method === 'GET' && $path === '/api/health') {
    try {
      $ok = db()->query('SELECT 1 AS ok')->fetch()['ok'] ?? 0;
      json(['app' => 'lotus', 'db' => $ok ? 'ok' : 'ng', 'time' => date('c')]);
    } catch (Throwable $e) { bad($e->getMessage(), 500); }
  }

  // =========================
  // 認証系
  // =========================

  // ログイン: email + password → JWT発行（org と shops を詰める）
  if ($method === 'POST' && $path === '/api/login') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $email = (string)($in['email'] ?? '');
    $pass  = (string)($in['password'] ?? '');
    if ($email === '' || $pass === '') bad('email and password required', 400);

    $st = db()->prepare("SELECT id, organization_id, password_hash FROM users WHERE email=? AND is_active=1");
    $st->execute([$email]);
    $u = $st->fetch();
    if (!$u || !password_verify($pass, $u['password_hash'])) bad('invalid credentials', 401);

    // ユーザーがアクセス可能な店舗ID一覧（Managerなら全店）
    $sql = "
      SELECT s.id
        FROM shops s
        LEFT JOIN user_shop_roles r
          ON r.shop_id = s.id AND r.user_id = ?
       WHERE s.organization_id = ?
         AND (r.user_id IS NOT NULL OR EXISTS(
               SELECT 1 FROM user_shop_roles m
                WHERE m.user_id=? AND m.role_key='MANAGER' AND m.shop_id IS NULL
             ))
    ";
    $ps = db()->prepare($sql);
    $ps->execute([(int)$u['id'], (int)$u['organization_id'], (int)$u['id']]);
    $allowedShopIds = array_map(fn($row) => (int)$row['id'], $ps->fetchAll());

    $token = issueToken([
      'sub'   => (int)$u['id'],
      'org'   => (int)$u['organization_id'],
      'shops' => $allowedShopIds,
    ], 3600);

    json(['token' => $token, 'shops' => $allowedShopIds]);
  }

  // =========================
  // 従業員用API（要ログイン）
  // =========================

  // 商品一覧（ショップに紐づく／org二重チェック）
  if ($method === 'GET' && $path === '/api/products') {
    $shopId = (int)($_GET['shop_id'] ?? 0);
    $c = ctx();
    assertShopAllowed($shopId);

    $sql = "SELECT p.id, p.name, p.price_cents
              FROM products p
              JOIN shops s ON s.id = p.shop_id
             WHERE p.shop_id = ? AND p.is_active = 1 AND s.organization_id = ?";
    $st = db()->prepare($sql);
    $st->execute([$shopId, $c['org']]);
    json(['items' => $st->fetchAll()]);
  }

  // 注文作成（発番→orders / order_items / order_events）+ org二重チェック
  if ($method === 'POST' && $path === '/api/orders') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $shopId = (int)($in['shop_id'] ?? 0);
    $items  = $in['items'] ?? [];
    $c = ctx();
    assertShopAllowed($shopId);

    if (!is_array($items) || count($items) === 0) bad('items required', 400);

    $pdo = db();
    $pdo->beginTransaction();
    try {
      // 営業日
      $biz = (new DateTime('now', new DateTimeZone('Asia/Tokyo')))->format('Y-m-d');

      // 発番行（初回用にINSERT IGNORE）
      $pdo->prepare("INSERT IGNORE INTO queue_counters (shop_id, business_date, last_number) VALUES (?, ?, 0)")
          ->execute([$shopId, $biz]);
      $pdo->prepare("UPDATE queue_counters SET last_number = LAST_INSERT_ID(last_number + 1)
                      WHERE shop_id = ? AND business_date = ?")
          ->execute([$shopId, $biz]);
      $ticket = (int)$pdo->query("SELECT LAST_INSERT_ID() AS n")->fetch()['n'];

      // org二重チェック
      $chk = $pdo->prepare("SELECT 1 FROM shops WHERE id=? AND organization_id=?");
      $chk->execute([$shopId, $c['org']]);
      if (!$chk->fetch()) throw new RuntimeException('shop/org mismatch');

      // 注文ヘッダ
      $pdo->prepare("INSERT INTO orders
                      (shop_id, customer_session_id, ticket_number, business_date, status, total_cents, created_at, updated_at)
                     VALUES
                      (?, NULL, ?, ?, 'RECEIVED', 0, NOW(), NOW())")
          ->execute([$shopId, $ticket, $biz]);
      $orderId = (int)$pdo->lastInsertId();

      // 明細 & 合計
      $sum = 0;
      $ins = $pdo->prepare("INSERT INTO order_items
                              (order_id, product_id, product_name_snap, unit_price_cents, qty)
                            VALUES
                              (?, ?, ?, ?, ?)");
      foreach ($items as $it) {
        $pid = isset($it['product_id']) ? (int)$it['product_id'] : null;
        $nm  = (string)($it['name'] ?? '');
        $pr  = (int)($it['unit_price_cents'] ?? 0);
        $qt  = (int)($it['qty'] ?? 0);
        if ($nm === '' || $pr <= 0 || $qt <= 0) throw new RuntimeException('invalid item');
        $sum += $pr * $qt;
        $ins->execute([$orderId, $pid, $nm, $pr, $qt]);
      }
      $pdo->prepare("UPDATE orders SET total_cents = ? WHERE id = ?")->execute([$sum, $orderId]);

      // イベント
      $pdo->prepare("INSERT INTO order_events (order_id, event_type, to_status)
                     VALUES (?, 'CREATED', 'RECEIVED')")
          ->execute([$orderId]);

      $pdo->commit();
      json(['order_id' => $orderId, 'ticket_number' => $ticket, 'total_cents' => $sum], 201);
    } catch (Throwable $e) {
      $pdo->rollBack();
      bad($e->getMessage(), 500);
    }
  }

  // 待ち一覧（RECEIVED/PREPARING/READY/CALLED）+ org二重チェック
  if ($method === 'GET' && $path === '/api/orders/waiting') {
    $shopId = (int)($_GET['shop_id'] ?? 0);
    $c = ctx();
    assertShopAllowed($shopId);

    $sql = "SELECT o.id, o.ticket_number, o.status, o.created_at,
                   COALESCE(SUM(oi.unit_price_cents * oi.qty), 0) AS amount_cents
              FROM orders o
              JOIN shops s ON s.id = o.shop_id
         LEFT JOIN order_items oi ON oi.order_id = o.id
             WHERE o.shop_id = ? AND s.organization_id = ?
               AND o.status IN ('RECEIVED','PREPARING','READY','CALLED')
          GROUP BY o.id, o.ticket_number, o.status, o.created_at
          ORDER BY o.created_at ASC";
    $st = db()->prepare($sql);
    $st->execute([$shopId, $c['org']]);
    json(['items' => $st->fetchAll()]);
  }

  // 状態更新（Cook/Caller）+ org二重チェック
  if ($method === 'PATCH' && preg_match('#^/api/orders/(\d+)/status$#', $path, $m)) {
    $orderId = (int)$m[1];
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $to = (string)($in['to'] ?? '');
    $allowed = ['RECEIVED','PREPARING','READY','CALLED','DELIVERED','CANCELLED'];
    if (!in_array($to, $allowed, true)) bad('invalid status', 400);

    $c = ctx();
    $pdo = db();
    $pdo->beginTransaction();
    try {
      // 対象注文が自組織のものか（shops経由でチェック）
      $lock = $pdo->prepare("
        SELECT o.status
          FROM orders o
          JOIN shops s ON s.id = o.shop_id
         WHERE o.id = ? AND s.organization_id = ?
         FOR UPDATE");
      $lock->execute([$orderId, $c['org']]);
      $row = $lock->fetch();
      if (!$row) bad('not found', 404);
      $from = $row['status'];

      $pdo->prepare("UPDATE orders
                        SET status = ?, updated_at = NOW(),
                            called_at    = IF(?='CALLED',    NOW(), called_at),
                            completed_at = IF(?='DELIVERED', NOW(), completed_at),
                            cancelled_at = IF(?='CANCELLED', NOW(), cancelled_at)
                      WHERE id = ?")
          ->execute([$to, $to, $to, $to, $orderId]);

      $pdo->prepare("INSERT INTO order_events (order_id, event_type, from_status, to_status)
                     VALUES (?, 'STATUS_CHANGED', ?, ?)")
          ->execute([$orderId, $from, $to]);

      $pdo->commit();
      json(['ok' => true, 'from' => $from, 'to' => $to]);
    } catch (Throwable $e) {
      $pdo->rollBack();
      bad($e->getMessage(), 500);
    }
  }

  // =========================
  // 客用API（ログイン不要）
  // =========================

  // 1) 客セッション発行（QR用URLを返す）
  if ($method === 'POST' && $path === '/api/customer/session') {
    $pub = bin2hex(random_bytes(16)); // public_token
    $ck  = bin2hex(random_bytes(16)); // cookie_token
    $base = getenv('APP_URL') ?: ('http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost'));
    $url  = rtrim($base, '/') . '/customer.html?t=' . $pub;

    $pdo = db();
    $pdo->prepare("INSERT INTO customer_sessions (public_token, cookie_token, created_at) VALUES (?, ?, NOW())")
        ->execute([$pub, $ck]);

    json(['public_token' => $pub, 'cookie_token' => $ck, 'url' => $url], 201);
  }

  // 2) 注文と客セッションを紐付け（Casherが呼ぶ）
  if ($method === 'POST' && $path === '/api/customer/link') {
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    $orderId = (int)($in['order_id'] ?? 0);
    $public  = (string)($in['public_token'] ?? '');
    if ($orderId <= 0 || $public === '') bad('order_id and public_token required', 400);

    $pdo = db();
    $st = $pdo->prepare("SELECT id FROM customer_sessions WHERE public_token = ?");
    $st->execute([$public]);
    $sess = $st->fetch();
    if (!$sess) bad('session not found', 404);

    $pdo->prepare("UPDATE orders SET customer_session_id = ? WHERE id = ?")
        ->execute([(int)$sess['id'], $orderId]);

    json(['ok' => true]);
  }

  // 3) public_token → cookie_token を交換（redeem）
  if ($method === 'GET' && $path === '/api/customer/redeem') {
    $public = (string)($_GET['public_token'] ?? '');
    if ($public === '') bad('public_token required', 400);

    $st = db()->prepare("SELECT cookie_token FROM customer_sessions WHERE public_token = ?");
    $st->execute([$public]);
    $row = $st->fetch();
    if (!$row) bad('not found', 404);

    header('Cache-Control: no-store');
    json(['cookie_token' => $row['cookie_token']]);
  }

  // 4) 客の待ち一覧（cookie_tokenで自分の未完了注文を取得）
  if ($method === 'GET' && $path === '/api/customer/orders') {
    $cookie = (string)($_GET['cookie_token'] ?? '');
    if ($cookie === '') bad('cookie_token required', 400);

    $sql = "
      SELECT o.id, o.shop_id, o.ticket_number, o.status, o.created_at
        FROM orders o
        JOIN customer_sessions cs ON cs.id = o.customer_session_id
       WHERE cs.cookie_token = ?
         AND o.status IN ('RECEIVED','PREPARING','READY','CALLED')
       ORDER BY o.created_at DESC";
    $st = db()->prepare($sql);
    $st->execute([$cookie]);
    header('Cache-Control: no-store');
    json(['items' => $st->fetchAll()]);
  }

  // -------------------------
  // ここまでで未ヒット → 404
  // -------------------------
  json(['error' => 'not found', 'path' => $path], 404);

} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['error' => $e->getMessage()]);
}
