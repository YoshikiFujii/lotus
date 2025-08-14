<?php
declare(strict_types=1);
require __DIR__ . '/../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

$method = $_SERVER['REQUEST_METHOD'];
$path   = strtok($_SERVER['REQUEST_URI'], '?'); // /api/orders など

function json($data, int $code=200) {
  http_response_code($code);
  echo json_encode($data, JSON_UNESCAPED_UNICODE);
  exit;
}

try {
  // 1) 待ち一覧（Cook/Caller用）
  if ($method === 'GET' && $path === '/api/orders/waiting') {
    $shopId = isset($_GET['shop_id']) ? (int)$_GET['shop_id'] : 0;
    if ($shopId <= 0) json(['error'=>'shop_id required'], 400);

    $sql = "SELECT o.id, o.ticket_number, o.status, o.created_at,
              COALESCE(SUM(oi.unit_price_cents * oi.qty),0) AS amount_cents
            FROM orders o
            LEFT JOIN order_items oi ON oi.order_id=o.id
            WHERE o.shop_id=? AND o.status IN ('RECEIVED','PREPARING','READY','CALLED')
            GROUP BY o.id, o.ticket_number, o.status, o.created_at
            ORDER BY o.created_at ASC";
    $st = db()->prepare($sql);
    $st->execute([$shopId]);
    json(['items'=>$st->fetchAll()]);
  }

  // 2) 注文作成（Casher用）
  if ($method === 'POST' && $path === '/api/orders') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $shopId = (int)($input['shop_id'] ?? 0);
    $items  = $input['items'] ?? []; // [{product_id, name, unit_price_cents, qty}, ...]

    if ($shopId<=0 || !is_array($items) || count($items)===0) {
      json(['error'=>'invalid payload'], 400);
    }

    $pdo = db();
    $pdo->beginTransaction();
    try {
      // 発番（queue_counters）※同一トランザクション内
      $biz = (new DateTime('now', new DateTimeZone('Asia/Tokyo')))->format('Y-m-d');
      $pdo->prepare("INSERT IGNORE INTO queue_counters (shop_id,business_date,last_number) VALUES (?,?,0)")
          ->execute([$shopId, $biz]);
      $pdo->prepare("UPDATE queue_counters SET last_number = LAST_INSERT_ID(last_number+1)
                     WHERE shop_id=? AND business_date=?")->execute([$shopId, $biz]);
      $ticket = (int)$pdo->query("SELECT LAST_INSERT_ID() AS n")->fetch()['n'];

      // 注文ヘッダ
      $pdo->prepare("INSERT INTO orders (shop_id, customer_session_id, ticket_number, business_date, status, total_cents, created_at, updated_at)
                     VALUES (?, NULL, ?, ?, 'RECEIVED', 0, NOW(), NOW())")
          ->execute([$shopId, $ticket, $biz]);
      $orderId = (int)$pdo->lastInsertId();

      // 明細＆合計
      $sum = 0;
      $ins = $pdo->prepare("INSERT INTO order_items (order_id, product_id, product_name_snap, unit_price_cents, qty)
                            VALUES (?, ?, ?, ?, ?)");
      foreach ($items as $it) {
        $pid = isset($it['product_id']) ? (int)$it['product_id'] : null;
        $nm  = (string)($it['name'] ?? '');
        $pr  = (int)($it['unit_price_cents'] ?? 0);
        $qt  = (int)($it['qty'] ?? 0);
        if ($nm==='' || $pr<=0 || $qt<=0) throw new RuntimeException('invalid item');
        $sum += $pr * $qt;
        $ins->execute([$orderId, $pid, $nm, $pr, $qt]);
      }
      $pdo->prepare("UPDATE orders SET total_cents=? WHERE id=?")->execute([$sum, $orderId]);

      // イベントログ
      $pdo->prepare("INSERT INTO order_events (order_id, event_type, to_status) VALUES (?, 'CREATED', 'RECEIVED')")
          ->execute([$orderId]);

      $pdo->commit();
      json(['order_id'=>$orderId, 'ticket_number'=>$ticket, 'total_cents'=>$sum], 201);
    } catch (Throwable $e) {
      $pdo->rollBack();
      json(['error'=>$e->getMessage()], 500);
    }
  }

  // 3) 状態更新（Cook/Caller用）
  if ($method === 'PATCH' && preg_match('#^/api/orders/(\d+)/status$#', $path, $m)) {
    $orderId = (int)$m[1];
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $to = (string)($input['to'] ?? '');
    $allowed = ['RECEIVED','PREPARING','READY','CALLED','DELIVERED','CANCELLED'];
    if (!in_array($to, $allowed, true)) json(['error'=>'invalid status'], 400);

    $pdo = db(); $pdo->beginTransaction();
    try {
      $curr = $pdo->prepare("SELECT status FROM orders WHERE id=? FOR UPDATE");
      $curr->execute([$orderId]);
      $row = $curr->fetch();
      if (!$row) json(['error'=>'not found'], 404);
      $from = $row['status'];

      $pdo->prepare("UPDATE orders SET status=?, updated_at=NOW(),
                      called_at = IF(?='CALLED', NOW(), called_at),
                      completed_at = IF(?='DELIVERED', NOW(), completed_at),
                      cancelled_at = IF(?='CANCELLED', NOW(), cancelled_at)
                    WHERE id=?")
          ->execute([$to, $to, $to, $to, $orderId]);

      $pdo->prepare("INSERT INTO order_events (order_id, event_type, from_status, to_status) VALUES (?,?,?,?)")
          ->execute([$orderId, 'STATUS_CHANGED', $from, $to]);

      $pdo->commit();
      json(['ok'=>true, 'from'=>$from, 'to'=>$to]);
    } catch (Throwable $e) {
      $pdo->rollBack();
      json(['error'=>$e->getMessage()], 500);
    }
  }
  // 商品一覧（Casher用）
  if ($method === 'GET' && $path === '/api/products') {
    $shopId = isset($_GET['shop_id']) ? (int)$_GET['shop_id'] : 0;
    if ($shopId <= 0) json(['error'=>'shop_id required'], 400);
    $sql = "SELECT id, name, price_cents
              FROM products
             WHERE shop_id=? AND is_active=1
             ORDER BY sort_order ASC, id ASC";
    $st = db()->prepare($sql);
    $st->execute([$shopId]);
    json(['items'=>$st->fetchAll()]);
  }

  // 1) 客セッション新規発行（CasherがQRを出すため）
  if ($method === 'POST' && $path === '/api/customer/session') {
    $pub = bin2hex(random_bytes(16));   // public_token
    $ck  = bin2hex(random_bytes(16));   // cookie_token
    $pdo = db();
    $pdo->prepare("INSERT INTO customer_sessions (public_token, cookie_token, created_at) VALUES (?, ?, NOW())")
        ->execute([$pub, $ck]);

    // 客が読み取るURL（同一オリジンで /customer.html?t=public_token）
    $base = getenv('APP_URL') ?: ('http://' . $_SERVER['HTTP_HOST']);
    $url  = rtrim($base, '/') . '/customer.html?t=' . $pub;

    json(['public_token'=>$pub, 'cookie_token'=>$ck, 'url'=>$url], 201);
  }

  // 2) 注文と客セッションの紐づけ（Casher側で注文直後に呼ぶ）
  if ($method === 'POST' && $path === '/api/customer/link') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $orderId = (int)($input['order_id'] ?? 0);
    $public  = (string)($input['public_token'] ?? '');
    if ($orderId<=0 || $public==='') json(['error'=>'order_id and public_token required'], 400);

    $pdo = db();
    $st = $pdo->prepare("SELECT id FROM customer_sessions WHERE public_token=?");
    $st->execute([$public]);
    $sess = $st->fetch();
    if (!$sess) json(['error'=>'session not found'], 404);

    $pdo->prepare("UPDATE orders SET customer_session_id=? WHERE id=?")->execute([(int)$sess['id'], $orderId]);
    json(['ok'=>true]);
  }

  // 3) 客の待ち一覧（cookie_token でひも付く未完了注文を返す）
  if ($method === 'GET' && $path === '/api/customer/orders') {
    $cookie = (string)($_GET['cookie_token'] ?? '');
    if ($cookie==='') json(['error'=>'cookie_token required'], 400);

    $pdo = db();
    $st = $pdo->prepare("
      SELECT o.id, o.shop_id, o.ticket_number, o.status, o.created_at
        FROM orders o
        JOIN customer_sessions cs ON cs.id = o.customer_session_id
      WHERE cs.cookie_token = ?
        AND o.status IN ('RECEIVED','PREPARING','READY','CALLED')
      ORDER BY o.created_at DESC
    ");
    $st->execute([$cookie]);
    json(['items'=>$st->fetchAll()]);
  }
  // public_token を cookie_token に交換
  if ($method === 'GET' && $path === '/api/customer/redeem') {
    $public = (string)($_GET['public_token'] ?? '');
    if ($public === '') json(['error'=>'public_token required'], 400);

    $st = db()->prepare('SELECT cookie_token FROM customer_sessions WHERE public_token=?');
    $st->execute([$public]);
    $row = $st->fetch();
    if (!$row) json(['error'=>'not found'], 404);

    // キャッシュさせない
    header('Cache-Control: no-store');
    json(['cookie_token' => $row['cookie_token']]);
  }

  // 未定義
  json(['error'=>'not found', 'path'=>$path], 404);

} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['error'=>$e->getMessage()]);
}
