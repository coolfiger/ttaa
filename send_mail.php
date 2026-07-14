<?php
/**
 * TTAA Contact Form Mailer
 * Uses SMTP2GO via PHPMailer (via Composer or manual include)
 * Place this file in the same directory as your HTML file on the server.
 */

// ─── Rate limiting (file-based, no DB required) ───────────────────────────
define('RATE_LIMIT_DIR',  sys_get_temp_dir() . '/ttaa_rl/');
define('RATE_LIMIT_MAX',  5);    // max submissions
define('RATE_LIMIT_WIN',  600);  // per 10 minutes, per IP

function check_rate_limit(string $ip): bool {
    if (!is_dir(RATE_LIMIT_DIR)) mkdir(RATE_LIMIT_DIR, 0700, true);
    $file = RATE_LIMIT_DIR . md5($ip) . '.json';
    $now  = time();
    $data = file_exists($file) ? json_decode(file_get_contents($file), true) : ['hits' => [], 'blocked_until' => 0];

    if ($now < ($data['blocked_until'] ?? 0)) return false;

    // purge old hits outside the window
    $data['hits'] = array_filter($data['hits'], fn($t) => ($now - $t) < RATE_LIMIT_WIN);

    if (count($data['hits']) >= RATE_LIMIT_MAX) {
        $data['blocked_until'] = $now + 1800; // block for 30 min after breach
        file_put_contents($file, json_encode($data), LOCK_EX);
        return false;
    }

    $data['hits'][] = $now;
    file_put_contents($file, json_encode($data), LOCK_EX);
    return true;
}

// ─── Config ───────────────────────────────────────────────────────────────
$RECAPTCHA_SECRET = '6LcriRstAAAAAKLIo47itXhbmdd7GlhQ1hUwzvuO';
$SMTP_HOST        = 'mail.smtp2go.com';
$SMTP_PORT        = 2525;
$SMTP_USER        = 'ttaa';
$SMTP_PASS        = 'sPVNa7QT1MsEiwHH';
$MAIL_FROM        = 'info@ttaa.co.tt';
$MAIL_FROM_NAME   = 'TTAA Website';
$MAIL_TO          = 'info@ttaa.co.tt';
$MAIL_TO_NAME     = 'Trinidad & Tobago Automobile Association';

// ─── CORS / method guard ───────────────────────────────────────────────────
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['success' => false, 'message' => 'Method not allowed.']));
}

// ─── Honeypot check ───────────────────────────────────────────────────────
if (!empty($_POST['website'])) {
    // Silent success to bots
    exit(json_encode(['success' => true]));
}

// ─── Rate limit ───────────────────────────────────────────────────────────
$ip = $_SERVER['HTTP_CF_CONNECTING_IP']
   ?? $_SERVER['HTTP_X_FORWARDED_FOR']
   ?? $_SERVER['REMOTE_ADDR']
   ?? '0.0.0.0';
$ip = filter_var(explode(',', $ip)[0], FILTER_VALIDATE_IP) ?: '0.0.0.0';

if (!check_rate_limit($ip)) {
    http_response_code(429);
    exit(json_encode(['success' => false, 'message' => 'Too many submissions. Please try again later.']));
}

// ─── reCAPTCHA v3 verification ────────────────────────────────────────────
$captcha_token = trim($_POST['g-recaptcha-response'] ?? '');
if (empty($captcha_token)) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'CAPTCHA verification failed.']));
}

$rc = json_decode(file_get_contents(
    'https://www.google.com/recaptcha/api/siteverify?secret='
    . urlencode($RECAPTCHA_SECRET)
    . '&response=' . urlencode($captcha_token)
    . '&remoteip=' . urlencode($ip)
), true);

if (empty($rc['success']) || ($rc['score'] ?? 0) < 0.5) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'CAPTCHA score too low. Please try again.']));
}

// ─── Input sanitisation ───────────────────────────────────────────────────
function clean(string $val): string {
    return htmlspecialchars(strip_tags(trim($val)), ENT_QUOTES, 'UTF-8');
}

$first   = clean($_POST['first_name']   ?? '');
$last    = clean($_POST['last_name']    ?? '');
$email   = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
$phone   = clean($_POST['phone']        ?? '');
$subject = clean($_POST['interest']     ?? 'General Enquiry');
$message = clean($_POST['message']      ?? '');

if (!$first || !$last || !$email || !$message) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Please fill in all required fields.']));
}

if (strlen($message) > 3000) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'message' => 'Message exceeds maximum length.']));
}

// ─── Build email body ─────────────────────────────────────────────────────
$body_html = "
<div style='font-family:Arial,sans-serif;max-width:600px;margin:0 auto'>
  <div style='background:#030e2e;padding:24px 32px;border-radius:6px 6px 0 0'>
    <h2 style='color:#2dd4fa;margin:0;font-size:20px;text-transform:uppercase;letter-spacing:.05em'>
      New Contact Form Submission
    </h2>
  </div>
  <div style='background:#f9f9f9;padding:24px 32px;border:1px solid #e0e0e0;border-top:none'>
    <table style='width:100%;border-collapse:collapse;font-size:14px'>
      <tr><td style='padding:8px 0;color:#555;width:130px;vertical-align:top'><strong>Name</strong></td><td style='padding:8px 0;color:#222'>{$first} {$last}</td></tr>
      <tr><td style='padding:8px 0;color:#555;vertical-align:top'><strong>Email</strong></td><td style='padding:8px 0'><a href='mailto:{$email}' style='color:#1745c4'>{$email}</a></td></tr>
      <tr><td style='padding:8px 0;color:#555;vertical-align:top'><strong>Phone</strong></td><td style='padding:8px 0;color:#222'>" . ($phone ?: '—') . "</td></tr>
      <tr><td style='padding:8px 0;color:#555;vertical-align:top'><strong>Enquiry</strong></td><td style='padding:8px 0;color:#222'>{$subject}</td></tr>
      <tr><td style='padding:8px 0;color:#555;vertical-align:top'><strong>Message</strong></td><td style='padding:8px 0;color:#222;white-space:pre-wrap'>{$message}</td></tr>
      <tr><td style='padding:8px 0;color:#555;vertical-align:top'><strong>IP</strong></td><td style='padding:8px 0;color:#aaa;font-size:12px'>{$ip}</td></tr>
    </table>
  </div>
  <div style='background:#e8ecf4;padding:12px 32px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 6px 6px;font-size:11px;color:#888'>
    Sent via TTAA website contact form · ttaa.co.tt
  </div>
</div>";

$body_text = "New TTAA Contact Form Submission\n\n"
    . "Name: {$first} {$last}\n"
    . "Email: {$email}\n"
    . "Phone: " . ($phone ?: '—') . "\n"
    . "Enquiry: {$subject}\n"
    . "Message:\n{$message}\n\n"
    . "IP: {$ip}";

// ─── Send via SMTP2GO (raw SMTP, no library dependency) ───────────────────
function smtp_send(array $cfg): bool {
    $sock = @fsockopen($cfg['host'], $cfg['port'], $errno, $errstr, 10);
    if (!$sock) return false;

    $read = fn() => fgets($sock, 512);
    $send = function(string $cmd) use ($sock, $read) {
        fwrite($sock, $cmd . "\r\n");
        return $read();
    };

    $read(); // 220 banner

    // EHLO
    $send('EHLO ttaa.co.tt');
    // read multi-line EHLO
    while (true) { $l = $read(); if ($l === false || substr($l,3,1) === ' ') break; }

    // STARTTLS
    $send('STARTTLS');
    $read();
    stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);

    // re-EHLO after TLS
    $send('EHLO ttaa.co.tt');
    while (true) { $l = $read(); if ($l === false || substr($l,3,1) === ' ') break; }

    // AUTH LOGIN
    $send('AUTH LOGIN');
    $read();
    $send(base64_encode($cfg['user']));
    $read();
    $resp = $send(base64_encode($cfg['pass']));
    if (strpos($resp, '235') === false) { fclose($sock); return false; }

    $send('MAIL FROM:<' . $cfg['from'] . '>');  $read();
    $send('RCPT TO:<'   . $cfg['to']   . '>');  $read();
    $send('DATA');
    $read();

    $boundary = md5(uniqid('', true));
    $headers  = implode("\r\n", [
        'From: '                        . $cfg['from_name'] . ' <' . $cfg['from'] . '>',
        'To: '                          . $cfg['to_name']   . ' <' . $cfg['to']   . '>',
        'Reply-To: '                    . $cfg['reply_to'],
        'Subject: '                     . '=?UTF-8?B?' . base64_encode($cfg['subject']) . '?=',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        'X-Mailer: TTAA-Mailer/1.0',
    ]);

    $body = "--{$boundary}\r\n"
          . "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
          . $cfg['body_text'] . "\r\n\r\n"
          . "--{$boundary}\r\n"
          . "Content-Type: text/html; charset=UTF-8\r\n\r\n"
          . $cfg['body_html'] . "\r\n\r\n"
          . "--{$boundary}--";

    fwrite($sock, $headers . "\r\n\r\n" . $body . "\r\n.\r\n");
    $resp = $read();
    $send('QUIT');
    fclose($sock);

    return strpos($resp, '250') !== false;
}

$sent = smtp_send([
    'host'       => $SMTP_HOST,
    'port'       => $SMTP_PORT,
    'user'       => $SMTP_USER,
    'pass'       => $SMTP_PASS,
    'from'       => $MAIL_FROM,
    'from_name'  => $MAIL_FROM_NAME,
    'to'         => $MAIL_TO,
    'to_name'    => $MAIL_TO_NAME,
    'reply_to'   => $email,
    'subject'    => 'TTAA Enquiry: ' . $subject . ' — ' . $first . ' ' . $last,
    'body_html'  => $body_html,
    'body_text'  => $body_text,
]);

if ($sent) {
    exit(json_encode(['success' => true, 'message' => 'Thank you. We will be in touch shortly.']));
} else {
    http_response_code(500);
    exit(json_encode(['success' => false, 'message' => 'Mail delivery failed. Please call us directly or email info@ttaa.co.tt.']));
}
