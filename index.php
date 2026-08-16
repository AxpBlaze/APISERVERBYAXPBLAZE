<?php
declare(strict_types=1);
session_start();

/*
 AXP BLAZE - Single-file PHP + SQLite API Key Platform
 Run in Termux:
   pkg install php
   php -S 0.0.0.0:8080
 Open:
   http://127.0.0.1:8080

 Default admin:
   Username: admin
   Password: AXP@Admin123

 IMPORTANT:
 - Passwords are securely hashed. Admin cannot view a user's real password.
 - Admin can reset/change a user's password.
*/

const DB_FILE = __DIR__ . '/axpblaze.sqlite';
const MAX_ACTIVE_KEYS = 5;

$db = new PDO('sqlite:' . DB_FILE);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

$db->exec("
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    banned INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    key_type TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    requests INTEGER NOT NULL DEFAULT 0,
    last_used TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    api_key TEXT,
    action TEXT NOT NULL,
    ip TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    project_type TEXT NOT NULL,
    user_hash TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(key_id, project_name, project_type, user_hash)
);

CREATE INDEX IF NOT EXISTS idx_project_activity_key
ON project_activity(key_id);

CREATE INDEX IF NOT EXISTS idx_project_activity_last_seen
ON project_activity(last_seen);
");

$defaults = [
    'admin_username' => 'admin',
    'maintenance' => '0',
    'maintenance_title' => 'AXP BLAZE is upgrading',
    'maintenance_message' => 'Please come back soon.'
];

foreach ($defaults as $name => $value) {
    $q = $db->prepare("INSERT OR IGNORE INTO settings(name,value) VALUES(?,?)");
    $q->execute([$name, $value]);
}

if ((int)$db->query("SELECT COUNT(*) FROM users")->fetchColumn() === 0) {
    $q = $db->prepare("
        INSERT INTO users(username,password,banned,created_at)
        VALUES(?,?,0,?)
    ");
    $q->execute([
        'admin',
        password_hash('AXP@Admin123', PASSWORD_DEFAULT),
        date('Y-m-d H:i:s')
    ]);
}

function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function csrf(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function check_csrf(): void {
    if (
        empty($_POST['csrf']) ||
        empty($_SESSION['csrf']) ||
        !hash_equals($_SESSION['csrf'], (string)$_POST['csrf'])
    ) {
        http_response_code(400);
        exit('Invalid request.');
    }
}

function get_setting(string $name): string {
    global $db;
    $q = $db->prepare("SELECT value FROM settings WHERE name=?");
    $q->execute([$name]);
    return (string)($q->fetchColumn() ?? '');
}

function set_setting(string $name, string $value): void {
    global $db;
    $q = $db->prepare("
        INSERT INTO settings(name,value) VALUES(?,?)
        ON CONFLICT(name) DO UPDATE SET value=excluded.value
    ");
    $q->execute([$name, $value]);
}

function current_user(): ?array {
    global $db;
    if (empty($_SESSION['user_id'])) {
        return null;
    }

    $q = $db->prepare("SELECT * FROM users WHERE id=?");
    $q->execute([(int)$_SESSION['user_id']]);
    $u = $q->fetch();

    return $u ?: null;
}

function is_admin(): bool {
    $u = current_user();
    return $u !== null &&
        strtolower((string)$u['username']) === strtolower(get_setting('admin_username'));
}

function log_event(?int $userId, ?string $key, string $action): void {
    global $db;
    $q = $db->prepare("
        INSERT INTO logs(user_id,api_key,action,ip,created_at)
        VALUES(?,?,?,?,?)
    ");
    $q->execute([
        $userId,
        $key,
        $action,
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        date('Y-m-d H:i:s')
    ]);
}

function redirect_to(string $url = '?'): never {
    header('Location: ' . $url);
    exit;
}

function active_key_count(int $userId): int {
    global $db;
    $q = $db->prepare("
        SELECT COUNT(*) FROM api_keys
        WHERE user_id=?
        AND active=1
        AND datetime(expires_at) > datetime('now')
    ");
    $q->execute([$userId]);
    return (int)$q->fetchColumn();
}


/* -------------------------
   Project / type analytics
------------------------- */

function type_slot_name(string $keyType): string {
    $map = [
        'Python'      => 'PythonDateBase',
        'PHP'         => 'PHPDateBase',
        'HTML'        => 'HTMLDateBase',
        'PhoneLookup' => 'PhoneLookupDateBase',
        'Database'    => 'DatabaseDateBase',
        'Custom'      => 'CustomDateBase',
    ];
    return $map[$keyType] ?? (preg_replace('/[^A-Za-z0-9]/', '', $keyType) . 'DateBase');
}

function clean_project_value(string $value, int $max = 80): string {
    $value = trim($value);
    $value = preg_replace('/[^\pL\pN ._:@\/-]/u', '', $value) ?? '';
    return substr($value !== '' ? $value : 'Unknown', 0, $max);
}

function record_project_heartbeat(string $apiKey, string $project, string $projectType, string $userId): array {
    global $db;

    $q = $db->prepare("
        SELECT api_keys.*, users.username, users.banned
        FROM api_keys
        JOIN users ON users.id=api_keys.user_id
        WHERE api_keys.api_key=?
    ");
    $q->execute([$apiKey]);
    $row = $q->fetch();

    if (
        !$row ||
        (int)$row['banned'] === 1 ||
        (int)$row['active'] !== 1 ||
        strtotime((string)$row['expires_at']) <= time()
    ) {
        return ['ok' => false, 'error' => 'Invalid, disabled or expired API key.'];
    }

    $project = clean_project_value($project);
    $projectType = clean_project_value($projectType);
    $userId = clean_project_value($userId);

    /*
     * Store a one-way identifier rather than the raw user identifier.
     * This lets the dashboard count unique users without storing the
     * supplied identifier itself.
     */
    $userHash = hash_hmac('sha256', $userId, (string)$apiKey);
    $now = date('Y-m-d H:i:s');

    $q = $db->prepare("
        INSERT INTO project_activity
            (key_id,project_name,project_type,user_hash,requests,first_seen,last_seen)
        VALUES(?,?,?,?,1,?,?)
        ON CONFLICT(key_id,project_name,project_type,user_hash)
        DO UPDATE SET
            requests=project_activity.requests+1,
            last_seen=excluded.last_seen
    ");
    $q->execute([
        (int)$row['id'],
        $project,
        $projectType,
        $userHash,
        $now,
        $now
    ]);

    $q = $db->prepare("
        UPDATE api_keys
        SET requests=requests+1,last_used=?
        WHERE id=?
    ");
    $q->execute([$now, (int)$row['id']]);

    log_event((int)$row['user_id'], $apiKey, 'PROJECT_HEARTBEAT');

    return [
        'ok' => true,
        'key_type' => (string)$row['key_type'],
        'slot' => type_slot_name((string)$row['key_type']),
        'project' => $project,
        'project_type' => $projectType,
        'expires_at' => (string)$row['expires_at']
    ];
}

function project_stats_for_admin(): array {
    global $db;

    $q = $db->query("
        SELECT
            pa.*,
            ak.api_key,
            ak.key_type,
            u.username
        FROM project_activity pa
        JOIN api_keys ak ON ak.id=pa.key_id
        JOIN users u ON u.id=ak.user_id
        ORDER BY pa.last_seen DESC
    ");

    $slots = [];
    $now = time();

    while ($row = $q->fetch()) {
        $slot = type_slot_name((string)$row['key_type']);

        if (!isset($slots[$slot])) {
            $slots[$slot] = [
                'key_type' => (string)$row['key_type'],
                'projects' => [],
                'requests' => 0,
                'users' => []
            ];
        }

        $projectKey = (string)$row['project_name'];
        if (!isset($slots[$slot]['projects'][$projectKey])) {
            $slots[$slot]['projects'][$projectKey] = [
                'project_type' => (string)$row['project_type'],
                'requests' => 0,
                'users' => [],
                'live_users' => 0,
                'last_seen' => null
            ];
        }

        $p =& $slots[$slot]['projects'][$projectKey];
        $p['requests'] += (int)$row['requests'];
        $p['users'][(string)$row['user_hash']] = true;

        $lastTs = strtotime((string)$row['last_seen']) ?: 0;
        if ($lastTs >= $now - 90) {
            $p['live_users']++;
        }

        if (
            $p['last_seen'] === null ||
            strtotime((string)$p['last_seen']) < $lastTs
        ) {
            $p['last_seen'] = (string)$row['last_seen'];
        }

        $slots[$slot]['requests'] += (int)$row['requests'];
        $slots[$slot]['users'][(string)$row['user_hash']] = true;
        unset($p);
    }

    return $slots;
}

/* -------------------------
   Authentication
------------------------- */

$error = '';
$success = '';

if (isset($_POST['login'])) {
    check_csrf();

    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    $q = $db->prepare("SELECT * FROM users WHERE username=?");
    $q->execute([$username]);
    $u = $q->fetch();

    if (!$u || !password_verify($password, (string)$u['password'])) {
        $error = 'Invalid username or password.';
    } elseif ((int)$u['banned'] === 1) {
        $error = 'Your account is banned.';
    } else {
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int)$u['id'];
        log_event((int)$u['id'], null, 'LOGIN');
        redirect_to('?');
    }
}

if (isset($_POST['register'])) {
    check_csrf();

    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if (strlen($username) < 3) {
        $error = 'Username must contain at least 3 characters.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must contain at least 6 characters.';
    } else {
        try {
            $q = $db->prepare("
                INSERT INTO users(username,password,banned,created_at)
                VALUES(?,?,0,?)
            ");
            $q->execute([
                $username,
                password_hash($password, PASSWORD_DEFAULT),
                date('Y-m-d H:i:s')
            ]);
            $success = 'Account created successfully. You can login now.';
        } catch (Throwable $ex) {
            $error = 'That username is already in use.';
        }
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    redirect_to('?');
}

$me = current_user();

if ($me && (int)$me['banned'] === 1) {
    session_destroy();
    exit('Your account has been banned.');
}

/* -------------------------
   API key generation
------------------------- */

if ($me && isset($_POST['generate_key'])) {
    check_csrf();

    if (active_key_count((int)$me['id']) >= MAX_ACTIVE_KEYS) {
        $error = 'You already have 5 active keys. Delete or wait for one to expire.';
    } else {
        $allowedTypes = ['Python','PHP','HTML','PhoneLookup','Database','Custom'];
        $type = (string)($_POST['type'] ?? 'Custom');
        if (!in_array($type, $allowedTypes, true)) {
            $type = 'Custom';
        }

        $days = (int)($_POST['expiry'] ?? 7);
        if (!in_array($days, [1,7,14,30], true)) {
            $days = 7;
        }

        $apiKey =
            'AXP-' .
            strtoupper(bin2hex(random_bytes(4))) . '-' .
            strtoupper(bin2hex(random_bytes(10)));

        $expires = date('Y-m-d H:i:s', strtotime("+{$days} days"));

        $q = $db->prepare("
            INSERT INTO api_keys
            (user_id,api_key,key_type,expires_at,active,requests,created_at)
            VALUES(?,?,?,?,1,0,?)
        ");
        $q->execute([
            (int)$me['id'],
            $apiKey,
            $type,
            $expires,
            date('Y-m-d H:i:s')
        ]);

        log_event((int)$me['id'], $apiKey, 'GENERATE_KEY');
        $success = 'New API key generated.';
    }
}

if ($me && isset($_POST['delete_own_key'])) {
    check_csrf();

    $q = $db->prepare("DELETE FROM api_keys WHERE id=? AND user_id=?");
    $q->execute([
        (int)($_POST['key_id'] ?? 0),
        (int)$me['id']
    ]);

    redirect_to('?page=keys');
}

/* -------------------------
   Public API key tester / project heartbeat
   Test: /?api=1&key=YOUR_KEY
   Heartbeat:
   /?api=1&action=heartbeat&key=YOUR_KEY&project=MySite&project_type=website&user=USER_ID
------------------------- */

if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        exit;
    }

    $key = trim((string)($_GET['key'] ?? ''));

    if ($key === '') {
        echo json_encode([
            'success' => false,
            'error' => 'API key required.'
        ], JSON_PRETTY_PRINT);
        exit;
    }

    if ((string)($_GET['action'] ?? '') === 'heartbeat') {
        $result = record_project_heartbeat(
            $key,
            (string)($_GET['project'] ?? 'Unknown Project'),
            (string)($_GET['project_type'] ?? 'website'),
            (string)($_GET['user'] ?? 'anonymous')
        );

        if (!$result['ok']) {
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'error' => $result['error']
            ], JSON_PRETTY_PRINT);
            exit;
        }

        echo json_encode([
            'success' => true,
            'message' => 'Heartbeat recorded.',
            'key_type' => $result['key_type'],
            'database_slot' => $result['slot'],
            'project' => $result['project'],
            'project_type' => $result['project_type'],
            'expires_at' => $result['expires_at']
        ], JSON_PRETTY_PRINT);
        exit;
    }

    $q = $db->prepare("
        SELECT
            api_keys.*,
            users.username,
            users.banned
        FROM api_keys
        JOIN users ON users.id=api_keys.user_id
        WHERE api_keys.api_key=?
    ");
    $q->execute([$key]);
    $row = $q->fetch();

    if (
        !$row ||
        (int)$row['banned'] === 1 ||
        (int)$row['active'] !== 1 ||
        strtotime((string)$row['expires_at']) <= time()
    ) {
        echo json_encode([
            'success' => false,
            'error' => 'Invalid, disabled or expired API key.'
        ], JSON_PRETTY_PRINT);
        exit;
    }

    $q = $db->prepare("
        UPDATE api_keys
        SET requests=requests+1,last_used=?
        WHERE id=?
    ");
    $q->execute([date('Y-m-d H:i:s'), (int)$row['id']]);

    echo json_encode([
        'success' => true,
        'message' => 'API key is valid.',
        'key_type' => $row['key_type'],
        'database_slot' => type_slot_name((string)$row['key_type']),
        'username' => $row['username'],
        'expires_at' => $row['expires_at'],
        'requests' => (int)$row['requests'] + 1
    ], JSON_PRETTY_PRINT);
    exit;
}

/* -------------------------
   Admin actions
------------------------- */

if (is_admin()) {

    /* Website updater: authenticated admin + CSRF + PHP lint + backup + atomic install */
    if (isset($_POST['action']) && $_POST['action'] === 'website_update_upload') {
        check_csrf();

        if (
            !isset($_FILES['website_update_file']) ||
            !is_array($_FILES['website_update_file'])
        ) {
            $error = 'Please select an index.php file.';
        } elseif ((int)$_FILES['website_update_file']['error'] !== UPLOAD_ERR_OK) {
            $error = 'Upload failed. Error code: ' . (int)$_FILES['website_update_file']['error'];
        } elseif ((int)$_FILES['website_update_file']['size'] > 2 * 1024 * 1024) {
            $error = 'Update file is too large. Maximum size is 2 MB.';
        } else {
            $tmp = (string)$_FILES['website_update_file']['tmp_name'];
            $original = (string)$_FILES['website_update_file']['name'];

            if (strtolower(pathinfo($original, PATHINFO_EXTENSION)) !== 'php') {
                $error = 'Only a PHP index.php file is allowed.';
            } elseif (!is_uploaded_file($tmp)) {
                $error = 'Invalid uploaded file.';
            } else {
                $contents = @file_get_contents($tmp);

                if ($contents === false || !preg_match('/^\s*<\?php\b/i', $contents)) {
                    $error = 'The uploaded file must start with a PHP opening tag.';
                } else {
                    $backupDir = __DIR__ . DIRECTORY_SEPARATOR . 'backups';

                    if (!is_dir($backupDir)) {
                        @mkdir($backupDir, 0755, true);
                    }

                    $lintTmp = $backupDir . DIRECTORY_SEPARATOR . '.update_check_' . bin2hex(random_bytes(8)) . '.php';
                    $newTmp = $backupDir . DIRECTORY_SEPARATOR . '.new_index_' . bin2hex(random_bytes(8)) . '.php';

                    if (@file_put_contents($lintTmp, $contents, LOCK_EX) === false) {
                        $error = 'Could not prepare the update file.';
                    } else {
                        $phpBin = defined('PHP_BINARY') && PHP_BINARY !== '' ? PHP_BINARY : 'php';
                        $output = [];
                        $exitCode = 1;

                        @exec(
                            escapeshellarg($phpBin) . ' -l ' . escapeshellarg($lintTmp) . ' 2>&1',
                            $output,
                            $exitCode
                        );

                        @unlink($lintTmp);

                        if ($exitCode !== 0) {
                            $error = 'Update rejected: PHP syntax check failed. ' .
                                trim(implode("\n", $output));
                        } elseif (@file_put_contents($newTmp, $contents, LOCK_EX) === false) {
                            $error = 'Could not prepare the new website file.';
                        } else {
                            $backupFile = $backupDir . DIRECTORY_SEPARATOR .
                                'index_' . date('Ymd_His') . '_' . bin2hex(random_bytes(3)) . '.php';

                            if (!@copy(__FILE__, $backupFile)) {
                                @unlink($newTmp);
                                $error = 'Backup could not be created. Update cancelled.';
                            } elseif (!@rename($newTmp, __DIR__ . DIRECTORY_SEPARATOR . 'index.php')) {
                                @unlink($newTmp);
                                $error = 'Could not activate the new website file.';
                            } else {
                                set_setting('last_update_backup', basename($backupFile));
                                set_setting('last_update_at', date('Y-m-d H:i:s'));
                                log_event((int)$me['id'], null, 'WEBSITE_UPDATE');
                                redirect_to('?page=admin&tab=website&updated=1');
                            }
                        }
                    }
                }
            }
        }
    }

    if (isset($_POST['action']) && $_POST['action'] === 'website_update_rollback') {
        check_csrf();

        $backupDir = __DIR__ . DIRECTORY_SEPARATOR . 'backups';
        $backupName = get_setting('last_update_backup');
        $backupFile = $backupDir . DIRECTORY_SEPARATOR . basename($backupName);

        if (
            $backupName === '' ||
            !is_file($backupFile)
        ) {
            $error = 'No valid website backup was found.';
        } else {
            $restoreTmp = $backupDir . DIRECTORY_SEPARATOR . '.rollback_' . bin2hex(random_bytes(8)) . '.php';
            $contents = @file_get_contents($backupFile);

            if ($contents === false || !preg_match('/^\s*<\?php\b/i', $contents)) {
                $error = 'Backup file is invalid.';
            } elseif (@file_put_contents($restoreTmp, $contents, LOCK_EX) === false) {
                $error = 'Could not prepare rollback.';
            } else {
                $phpBin = defined('PHP_BINARY') && PHP_BINARY !== '' ? PHP_BINARY : 'php';
                $output = [];
                $exitCode = 1;

                @exec(
                    escapeshellarg($phpBin) . ' -l ' . escapeshellarg($restoreTmp) . ' 2>&1',
                    $output,
                    $exitCode
                );

                if ($exitCode !== 0) {
                    @unlink($restoreTmp);
                    $error = 'Rollback rejected: backup syntax check failed.';
                } elseif (!@rename($restoreTmp, __DIR__ . DIRECTORY_SEPARATOR . 'index.php')) {
                    @unlink($restoreTmp);
                    $error = 'Could not activate rollback.';
                } else {
                    log_event((int)$me['id'], null, 'WEBSITE_ROLLBACK');
                    redirect_to('?page=admin&tab=website&rolled_back=1');
                }
            }
        }
    }

    if (isset($_POST['admin_toggle_user'])) {
        check_csrf();

        $id = (int)($_POST['user_id'] ?? 0);

        if ($id !== (int)$me['id']) {
            $q = $db->prepare("
                UPDATE users
                SET banned=CASE banned WHEN 1 THEN 0 ELSE 1 END
                WHERE id=?
            ");
            $q->execute([$id]);
        }

        redirect_to('?page=admin&tab=users');
    }

    if (isset($_POST['admin_delete_user'])) {
        check_csrf();

        $id = (int)($_POST['user_id'] ?? 0);

        if ($id !== (int)$me['id']) {
            $db->prepare("DELETE FROM api_keys WHERE user_id=?")->execute([$id]);
            $db->prepare("DELETE FROM logs WHERE user_id=?")->execute([$id]);
            $db->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
        }

        redirect_to('?page=admin&tab=users');
    }

    if (isset($_POST['admin_reset_password'])) {
        check_csrf();

        $id = (int)($_POST['user_id'] ?? 0);
        $newPassword = (string)($_POST['new_password'] ?? '');

        if (strlen($newPassword) >= 6) {
            $q = $db->prepare("
                UPDATE users SET password=? WHERE id=?
            ");
            $q->execute([
                password_hash($newPassword, PASSWORD_DEFAULT),
                $id
            ]);
            $success = 'User password has been reset.';
        } else {
            $error = 'New password must contain at least 6 characters.';
        }
    }

    if (isset($_POST['admin_toggle_key'])) {
        check_csrf();

        $q = $db->prepare("
            UPDATE api_keys
            SET active=CASE active WHEN 1 THEN 0 ELSE 1 END
            WHERE id=?
        ");
        $q->execute([(int)($_POST['key_id'] ?? 0)]);

        redirect_to('?page=admin&tab=keys');
    }

    if (isset($_POST['admin_delete_key'])) {
        check_csrf();

        $q = $db->prepare("DELETE FROM api_keys WHERE id=?");
        $q->execute([(int)($_POST['key_id'] ?? 0)]);

        redirect_to('?page=admin&tab=keys');
    }

    if (isset($_POST['save_maintenance'])) {
        check_csrf();

        set_setting(
            'maintenance',
            isset($_POST['maintenance']) ? '1' : '0'
        );
        set_setting(
            'maintenance_title',
            trim((string)($_POST['maintenance_title'] ?? 'AXP BLAZE is upgrading'))
        );
        set_setting(
            'maintenance_message',
            trim((string)($_POST['maintenance_message'] ?? 'Please come back soon.'))
        );

        redirect_to('?page=admin&tab=website');
    }

    if (isset($_POST['change_admin_login'])) {
        check_csrf();

        $oldAdmin = get_setting('admin_username');
        $newUsername = trim((string)($_POST['admin_username'] ?? ''));
        $newPassword = (string)($_POST['admin_password'] ?? '');

        if (strlen($newUsername) < 3 || strlen($newPassword) < 6) {
            $error = 'Admin username needs 3+ chars and password needs 6+ chars.';
        } else {
            $q = $db->prepare("
                UPDATE users
                SET username=?,password=?
                WHERE username=?
            ");
            $q->execute([
                $newUsername,
                password_hash($newPassword, PASSWORD_DEFAULT),
                $oldAdmin
            ]);

            set_setting('admin_username', $newUsername);
            $success = 'Admin login updated.';
        }
    }

    if (isset($_POST['add_channel'])) {
        check_csrf();

        $name = trim((string)($_POST['channel_name'] ?? ''));
        $url = trim((string)($_POST['channel_url'] ?? ''));

        if (
            $name !== '' &&
            filter_var($url, FILTER_VALIDATE_URL)
        ) {
            $q = $db->prepare("
                INSERT INTO channels(name,url) VALUES(?,?)
            ");
            $q->execute([$name, $url]);
        }

        redirect_to('?page=admin&tab=links');
    }

    if (isset($_POST['delete_channel'])) {
        check_csrf();

        $q = $db->prepare("DELETE FROM channels WHERE id=?");
        $q->execute([(int)($_POST['channel_id'] ?? 0)]);

        redirect_to('?page=admin&tab=links');
    }
}

/* -------------------------
   Maintenance mode
------------------------- */

$maintenanceAdminAccess = is_admin();

if (get_setting('maintenance') === '1' && !is_admin() && !$maintenanceAdminAccess) {
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#05050a">
<title>AXP BLAZE</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100svh;
    background:#05050a;
    color:#fff;
    font-family:system-ui,sans-serif;
    display:grid;
    place-items:center;
    padding:18px;
}
.box{
    width:min(100%,420px);
    padding:30px 22px;
    border:1px solid #28253e;
    border-radius:24px;
    background:#0b0b13;
    text-align:center;
    box-shadow:0 20px 80px #000;
}
.logo{
    color:#00dda0;
    font-size:24px;
    font-weight:1000;
    letter-spacing:4px;
}
.muted{color:#89899c;line-height:1.7}
</style>



<style>
.admin-mode-marker{
    display:none;
    width:max-content;
    margin:8px auto;
    padding:5px 9px;
    border:1px solid #1b6a4d;
    border-radius:999px;
    color:#61e1b0;
    background:#07130e;
    font-size:8px;
    font-weight:900;
    letter-spacing:1px;
}
</style>

<style>
.updateDrop{
    margin-top:12px;
    padding:14px;
    border:1px dashed #236a4d;
    border-radius:15px;
    background:#07100c;
}
#website-updater-card input[type=file]{
    width:100%;
    padding:11px;
    border:1px solid #23372f;
    border-radius:11px;
    background:#080d0b;
    color:#ccefe0;
    font-size:10px;
}
</style>
</head>
<body>
<div class="box">
    <div class="logo">AXP BLAZE
<a class="maintenance-admin-login" href="?admin=1">🔐 Admin Login</a><div id="admin-mode-marker" class="admin-mode-marker">🔐 ADMIN ACCESS MODE</div>
</div>
    <h2><?=e(get_setting('maintenance_title'))?></h2>
    <p class="muted"><?=nl2br(e(get_setting('maintenance_message')))?></p>
</div>
</body>
</html>
<?php
exit;
}

$page = (string)($_GET['page'] ?? 'home');

/* -------------------------
   Dashboard numbers
------------------------- */

$totalUsers = (int)$db->query("
    SELECT COUNT(*) FROM users WHERE banned=0
")->fetchColumn();

$totalActiveKeys = (int)$db->query("
    SELECT COUNT(*) FROM api_keys
    WHERE active=1 AND datetime(expires_at)>datetime('now')
")->fetchColumn();

$totalExpiredKeys = (int)$db->query("
    SELECT COUNT(*) FROM api_keys
    WHERE datetime(expires_at)<=datetime('now')
")->fetchColumn();

$totalRequests = (int)$db->query("
    SELECT COALESCE(SUM(requests),0) FROM api_keys
")->fetchColumn();

$channels = $db->query("
    SELECT * FROM channels ORDER BY id DESC
")->fetchAll();

/* -------------------------
   Current user's keys
------------------------- */

$myKeys = [];

if ($me) {
    $q = $db->prepare("
        SELECT * FROM api_keys
        WHERE user_id=?
        ORDER BY id DESC
    ");
    $q->execute([(int)$me['id']]);
    $myKeys = $q->fetchAll();
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="theme-color" content="#05050a">
<title>AXP BLAZE</title>

<style>
*{
    box-sizing:border-box;
    -webkit-tap-highlight-color:transparent;
}

html,body{
    margin:0;
    padding:0;
    width:100%;
    min-height:100%;
    background:#05050a;
    color:#fff;
    font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}

body{
    overflow-x:hidden;
}

a{
    color:inherit;
    text-decoration:none;
}

button,input,select,textarea{
    font:inherit;
}

button{
    cursor:pointer;
}

:root{
    --bg:#05050a;
    --panel:#0b0b13;
    --panel2:#10101a;
    --line:#25253a;
    --indigo:#8e7cff;
    --green:#00dda0;
    --muted:#858598;
}

/* PHONE-FIRST LAYOUT */
.app{
    width:100%;
    min-height:100svh;
}

.nav{
    position:sticky;
    top:0;
    z-index:80;
    width:100%;
    height:60px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:0 13px;
    background:rgba(5,5,10,.90);
    backdrop-filter:blur(18px);
    border-bottom:1px solid #1f1f30;
}

.logo{
    color:var(--indigo);
    font-size:17px;
    font-weight:1000;
    letter-spacing:3px;
}

.menu{
    width:41px;
    height:39px;
    border:1px solid #2b2941;
    border-radius:12px;
    color:#fff;
    background:#0d0d16;
}

.container{
    width:100%;
    max-width:560px;
    margin:0 auto;
    padding:13px 12px 20px;
}

.hero{
    padding:21px 3px 13px;
}

.tag{
    display:inline-block;
    padding:5px 8px;
    border:1px solid #302b56;
    border-radius:20px;
    background:#0c0b17;
    color:#a99cff;
    font-size:8px;
    font-weight:900;
    letter-spacing:1px;
}

.hero h1{
    margin:13px 0 9px;
    font-size:48px;
    line-height:.90;
    letter-spacing:-3px;
    background:linear-gradient(90deg,#fff,#a394ff,var(--green));
    -webkit-background-clip:text;
    background-clip:text;
    color:transparent;
}

.hero p{
    margin:0;
    color:var(--muted);
    font-size:12px;
    line-height:1.55;
}

.card{
    width:100%;
    margin-bottom:11px;
    padding:15px;
    border:1px solid var(--line);
    border-radius:19px;
    background:linear-gradient(145deg,#11111a,#08080e);
    box-shadow:0 12px 35px rgba(0,0,0,.22);
}

h2{
    margin:0 0 7px;
    font-size:20px;
}

h3{
    margin:0 0 6px;
}

.muted{
    color:var(--muted);
    font-size:12px;
    line-height:1.6;
}

.stats{
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:8px;
    margin-bottom:11px;
}

.stat{
    min-width:0;
    padding:12px;
    border:1px solid #24243a;
    border-radius:16px;
    background:#0b0b13;
}

.statIcon{
    font-size:16px;
}

.statName{
    color:#77778b;
    font-size:9px;
    margin-top:3px;
}

.statValue{
    margin-top:1px;
    font-size:23px;
    font-weight:1000;
}

.btn{
    min-height:41px;
    display:inline-flex;
    align-items:center;
    justify-content:center;
    padding:9px 12px;
    border:0;
    border-radius:11px;
    color:#fff;
    font-size:11px;
    font-weight:900;
    background:linear-gradient(135deg,#6551ff,#8d79ff);
}

.green{
    background:linear-gradient(135deg,#009d78,#00dda0);
}

.red{
    background:#8d2942;
}

.gray{
    background:#262638;
}

.full{
    width:100%;
}

.grid2{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:8px;
}

input,select,textarea{
    width:100%;
    margin:5px 0 11px;
    padding:11px;
    border:1px solid #2b2b40;
    border-radius:11px;
    outline:none;
    background:#06060b;
    color:#fff;
}

textarea{
    min-height:100px;
    resize:vertical;
}

label{
    color:#858598;
    font-size:10px;
}

.alert{
    margin-bottom:11px;
    padding:11px;
    border:1px solid #2c2c40;
    border-radius:11px;
    background:#10101a;
    font-size:11px;
}

.alert.error{
    color:#ff7188;
    border-color:#562a39;
}

.alert.success{
    color:#5ee0ae;
    border-color:#1b5c42;
}

/* LOGIN PAGE STATS ARE ABOVE THE LOGIN CARD */
.loginStats{
    margin-top:2px;
}

.authLogo{
    margin-bottom:15px;
    text-align:center;
    color:var(--indigo);
    font-size:26px;
    font-weight:1000;
    letter-spacing:4px;
}

.key{
    margin-top:9px;
    padding:12px;
    border:1px solid #27273b;
    border-radius:14px;
    background:#06060b;
}

.keyHead{
    display:flex;
    justify-content:space-between;
    gap:8px;
    align-items:center;
}

.keyCode{
    margin:9px 0;
    color:var(--green);
    font-family:monospace;
    font-size:10px;
    line-height:1.5;
    word-break:break-all;
}

.badge{
    display:inline-block;
    padding:4px 7px;
    border-radius:7px;
    background:#17152b;
    color:#a69aff;
    font-size:8px;
    font-weight:900;
}

.dbslot{
    margin-top:9px;
    padding:12px;
    border:1px solid #18563e;
    border-radius:14px;
    background:linear-gradient(145deg,#06140f,#090a10);
}

.dbslot h4{
    margin:0 0 8px;
    color:var(--green);
}

.dbgrid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:6px;
}

.dbitem{
    padding:8px;
    border-radius:9px;
    background:#080c0d;
}

.dbitem small{
    display:block;
    color:#727786;
    font-size:8px;
}

.dbitem b{
    display:block;
    margin-top:2px;
    font-size:10px;
    word-break:break-word;
}

/* SIDE MENU */
.side{
    position:fixed;
    top:0;
    right:-310px;
    z-index:150;
    width:min(300px,88vw);
    height:100svh;
    padding:18px 14px;
    border-left:1px solid #2a2940;
    background:#08080f;
    box-shadow:-25px 0 70px #000;
    transition:right .25s ease;
}

.side.open{
    right:0;
}

.close{
    position:absolute;
    top:7px;
    right:10px;
    border:0;
    background:transparent;
    color:#fff;
    font-size:27px;
}

.sideLogo{
    margin:35px 0 18px;
    color:var(--green);
    font-size:21px;
    font-weight:1000;
    letter-spacing:3px;
}

.side a{
    display:block;
    margin:7px 0;
    padding:12px;
    border:1px solid #24243a;
    border-radius:11px;
    background:#0d0d16;
    color:#aaaabd;
    font-size:11px;
}

/* ADMIN */
.admin{
    border-color:#16513a;
    background:linear-gradient(145deg,#07100b,#07070c);
}

.adminTitle{
    color:var(--green);
    font-size:21px;
    font-weight:1000;
}

.adminUser{
    color:#b0afbd;
    font-size:10px;
    margin-top:2px;
}

.tabs{
    display:flex;
    gap:5px;
    overflow:auto;
    margin:13px 0;
    scrollbar-width:none;
}

.tabs a{
    white-space:nowrap;
    padding:8px 9px;
    border:1px solid #174631;
    border-radius:9px;
    background:#07130d;
    color:#65d9ae;
    font-size:9px;
}

.table{
    width:100%;
    overflow-x:auto;
}

table{
    width:100%;
    min-width:610px;
    border-collapse:collapse;
    font-size:9px;
}

th,td{
    padding:8px 5px;
    border-bottom:1px solid #202031;
    text-align:left;
    vertical-align:top;
}

th{
    color:var(--green);
}

.actionRow{
    display:flex;
    flex-wrap:wrap;
    gap:5px;
}

.actionRow .btn{
    min-height:32px;
    padding:6px 8px;
    font-size:9px;
}

/* PASSWORD SHOW/HIDE */
.passWrap{
    display:flex;
    gap:5px;
}

.passWrap input{
    margin:0;
    flex:1;
}

.passWrap button{
    width:54px;
    border:1px solid #2b2b40;
    border-radius:10px;
    background:#151521;
    color:#fff;
    font-size:9px;
}

/* FOOTER LINKS */
.footer{
    margin-top:16px;
    padding:17px 2px 26px;
    text-align:center;
    color:#5c5c6d;
    font-size:9px;
}

.footerLinks{
    display:flex;
    flex-wrap:wrap;
    justify-content:center;
    gap:6px;
    margin-bottom:10px;
}

.footerLinks a{
    padding:8px 10px;
    border:1px solid #27273a;
    border-radius:9px;
    background:#0c0c14;
    color:#a29abf;
    font-size:9px;
}

/* SPLASH ANIMATION - ONLY ON FIRST OPEN/REFRESH */
#splash{
    position:fixed;
    inset:0;
    z-index:9999;
    display:grid;
    place-items:center;
    overflow:hidden;
    background:#05050a;
}

.splashGlow{
    position:absolute;
    width:250px;
    height:250px;
    border-radius:50%;
    background:radial-gradient(circle,rgba(112,81,255,.34),transparent 68%);
    filter:blur(12px);
    animation:glow 1.8s ease-in-out infinite alternate;
}

.splashLogo{
    position:relative;
    color:transparent;
    font-size:clamp(30px,10vw,52px);
    font-weight:1000;
    letter-spacing:6px;
    background:linear-gradient(90deg,#fff,#9d8cff,var(--green));
    -webkit-background-clip:text;
    background-clip:text;
    animation:logoIn .9s cubic-bezier(.2,.8,.2,1);
}

.splashLine{
    position:absolute;
    bottom:31%;
    width:0;
    height:2px;
    background:var(--green);
    box-shadow:0 0 18px var(--green);
    animation:lineIn 1.25s .25s forwards;
}

.splashOut{
    animation:splashOut .5s forwards;
}

@keyframes logoIn{
    0%{
        opacity:0;
        transform:scale(.72) translateY(18px);
        filter:blur(10px);
    }
    100%{
        opacity:1;
        transform:scale(1);
        filter:blur(0);
    }
}

@keyframes lineIn{
    to{width:145px}
}

@keyframes glow{
    to{
        transform:scale(1.3);
        opacity:.65;
    }
}

@keyframes splashOut{
    to{
        opacity:0;
        visibility:hidden;
        transform:scale(1.03);
    }
}

/* Make it look like a normal phone even when desktop CSS is present */
@media(min-width:700px){
    .container{
        max-width:560px;
    }
}

@media(max-width:360px){
    .container{
        padding-left:9px;
        padding-right:9px;
    }

    .hero h1{
        font-size:43px;
    }

    .card{
        padding:13px;
    }

    .stats{
        gap:6px;
    }
}
</style>
</head>

<body>

<!-- OPENING ANIMATION -->
<div id="splash">
    <div class="splashGlow"></div>
    <div class="splashLogo">AXP BLAZE</div>
    <div class="splashLine"></div>
</div>

<nav class="nav">
    <a href="?"><div class="logo">AXP BLAZE</div></a>
    <button class="menu" onclick="openMenu()">☰</button>
</nav>

<aside class="side" id="side">
    <button class="close" onclick="closeMenu()">×</button>

    <div class="sideLogo">AXP BLAZE</div>

    <a href="?">🏠 Dashboard</a>

    <?php if ($me): ?>
        <a href="?page=generate">⚡ Generate Key</a>
        <a href="?page=keys">🔑 My Keys</a>
        <a href="?page=tester">🧪 Key Tester</a>

        <?php if (is_admin()): ?>
            <a href="?page=admin">🛠 Admin Panel</a>
        <?php endif; ?>

        <a href="?logout=1">🚪 Logout</a>
    <?php else: ?>
        <a href="?page=login">🔐 Login</a>
        <a href="?page=register">📝 Create Account</a>
    <?php endif; ?>
</aside>

<main class="container">

<?php if ($error !== ''): ?>
    <div class="alert error"><?=e($error)?></div>
<?php endif; ?>

<?php if ($success !== ''): ?>
    <div class="alert success"><?=e($success)?></div>
<?php endif; ?>


<?php if (!$me && ($page === 'home' || $page === 'login' || $page === 'register')): ?>

    <!-- MAIN / LOGIN AREA -->
    <section class="hero">
        <span class="tag">PREMIUM API PLATFORM</span>
        <h1>AXP<br>BLAZE</h1>
        <p>Secure API keys. Simple management. Powerful dashboard.</p>
    </section>

    <!-- REAL STATS STAY OUTSIDE THE LOGIN CARD -->
    <section class="stats loginStats">
        <div class="stat">
            <div class="statIcon">👥</div>
            <div class="statName">USERS</div>
            <div class="statValue"><?=number_format($totalUsers)?></div>
        </div>

        <div class="stat">
            <div class="statIcon">🔑</div>
            <div class="statName">ACTIVE KEYS</div>
            <div class="statValue"><?=number_format($totalActiveKeys)?></div>
        </div>

        <div class="stat">
            <div class="statIcon">⏳</div>
            <div class="statName">EXPIRED KEYS</div>
            <div class="statValue"><?=number_format($totalExpiredKeys)?></div>
        </div>

        <div class="stat">
            <div class="statIcon">⚡</div>
            <div class="statName">REQUESTS</div>
            <div class="statValue"><?=number_format($totalRequests)?></div>
        </div>
    </section>

    <?php if ($page === 'register'): ?>

        <section class="card">
            <div class="authLogo">CREATE ACCOUNT</div>

            <form method="post">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">

                <label>Username</label>
                <input name="username" minlength="3" required autocomplete="username">

                <label>Password</label>
                <div class="passWrap">
                    <input id="registerPassword" type="password" name="password" minlength="6" required>
                    <button type="button" onclick="togglePass('registerPassword',this)">Show</button>
                </div>

                <button class="btn green full" name="register">
                    Create Account
                </button>
            </form>

            <div style="height:8px"></div>
            <a class="btn full" href="?page=login">Already have an account? Login</a>
        </section>

    <?php else: ?>

        <section class="card">
            <div class="authLogo">LOGIN</div>

            <form method="post">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">

                <label>Username</label>
                <input name="username" required autocomplete="username">

                <label>Password</label>
                <div class="passWrap">
                    <input id="loginPassword" type="password" name="password" required autocomplete="current-password">
                    <button type="button" onclick="togglePass('loginPassword',this)">Show</button>
                </div>

                <button class="btn full" name="login">
                    Login →
                </button>
            </form>

            <div style="height:8px"></div>
            <a class="btn green full" href="?page=register">Create Account</a>
        </section>

    <?php endif; ?>


<?php elseif ($me && ($page === 'home')): ?>

    <!-- LOGGED-IN DASHBOARD -->
    <section class="hero">
        <span class="tag">WELCOME BACK</span>
        <h1><?=e((string)$me['username'])?></h1>
        <p>Your API control center is ready.</p>
    </section>

    <section class="stats">
        <div class="stat">
            <div class="statIcon">👥</div>
            <div class="statName">USERS</div>
            <div class="statValue"><?=number_format($totalUsers)?></div>
        </div>

        <div class="stat">
            <div class="statIcon">🔑</div>
            <div class="statName">ACTIVE KEYS</div>
            <div class="statValue"><?=number_format($totalActiveKeys)?></div>
        </div>

        <div class="stat">
            <div class="statIcon">⏳</div>
            <div class="statName">EXPIRED KEYS</div>
            <div class="statValue"><?=number_format($totalExpiredKeys)?></div>
        </div>

        <div class="stat">
            <div class="statIcon">⚡</div>
            <div class="statName">REQUESTS</div>
            <div class="statValue"><?=number_format($totalRequests)?></div>
        </div>
    </section>

    <section class="card">
        <h3>Account</h3>
        <p class="muted">
            ID: <b>#<?=e((string)$me['id'])?></b><br>
            Username: <b><?=e((string)$me['username'])?></b><br>
            Active keys: <b><?=active_key_count((int)$me['id'])?> / <?=MAX_ACTIVE_KEYS?></b>
        </p>

        <div class="grid2">
            <a class="btn green" href="?page=generate">Generate Key</a>
            <a class="btn" href="?page=keys">My Keys</a>
        </div>
    </section>


<?php elseif ($me && $page === 'generate'): ?>

    <section class="card">
        <h2>⚡ Generate API Key</h2>
        <p class="muted">
            Maximum <?=MAX_ACTIVE_KEYS?> active keys per account.
        </p>

        <form method="post">
            <input type="hidden" name="csrf" value="<?=e(csrf())?>">

            <label>SELECT YOUR KEY</label>
            <select name="type">
                <option>Python</option>
                <option>PHP</option>
                <option>HTML</option>
                <option>PhoneLookup</option>
                <option>Database</option>
                <option>Custom</option>
            </select>

            <label>SELECT EXPIRY</label>
            <select name="expiry">
                <option value="1">1 Day</option>
                <option value="7">7 Days</option>
                <option value="14">14 Days</option>
                <option value="30">30 Days</option>
            </select>

            <button class="btn green full" name="generate_key">
                Generate API Key
            </button>
        </form>
    </section>


<?php elseif ($me && $page === 'keys'): ?>

    <section class="card">
        <h2>🔑 My API Keys</h2>
        <p class="muted">
            Active limit: <?=active_key_count((int)$me['id'])?> / <?=MAX_ACTIVE_KEYS?>
        </p>

        <?php if (!$myKeys): ?>
            <p class="muted">You have not generated any keys yet.</p>
        <?php endif; ?>

        <?php foreach ($myKeys as $key): ?>
            <div class="key">

                <div class="keyHead">
                    <span class="badge"><?=e((string)$key['key_type'])?></span>

                    <?php
                    $expired = strtotime((string)$key['expires_at']) <= time();
                    ?>

                    <?php if ((int)$key['active'] === 1 && !$expired): ?>
                        <span class="badge" style="color:#54dfaa">ACTIVE</span>
                    <?php else: ?>
                        <span class="badge" style="color:#ff7188">EXPIRED / OFF</span>
                    <?php endif; ?>
                </div>

                <div class="keyCode">
                    <?=e((string)$key['api_key'])?>
                </div>

                <div class="muted">
                    Expires: <?=e((string)$key['expires_at'])?><br>
                    Requests: <?=number_format((int)$key['requests'])?><br>
                    Last used: <?=e((string)($key['last_used'] ?? 'Never'))?>
                </div>

                <?php if (strcasecmp((string)$key['key_type'], 'Database') === 0): ?>
                    <!-- DATABASE KEY DATA SLOT -->
                    <div class="dbslot">
                        <h4>🗄 Database Key Data</h4>

                        <div class="dbgrid">
                            <div class="dbitem">
                                <small>KEY ID</small>
                                <b>#<?=e((string)$key['id'])?></b>
                            </div>

                            <div class="dbitem">
                                <small>OWNER</small>
                                <b><?=e((string)$me['username'])?></b>
                            </div>

                            <div class="dbitem">
                                <small>REQUESTS</small>
                                <b><?=number_format((int)$key['requests'])?></b>
                            </div>

                            <div class="dbitem">
                                <small>STATUS</small>
                                <b><?=((int)$key['active']===1 && !$expired)?'ACTIVE':'OFF'?></b>
                            </div>

                            <div class="dbitem">
                                <small>CREATED</small>
                                <b><?=e((string)$key['created_at'])?></b>
                            </div>

                            <div class="dbitem">
                                <small>LAST USED</small>
                                <b><?=e((string)($key['last_used'] ?? 'Never'))?></b>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <div style="margin-top:9px">
                    <form method="post">
                        <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                        <input type="hidden" name="key_id" value="<?=e((string)$key['id'])?>">
                        <button class="btn red" name="delete_own_key">
                            Delete Key
                        </button>
                    </form>
                </div>
            </div>
        <?php endforeach; ?>
    </section>


<?php elseif ($me && $page === 'tester'): ?>

    <section class="card">
        <h2>🧪 API Key Tester</h2>
        <p class="muted">
            Paste a key and test it directly in Chrome.
        </p>

        <input id="testerKey" placeholder="AXP-XXXXXXXX-XXXXXXXXXXXXXXXXXXXX">

        <button class="btn green full" onclick="testKey()">
            Test Key
        </button>

        <pre id="testerResult" style="
            display:none;
            white-space:pre-wrap;
            word-break:break-word;
            margin-top:11px;
            padding:11px;
            border-radius:11px;
            background:#050509;
            border:1px solid #24243a;
            color:#00dda0;
            font-size:10px;
        "></pre>
    </section>


<?php elseif ($me && is_admin() && $page === 'admin'): ?>

    <?php
    $tab = (string)($_GET['tab'] ?? 'overview');
    ?>

    <section class="card admin">
        <div class="adminTitle">🛠 AXP BLAZE ADMIN</div>
        <div class="adminUser">
            Logged in as: <?=e((string)$me['username'])?>
        </div>
    </section>

    <div class="tabs">
        <a href="?page=admin&tab=overview">Overview</a>
        <a href="?page=admin&tab=users">Users</a>
        <a href="?page=admin&tab=keys">Keys</a>
        <a href="?page=admin&tab=projects">Projects</a>
        <a href="?page=admin&tab=website">Website</a>
        <a href="?page=admin&tab=links">Links</a>
        <a href="?page=admin&tab=security">Security</a>
    </div>

    <?php if ($tab === 'overview'): ?>

        <section class="stats">
            <div class="stat">
                <div class="statIcon">👥</div>
                <div class="statName">USERS</div>
                <div class="statValue"><?=$totalUsers?></div>
            </div>
            <div class="stat">
                <div class="statIcon">🔑</div>
                <div class="statName">ACTIVE KEYS</div>
                <div class="statValue"><?=$totalActiveKeys?></div>
            </div>
            <div class="stat">
                <div class="statIcon">⏳</div>
                <div class="statName">EXPIRED</div>
                <div class="statValue"><?=$totalExpiredKeys?></div>
            </div>
            <div class="stat">
                <div class="statIcon">⚡</div>
                <div class="statName">REQUESTS</div>
                <div class="statValue"><?=$totalRequests?></div>
            </div>
        </section>

        <section class="card admin">
            <h3>System</h3>
            <p class="muted">
                SQLite database: connected<br>
                Key limit: <?=MAX_ACTIVE_KEYS?> active keys / user<br>
                Maintenance: <?=get_setting('maintenance')==='1'?'ON':'OFF'?>
            </p>
        </section>

    <?php elseif ($tab === 'users'): ?>

        <?php
        $users = $db->query("
            SELECT
                u.*,
                (SELECT COUNT(*) FROM api_keys k WHERE k.user_id=u.id) AS key_count,
                (SELECT COALESCE(SUM(k.requests),0) FROM api_keys k WHERE k.user_id=u.id) AS requests
            FROM users u
            ORDER BY u.id DESC
        ")->fetchAll();
        ?>

        <section class="card admin">
            <h3>👥 Users</h3>
            <p class="muted">
                User ID, username, status, key count and request data.
            </p>

            <div class="table">
                <table>
                    <tr>
                        <th>ID</th>
                        <th>USERNAME</th>
                        <th>PASSWORD</th>
                        <th>STATUS</th>
                        <th>KEYS</th>
                        <th>REQUESTS</th>
                        <th>ACTION</th>
                    </tr>

                    <?php foreach ($users as $u): ?>
                        <tr>
                            <td>#<?=e((string)$u['id'])?></td>

                            <td><?=e((string)$u['username'])?></td>

                            <td>
                                <!-- Stored passwords are hashes; they cannot be revealed. -->
                                <span style="color:#77778b">••••••••</span>
                            </td>

                            <td>
                                <?=((int)$u['banned']===1)
                                    ? '<span style="color:#ff7188">BANNED</span>'
                                    : '<span style="color:#55dfa9">ACTIVE</span>'?>
                            </td>

                            <td><?=e((string)$u['key_count'])?></td>
                            <td><?=number_format((int)$u['requests'])?></td>

                            <td>
                                <div class="actionRow">

                                    <?php if ((int)$u['id'] !== (int)$me['id']): ?>

                                        <form method="post">
                                            <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                                            <input type="hidden" name="user_id" value="<?=e((string)$u['id'])?>">

                                            <button class="btn <?=((int)$u['banned']===1)?'green':'red'?>" name="admin_toggle_user">
                                                <?=((int)$u['banned']===1)?'Unban':'Ban'?>
                                            </button>
                                        </form>

                                        <button
                                            class="btn gray"
                                            type="button"
                                            onclick="showReset(<?=e((string)$u['id'])?>,'<?=e((string)$u['username'])?>')">
                                            Reset Password
                                        </button>

                                        <form method="post" onsubmit="return confirm('Delete this user?')">
                                            <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                                            <input type="hidden" name="user_id" value="<?=e((string)$u['id'])?>">
                                            <button class="btn red" name="admin_delete_user">
                                                Delete
                                            </button>
                                        </form>

                                    <?php else: ?>

                                        <span class="badge">CURRENT ADMIN</span>

                                    <?php endif; ?>

                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </section>

        <!-- Reset-password modal -->
        <section class="card admin" id="resetBox" style="display:none">
            <h3>🔐 Reset User Password</h3>
            <p class="muted" id="resetUserName"></p>

            <form method="post">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                <input type="hidden" name="user_id" id="resetUserId">

                <label>New password</label>
                <div class="passWrap">
                    <input id="newUserPassword" type="password" name="new_password" minlength="6" required>
                    <button type="button" onclick="togglePass('newUserPassword',this)">Show</button>
                </div>

                <button class="btn green full" name="admin_reset_password">
                    Save New Password
                </button>
            </form>
        </section>

    <?php elseif ($tab === 'keys'): ?>

        <?php
        $allKeys = $db->query("
            SELECT k.*,u.username
            FROM api_keys k
            JOIN users u ON u.id=k.user_id
            ORDER BY k.id DESC
        ")->fetchAll();
        ?>

        <section class="card admin">
            <h3>🔑 All API Keys</h3>

            <div class="table">
                <table>
                    <tr>
                        <th>ID</th>
                        <th>USER</th>
                        <th>TYPE</th>
                        <th>KEY</th>
                        <th>EXPIRES</th>
                        <th>REQUESTS</th>
                        <th>STATUS</th>
                        <th>ACTION</th>
                    </tr>

                    <?php foreach ($allKeys as $k): ?>
                        <?php $expired = strtotime((string)$k['expires_at']) <= time(); ?>

                        <tr>
                            <td>#<?=e((string)$k['id'])?></td>
                            <td><?=e((string)$k['username'])?></td>
                            <td><?=e((string)$k['key_type'])?></td>
                            <td style="max-width:180px;white-space:normal;word-break:break-all;color:#00dda0">
                                <?=e((string)$k['api_key'])?>
                            </td>
                            <td><?=e((string)$k['expires_at'])?></td>
                            <td><?=number_format((int)$k['requests'])?></td>
                            <td>
                                <?php if ((int)$k['active']===1 && !$expired): ?>
                                    <span style="color:#55dfa9">ACTIVE</span>
                                <?php else: ?>
                                    <span style="color:#ff7188">OFF</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div class="actionRow">
                                    <form method="post">
                                        <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                                        <input type="hidden" name="key_id" value="<?=e((string)$k['id'])?>">
                                        <button class="btn gray" name="admin_toggle_key">
                                            <?=((int)$k['active']===1)?'Disable':'Enable'?>
                                        </button>
                                    </form>

                                    <form method="post" onsubmit="return confirm('Delete this key?')">
                                        <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                                        <input type="hidden" name="key_id" value="<?=e((string)$k['id'])?>">
                                        <button class="btn red" name="admin_delete_key">
                                            Delete
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </section>

    <?php elseif ($tab === 'projects'): ?>

        <?php
        $projectSlots = project_stats_for_admin();
        $slotOrder = [
            'PythonDateBase','PHPDateBase','HTMLDateBase',
            'PhoneLookupDateBase','DatabaseDateBase','CustomDateBase'
        ];
        ?>

        <section class="card admin">
            <h3>📊 Project Tracking DataBases</h3>
            <p class="muted">
                Data is grouped by the API key type. A Python key goes to
                <b>PythonDateBase</b>, PHP to <b>PHPDateBase</b>, and so on.
                Live users are users whose heartbeat was seen within the last 90 seconds.
            </p>
        </section>

        <?php foreach ($slotOrder as $slotName): ?>
            <?php
            $slot = $projectSlots[$slotName] ?? [
                'key_type' => '',
                'projects' => [],
                'requests' => 0,
                'users' => []
            ];
            ?>
            <section class="card admin">
                <h3>🗃️ <?=e($slotName)?></h3>

                <div class="stats">
                    <div class="stat">
                        <div class="statIcon">📁</div>
                        <div class="statName">PROJECTS</div>
                        <div class="statValue"><?=count($slot['projects'])?></div>
                    </div>
                    <div class="stat">
                        <div class="statIcon">👥</div>
                        <div class="statName">USERS</div>
                        <div class="statValue"><?=count($slot['users'])?></div>
                    </div>
                    <div class="stat">
                        <div class="statIcon">⚡</div>
                        <div class="statName">REQUESTS</div>
                        <div class="statValue"><?=number_format((int)$slot['requests'])?></div>
                    </div>
                </div>

                <?php if (!$slot['projects']): ?>
                    <div class="notice" style="margin-top:10px">
                        No project has sent tracking data to this slot yet.
                    </div>
                <?php else: ?>
                    <?php foreach ($slot['projects'] as $projectName => $project): ?>
                        <div class="channel" style="margin-top:10px">
                            <div>
                                <b><?=e((string)$projectName)?></b>
                                <div class="muted">
                                    Type: <?=e((string)$project['project_type'])?> ·
                                    Users: <?=count($project['users'])?> ·
                                    Live: <?=e((string)$project['live_users'])?> ·
                                    Requests: <?=number_format((int)$project['requests'])?>
                                </div>
                                <div class="muted">
                                    Last seen: <?=e((string)($project['last_seen'] ?? 'Never'))?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </section>
        <?php endforeach; ?>

        <section class="card admin">
            <h3>🔌 Heartbeat Endpoint</h3>
            <p class="muted">
                A client project should send a heartbeat with its API key,
                project name, project type and a non-sensitive unique user ID.
            </p>
            <pre style="white-space:pre-wrap;word-break:break-word">/?api=1&amp;action=heartbeat&amp;key=YOUR_KEY&amp;project=MyWebsite&amp;project_type=website&amp;user=USER_ID</pre>
        </section>

    <?php elseif ($tab === 'website'): ?>

        <section class="card admin">
            <h3>🌐 Website Control</h3>

            <form method="post">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">

                <label>
                    <input
                        type="checkbox"
                        name="maintenance"
                        style="width:auto;margin-right:7px"
                        <?=get_setting('maintenance')==='1'?'checked':''?>
                    >
                    Enable maintenance / close website
                </label>

                <label>Notice title</label>
                <input name="maintenance_title" value="<?=e(get_setting('maintenance_title'))?>">

                <label>Notice message</label>
                <textarea name="maintenance_message"><?=e(get_setting('maintenance_message'))?></textarea>

                <button class="btn green full" name="save_maintenance">
                    Save Website Control
                </button>
            </form>
        </section>

        <?php if (isset($_GET['updated'])): ?>
            <div class="notice" style="margin-bottom:10px">
                ✅ Website update installed successfully.
            </div>
        <?php elseif (isset($_GET['rolled_back'])): ?>
            <div class="notice" style="margin-bottom:10px">
                ↩️ Latest website backup restored successfully.
            </div>
        <?php endif; ?>

        <section class="card admin" id="website-updater-card">
            <h3>🚀 Website Updater</h3>
            <p class="muted">
                Upload a new <b>index.php</b> to replace the current website.
                A backup is created automatically before activation.
            </p>

            <form method="post" enctype="multipart/form-data" style="margin-top:12px">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                <input type="hidden" name="action" value="website_update_upload">

                <label>New Website PHP File</label>
                <input
                    type="file"
                    name="website_update_file"
                    accept=".php,application/x-php,text/php"
                    required
                >

                <button class="btn green" type="submit" style="margin-top:10px">
                    🚀 Validate & Install Update
                </button>
            </form>

            <div class="notice" style="margin-top:10px">
                <b>Safety:</b> the file is syntax-checked before activation.
                The current website is backed up first.
            </div>
            <div class="muted" style="margin-top:8px">
                Last update:
                <?=e(get_setting('last_update_at') ?: 'Never')?>
                <?php if (get_setting('last_update_backup') !== ''): ?>
                    · Backup: <?=e(get_setting('last_update_backup'))?>
                <?php endif; ?>
            </div>

            <form method="post" style="margin-top:10px"
                  onsubmit="return confirm('Rollback to the latest website backup?');">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                <input type="hidden" name="action" value="website_update_rollback">
                <button class="btn gray" type="submit">
                    ↩️ Rollback Latest Backup
                </button>
            </form>
        </section>

    <?php elseif ($tab === 'links'): ?>

        <section class="card admin">
            <h3>🔗 Footer / Channel Links</h3>
            <p class="muted">
                These links appear at the bottom of the main website.
            </p>

            <form method="post">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">

                <label>Link name</label>
                <input name="channel_name" placeholder="YouTube">

                <label>Full URL</label>
                <input name="channel_url" placeholder="https://example.com" type="url">

                <button class="btn green full" name="add_channel">
                    Add Link
                </button>
            </form>

            <?php foreach ($channels as $c): ?>
                <div class="channel">
                    <div>
                        <b><?=e((string)$c['name'])?></b>
                        <div class="muted"><?=e((string)$c['url'])?></div>
                    </div>

                    <form method="post">
                        <input type="hidden" name="csrf" value="<?=e(csrf())?>">
                        <input type="hidden" name="channel_id" value="<?=e((string)$c['id'])?>">
                        <button class="btn red" name="delete_channel">Delete</button>
                    </form>
                </div>
            <?php endforeach; ?>
        </section>

    <?php elseif ($tab === 'security'): ?>

        <section class="card admin">
            <h3>🔐 Admin Login</h3>
            <p class="muted">
                The stored password is hashed. It is not possible to safely display
                the old password from the database. You can change it here.
            </p>

            <form method="post">
                <input type="hidden" name="csrf" value="<?=e(csrf())?>">

                <label>Admin username</label>
                <input name="admin_username" value="<?=e(get_setting('admin_username'))?>" required>

                <label>New admin password</label>
                <div class="passWrap">
                    <input id="adminPassword" type="password" name="admin_password" minlength="6" required>
                    <button type="button" onclick="togglePass('adminPassword',this)">Show</button>
                </div>

                <button class="btn green full" name="change_admin_login">
                    Update Admin Login
                </button>
            </form>
        </section>

    <?php endif; ?>


<?php else: ?>

    <section class="card">
        <h2>Page not found</h2>
        <a class="btn" href="?">Back to Dashboard</a>
    </section>

<?php endif; ?>


<!-- FOOTER LINKS AT THE BOTTOM -->
<footer class="footer">

    <?php if ($channels): ?>
        <div class="footerLinks">
            <?php foreach ($channels as $c): ?>
                <a
                    href="<?=e((string)$c['url'])?>"
                    target="_blank"
                    rel="noopener noreferrer">
                    <?=e((string)$c['name'])?>
                </a>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <div>AXP BLAZE • <?=date('Y')?></div>
</footer>

</main>

<script>
function openMenu(){
    document.getElementById('side').classList.add('open');
}

function closeMenu(){
    document.getElementById('side').classList.remove('open');
}

function togglePass(id, button){
    const input = document.getElementById(id);

    if(!input) return;

    if(input.type === 'password'){
        input.type = 'text';
        button.textContent = 'Hide';
    }else{
        input.type = 'password';
        button.textContent = 'Show';
    }
}

function showReset(id, username){
    document.getElementById('resetBox').style.display = 'block';
    document.getElementById('resetUserId').value = id;
    document.getElementById('resetUserName').textContent =
        'Resetting password for: ' + username;

    document.getElementById('resetBox').scrollIntoView({
        behavior:'smooth',
        block:'center'
    });
}

async function testKey(){
    const key = document.getElementById('testerKey').value.trim();
    const result = document.getElementById('testerResult');

    result.style.display = 'block';
    result.textContent = 'Testing...';

    if(!key){
        result.textContent = 'Enter an API key first.';
        return;
    }

    try{
        const response = await fetch('?api=1&key=' + encodeURIComponent(key));
        const data = await response.json();
        result.textContent = JSON.stringify(data,null,2);
    }catch(error){
        result.textContent = 'Tester error: ' + error;
    }
}

/*
 First-open animation:
 it runs once per browser tab/session, not every menu/page navigation.
 If the user refreshes after the session flag exists, it is skipped.
*/
(function(){
    const splash = document.getElementById('splash');

    if(sessionStorage.getItem('axp_splash_seen') === '1'){
        splash.remove();
        return;
    }

    sessionStorage.setItem('axp_splash_seen','1');

    setTimeout(function(){
        splash.classList.add('splashOut');

        setTimeout(function(){
            splash.remove();
        },550);
    },1500);
})();
</script>


<script>
(function(){
    const p = new URLSearchParams(window.location.search);
    const marker = document.getElementById('admin-mode-marker');
    if(marker && p.get('admin') === '1') marker.style.display = 'block';
})();
</script>
</body>
</html>
