<?php
// Session security settings
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_samesite', 'Lax');
session_start();
session_regenerate_id(true); // Prevent session fixation

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Only allow POST
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    die("Invalid request");
}

// Connect to DB
$conn = new mysqli("localhost", "root", "", "ksd");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// =============================================
// CHECK AND CREATE REQUIRED TABLES IF NOT EXISTS
// =============================================

// 1. Check/Create settings table
$tableCheck = $conn->query("SHOW TABLES LIKE 'settings'");
if ($tableCheck->num_rows == 0) {
    $conn->query("CREATE TABLE settings (
        id INT(11) AUTO_INCREMENT PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value VARCHAR(255) NOT NULL,
        description TEXT
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    
    // Insert default settings
    $conn->query("INSERT INTO settings (setting_key, setting_value, description) VALUES
        ('failed_login_attempts', '5', 'Maximum number of failed login attempts before temporary lockout'),
        ('enable_audit_log', '1', 'Enable or disable audit logging (1=on, 0=off)'),
        ('session_timeout_minutes', '30', 'Session timeout duration in minutes')");
}

// 2. Check/Create audit_log table
$tableCheck = $conn->query("SHOW TABLES LIKE 'audit_log'");
if ($tableCheck->num_rows == 0) {
    $conn->query("CREATE TABLE audit_log (
        id INT(11) AUTO_INCREMENT PRIMARY KEY,
        user_id INT(11) NULL,
        username VARCHAR(100) NOT NULL,
        action VARCHAR(50) NOT NULL,
        details TEXT,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_id),
        INDEX idx_username (username),
        INDEX idx_action (action),
        INDEX idx_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// 3. Check/Create login_attempts table
$tableCheck = $conn->query("SHOW TABLES LIKE 'login_attempts'");
if ($tableCheck->num_rows == 0) {
    $conn->query("CREATE TABLE login_attempts (
        id INT(11) AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username (username),
        INDEX idx_time (attempt_time)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// =============================================
// 1. GET LOGIN INPUT
// =============================================
$username = trim($_POST['username'] ?? '');
$password = trim($_POST['password'] ?? '');
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// =============================================
// 2. LOAD SECURITY SETTINGS
// =============================================
$settings = [];
$result = $conn->query("SELECT setting_key, setting_value FROM settings");
while ($row = $result->fetch_assoc()) {
    $settings[$row['setting_key']] = $row['setting_value'];
}
$max_attempts = (int)($settings['failed_login_attempts'] ?? 5);
$audit_enabled = ($settings['enable_audit_log'] ?? '1') == '1';
$timeout_minutes = (int)($settings['session_timeout_minutes'] ?? 30);

// =============================================
// 3. CHECK FAILED ATTEMPTS (last 15 minutes)
// =============================================
$stmt = $conn->prepare("SELECT COUNT(*) AS cnt FROM login_attempts WHERE username = ? AND attempt_time > NOW() - INTERVAL 15 MINUTE");
$stmt->bind_param("s", $username);
$stmt->execute();
$attemptResult = $stmt->get_result();
$attempts = $attemptResult->fetch_assoc()['cnt'] ?? 0;
$stmt->close();

if ($attempts >= $max_attempts) {
    // Too many attempts – block login
    echo "<script>
        alert('Too many failed login attempts. Please wait 15 minutes before trying again.');
        window.location.href = 'login.html';
    </script>";
    exit();
}

// =============================================
// 4. CHECK USER CREDENTIALS
// =============================================
// Add 'type' column to the SELECT query
$stmt = $conn->prepare("SELECT regid, username, password, department, type FROM register WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();
    $isValidPassword = ($password === $user['password'] || password_verify($password, $user['password']));

    if ($isValidPassword) {
        // ------------------------------
        //  SUCCESSFUL LOGIN
        // ------------------------------
        // Clear previous failed attempts
        $stmtDelete = $conn->prepare("DELETE FROM login_attempts WHERE username = ?");
        $stmtDelete->bind_param("s", $username);
        $stmtDelete->execute();
        $stmtDelete->close();

        // Set session with additional security data
        $_SESSION['regid'] = $user['regid'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['department'] = $user['department'];
        $_SESSION['user_type'] = $user['type'] ?? 'User';
        $_SESSION['logged_in'] = true;
        $_SESSION['last_activity'] = time();
        $_SESSION['ip_address'] = $ip;
        $_SESSION['user_agent'] = $user_agent;

        // Log the action (if audit log enabled)
        if ($audit_enabled) {
            $action = "Login";
            $details = "User $username logged in successfully from IP $ip";
            $stmtLog = $conn->prepare("INSERT INTO audit_log (user_id, username, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)");
            $stmtLog->bind_param("isssss", $user['regid'], $username, $action, $details, $ip, $user_agent);
            $stmtLog->execute();
            $stmtLog->close();
        }

        // Redirect based on role
        switch ($user['department']) {
            case 'Business':
                $redirectPage = 'welcome_m.php';
                break;
            case 'Admin':
                $redirectPage = 'admin_dashboard.php';
                break;
            case 'Fire':
                $redirectPage = 'fire_dashboard.php';
                break;
            default:
                $redirectPage = 'welcome_a.html';
                break;
        }

        // FIXED: Correct variable name
        $safeUsername = json_encode($username);
        $safeType = json_encode($_SESSION['user_type'] ?? 'User'); // FIXED: was user_Type
        $safeRedirect = json_encode($redirectPage);

        echo "<script>
            alert('Welcome back, ' + $safeUsername + '!\\n\\nYou have successfully logged in as ' + $safeType + '.\\n\\nRedirecting to your dashboard...');
            window.location.href = $safeRedirect;
        </script>";
        exit();
    } else {
        // ------------------------------
        //  FAILED LOGIN – wrong password
        // ------------------------------
        // Insert failed attempt
        $stmtFail = $conn->prepare("INSERT INTO login_attempts (username, ip_address) VALUES (?, ?)");
        $stmtFail->bind_param("ss", $username, $ip);
        $stmtFail->execute();
        $stmtFail->close();

        // Log the failure (if audit enabled)
        if ($audit_enabled) {
            $action = "Failed Login";
            $details = "Failed login attempt for $username from IP $ip";
            $stmtLog = $conn->prepare("INSERT INTO audit_log (user_id, username, action, details, ip_address, user_agent) VALUES (NULL, ?, ?, ?, ?, ?)");
            $stmtLog->bind_param("sssss", $username, $action, $details, $ip, $user_agent);
            $stmtLog->execute();
            $stmtLog->close();
        }

        // Alert user
        echo "<script>
            alert('Incorrect password!\\n\\nPlease check your password and try again.');
            window.location.href = 'login.html';
        </script>";
        exit();
    }
} else {
    // ------------------------------
    //  USER NOT FOUND
    // ------------------------------
    // Optionally log unknown username attempts (optional)
    if ($audit_enabled) {
        $action = "Failed Login";
        $details = "Attempted login with unknown username: $username from IP $ip";
        $stmtLog = $conn->prepare("INSERT INTO audit_log (user_id, username, action, details, ip_address, user_agent) VALUES (NULL, ?, ?, ?, ?, ?)");
        $stmtLog->bind_param("sssss", $username, $action, $details, $ip, $user_agent);
        $stmtLog->execute();
        $stmtLog->close();
    }

    echo "<script>
        alert('User not found!\\n\\nPlease check your username or register for an account.');
        window.location.href = 'login.html';
    </script>";
    exit();
}

$stmt->close();
$conn->close();
?>