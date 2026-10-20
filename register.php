<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Allow only POST
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    die("Invalid request");
}

// Connect DB
$conn = new mysqli("localhost", "root", "", "ksd");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// --- Helper functions ----------------------------------------------

function validatePhone($phone) {
    return preg_match('/^[0-9]{10}$/', $phone);
}

/**
 * Validate South African ID number
 * - Must be 13 digits
 * - Must pass Luhn checksum (last digit)
 */
function validateSAID($id) {
    // Remove any non-digit characters (spaces, hyphens, etc.)
    $id = preg_replace('/[^0-9]/', '', $id);
    
    // Check length
    if (strlen($id) !== 13) {
        return false;
    }
    
    // Extract birth date components
    $year = (int)substr($id, 0, 2);
    $month = (int)substr($id, 2, 2);
    $day = (int)substr($id, 4, 2);
    
    // Validate date
    $currentYear = (int)date('y');
    $fullYear = ($year <= $currentYear) ? 2000 + $year : 1900 + $year;
    
    // Check if date is valid
    if (!checkdate($month, $day, $fullYear)) {
        return false;
    }
    
    // Luhn algorithm for SA ID (South African ID checksum)
    $sum = 0;
    $alternate = false;
    
    // Process from right to left (excluding the last digit which is the check digit)
    for ($i = strlen($id) - 2; $i >= 0; $i--) {
        $digit = (int)$id[$i];
        
        if ($alternate) {
            $digit *= 2;
            if ($digit > 9) {
                $digit = ($digit % 10) + 1;
            }
        }
        $sum += $digit;
        $alternate = !$alternate;
    }
    
    // Calculate check digit
    $checkDigit = (10 - ($sum % 10)) % 10;
    $providedCheckDigit = (int)$id[12];
    
    return $checkDigit === $providedCheckDigit;
}

// --- Get and sanitize inputs ---------------------------------------
$name     = trim($_POST['name'] ?? '');
$lastname = trim($_POST['lastname'] ?? '');
$idnum    = trim($_POST['idnum'] ?? '');
$cellnum  = trim($_POST['cellnum'] ?? '');
$email    = trim($_POST['email'] ?? '');
$address  = trim($_POST['address'] ?? '');
$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';
$role     = $_POST['role'] ?? '';
$employee_number = trim($_POST['employee_number'] ?? '');

$errors = [];

// --- validation ----------------------------------------
if (empty($name) || !preg_match('/^[a-zA-Z\s\-]{2,50}$/', $name))
    $errors[] = "Invalid name (letters, spaces, hyphens, 2-50 chars).";

if (empty($lastname) || !preg_match('/^[a-zA-Z\s\-]{2,50}$/', $lastname))
    $errors[] = "Invalid last name.";

// Validate SA ID
if (!validateSAID($idnum))
    $errors[] = "Enter a valid 13-digit SA ID number (checksum validated).";

if (!validatePhone($cellnum))
    $errors[] = "Cell number must be 10 digits (e.g., 0821234567).";

if (!filter_var($email, FILTER_VALIDATE_EMAIL))
    $errors[] = "Invalid email address.";

if (empty($address))
    $errors[] = "Address is required.";

if (empty($username) || !preg_match('/^[a-zA-Z0-9_]{4,20}$/', $username))
    $errors[] = "Username must be 4-20 alphanumeric + underscore.";

if (strlen($password) < 8 || !preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password))
    $errors[] = "Password must be at least 8 chars with one uppercase and one number.";

if (!in_array($role, ['Applicant', 'Officer']))
    $errors[] = "Invalid role selection.";

if ($role === 'Officer') {
    if (empty($employee_number) || !preg_match('/^[A-Z0-9\-]{5,20}$/i', $employee_number))
        $errors[] = "Valid Employee Number required (letters, numbers, hyphens).";
}

// Check duplicates
if (empty($errors)) {
    $check = $conn->prepare("SELECT username, idnum, email FROM register WHERE username = ? OR idnum = ? OR email = ?");
    $check->bind_param("sss", $username, $idnum, $email);
    $check->execute();
    $check->store_result();
    if ($check->num_rows > 0) {
        $check->bind_result($u, $i, $e);
        $check->fetch();
        if ($u === $username) $errors[] = "Username already taken.";
        if ($i === $idnum) $errors[] = "Identity Number already registered.";
        if ($e === $email) $errors[] = "Email already used.";
    }
    $check->close();
}

// --- If errors, show them and stop --------------------------------
if (!empty($errors)) {
    echo "<ul style='color:red;'><li>" . implode("</li><li>", array_map('htmlspecialchars', $errors)) . "</li></ul>";
    echo "<a href='javascript:history.back()'>← Go back and fix errors</a>";
    exit;
}

// --- Store plain text password as requested --------------------------
$stmt = $conn->prepare("INSERT INTO register 
(name, lastname, idnum, cellnum, email, address, username, `password`, Type)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

if (!$stmt) {
    die("Prepare failed: " . $conn->error);
}

$stmt->bind_param("ssssssssss",
    $name,
    $lastname,
    $idnum,
    $cellnum,
    $email,
    $address,
    $username,
    $password,
    $role
  
);

// Execute
if ($stmt->execute()) {
    echo "<script>
        alert('Registration successful!');
        window.location.href = 'login.html';
    </script>";
} else {
    echo "Error: " . $stmt->error;
}

// Close
$stmt->close();
$conn->close();
?>