<?php

session_start();

class Database
{
    private static $pdo;

    public static function getConnection()
    {
        if (!self::$pdo) {
            $db_host = "localhost";
            $db_username = "root";
            $db_password = "";
            $db_name = "testdb";

            $dsn = "mysql:host={$db_host};dbname={$db_name}";

            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];

            try {
                self::$pdo = new PDO($dsn, $db_username, $db_password, $options);
            } catch (PDOException $e) {
                die("Database connection failed: " . $e->getMessage());
            }
        }

        return self::$pdo;
    }
}

class User
{
    public $id;
    public $email;
    public $password;

    public function __construct($email, $password)
    {
        $this->id = uniqid();
        $this->email = $email;
        $this->password = $password;
    }

    public function save()
    {
        $pdo = Database::getConnection();

        $query = "INSERT INTO users (id, email, password) VALUES (:id, :email, :password)";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(":id", $this->id);
        $stmt->bindParam(":email", $this->email);
        $stmt->bindParam(":password", $this->password);

        try {
            $stmt->execute();
        } catch (PDOException $e) {
            die("User save failed: " . $e->getMessage());
        }
    }

    public static function findByEmail($email)
    {
        $pdo = Database::getConnection();

        $query = "SELECT * FROM users WHERE email = :email";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(":email", $email);

        try {
            $stmt->execute();
            $user = $stmt->fetch();
            return $user;
        } catch (PDOException $e) {
            die("User retrieval failed: " . $e->getMessage());
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['action'])) {
    echo "Invalid request";
    exit;
}

if ($_POST['action'] === 'register') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    if (empty($email) || empty($password)) {
        echo "Email and password are required.";
        return;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format.";
        return;
    }

    if (strlen($password) < 6) {
        echo "Password must be at least 6 characters long.";
        return;
    }

    $existingUser = User::findByEmail($email);

    if ($existingUser) {
        echo "Email already exists. Please use a different email.";
        return;
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $user = new User(
        $email,
        $hashedPassword
    );

    try {
        $user->save();
        echo json_encode($user);
    } catch (PDOException $e) {
        echo "Registration failed: " . $e->getMessage();
    }
}

if ($_POST['action'] === 'login') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    if (empty($email) || empty($password)) {
        echo "Email and password are required.";
        return;
    }

    $user = User::findByEmail($email);

    if (!$user) {
        echo "Invalid email or password.";
        return;
    }

    try {
        $isPasswordMatched = password_verify($password, $user->password);

        if (!$isPasswordMatched) {
            echo "Invalid email or password.";
            return;
        }

        $_SESSION['user_id'] = $user->id;
        echo json_encode($user);
    } catch (PDOException $e) {
        echo "Login failed: " . $e->getMessage();
    }
}