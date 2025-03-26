<?php

$servername = "localhost";  
$username = "root";         
$password = "";             
$dbname = "users1db";       

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    $input_username = $_POST['username'];
    $input_password = $_POST['password'];

    $sql = "SELECT id, username, password FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $input_username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $username, $hashed_password);
        $stmt->fetch();

        if (password_verify($input_password, $hashed_password)) {
            // Start the session and store session variables if needed
            session_start();
            $_SESSION['user_id'] = $id;
            $_SESSION['username'] = $username;

            // Redirect to the dashboard or next page
            header("Location: dashboard.php");
            exit();  // Important to terminate the script after redirection
        } else {
            echo "Invalid username or password!";
        }
    } else {
        echo "Invalid username or password!";
    }

    $stmt->close();
    $conn->close();
}
?>
