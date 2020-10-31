<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: access");
header("Access-Control-Allow-Methods: POST");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require __DIR__ . '/classes/Database.php';
require __DIR__ . '/middlewares/Auth.php';
require __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;


$allHeaders = getallheaders();
$db_connection = new Database();
$conn = $db_connection->dbConnection();
$auth = new Auth($conn, $allHeaders);

$returnData = [
    "success" => 0,
    "status" => 401,
    "message" => "Unauthorized"
];

$data = json_decode(file_get_contents("php://input"));

$email_accept  = trim($data->email);
$subject       = trim($data->subject);
$posting       = trim($data->posting);

if ($auth->isAuth()) {

    $returnData         = $auth->isAuth();
    $email_sending      = $returnData['user']['email']; // Fill in the sender's email
    $name_sending       = $returnData['user']['name']; // Fill in the name of the sender
    $emailAccept        = $email_accept; // Extract recipient email from json raw
    $subject_message    = $subject; // Extract recipient subject from json raw
    $message            = $posting; // Extract recipient posting from json raw

    $mail = new PHPMailer;
    $mail->isSMTP();
    $mail->Host = 'smtp.gmail.com';
    $mail->Username = $email_sending; // sender's email
    $mail->Password = 'your password send email'; // fill password email
    $mail->Port = 465;
    $mail->SMTPAuth = true;
    $mail->SMTPSecure = 'ssl';
    // $mail->SMTPDebug = 2; // debuging email
    $mail->setFrom($email_sending, $name_sending);
    $mail->addAddress($emailAccept, '');
    $mail->isHTML(true);

    ob_start();
    include "content.php";
    $content = ob_get_contents(); // variable on content.php
    ob_end_clean();

    $mail->Subject = $subject_message;
    $mail->Body = $content;
    $send = $mail->send();

    if ($send) {
        $insert_query = "INSERT INTO posting(name_sending,email_accept,body) VALUES(:name_sending,:emailAccept,:body)";

        $insert_stmt = $conn->prepare($insert_query);

        // DATA BINDING
        $insert_stmt->bindValue(':name_sending', $email_sending, PDO::PARAM_STR);
        $insert_stmt->bindValue(':emailAccept', $emailAccept, PDO::PARAM_STR);
        $insert_stmt->bindValue(':body', $message, PDO::PARAM_STR);

        $insert_stmt->execute();
        echo json_encode('email sending succesfull');
    } else {
        echo json_encode('email invalid');
    }
}
