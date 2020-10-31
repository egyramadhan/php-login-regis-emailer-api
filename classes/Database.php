<?php
class Database
{

    // CHANGE THE DB INFO ACCORDING TO YOUR DATABASE
    private $db_host = 'localhost';
    private $db_name = 'emailsend';
    private $db_username = 'postgres';
    private $db_password = 'root';
    private $port       =  '5432';

    public function dbConnection()
    {

        try {
            $conn = new PDO('pgsql:host=' . $this->db_host . ';dbname=' . $this->db_name, $this->db_username, $this->db_password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $conn;
        } catch (PDOException $e) {
            echo "Connection error " . $e->getMessage();
            exit;
        }
    }
}
