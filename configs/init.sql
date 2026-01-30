-- Create database
CREATE DATABASE IF NOT EXISTS cyberforce;

-- Use database
USE cyberforce;

-- Create table
CREATE TABLE IF NOT EXISTS supersecret (
    id INT AUTO_INCREMENT PRIMARY KEY,
    data INT
);

-- Insert data (Value 7)
INSERT INTO supersecret (data) VALUES (7);

-- Create user and grant permissions
-- Note: Allowing access from any host (%) for scoring engine
CREATE USER IF NOT EXISTS 'scoring-sql'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON cyberforce.* TO 'scoring-sql'@'%';
FLUSH PRIVILEGES;
