-- One-time MySQL setup for RedGuardian (run as an admin user, e.g. root).
-- Replace CHANGE_ME with a password of your choice, then put the matching URL in .env:
--   MYSQL_URL=mysql+pymysql://redguardian:CHANGE_ME@localhost:3306/redguardian
-- Tables are created by the harness itself (storage.connect -> versioned init).

CREATE DATABASE IF NOT EXISTS redguardian CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS 'redguardian'@'localhost' IDENTIFIED BY 'CHANGE_ME';
-- Least privilege: only this schema, and only what the harness needs (no GRANT, no other databases).
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES ON redguardian.* TO 'redguardian'@'localhost';
FLUSH PRIVILEGES;
