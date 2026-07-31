-- PRISEC IV prototype — database bootstrap script
-- Run this once per machine (see README.md) to create the database and app user.
--
-- Usage (from a terminal in ./prototype/backend with the mysql client on PATH):
--   mysql -u root -p < init.sql
--
-- You will be prompted for your MySQL root password.
-- Feel free to change the password below before running this — just keep it
-- in sync with the DB_PASSWORD value in your backend/.env file.

CREATE DATABASE IF NOT EXISTS prisec_iv
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- '%' allows the user to connect from any host (localhost, 127.0.0.1, another
-- machine on the network). Restrict this to '127.0.0.1' or 'localhost' if you
-- only ever connect from the same machine running MySQL.
CREATE USER IF NOT EXISTS 'prisec_user'@'%' IDENTIFIED BY '123';

GRANT ALL PRIVILEGES ON prisec_iv.* TO 'prisec_user'@'%';

FLUSH PRIVILEGES;

-- Note: table creation is handled automatically by the FastAPI backend
-- (SQLAlchemy's Base.metadata.create_all) the first time it starts up.
-- You do not need to create tables manually here.