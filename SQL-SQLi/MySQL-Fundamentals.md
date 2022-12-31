# MySQL Fundamentals
https://academy.hackthebox.com/module/33/section/183

- Login
```bash
mysql -u root -p <password>
```

- Create Database
```sql
CREATE DATABASE users;
SHOW DATABASES;
USE users;
```

## Tables
List of MySQL datatypes: https://dev.mysql.com/doc/refman/8.0/en/data-types.html

- Create Tables
```sql
CREATE TABLE logins (
	id INT,
	username VARCHAR(100),
	password VARCHAR(100),
	date_joined DATETIME
	);

SHOW TABLES;
DESCRIBE logins;
```

## Table Properties

- Setting up the "id" column to auto-increment with every new user added.
```sql
id INT NOT NULL AUTO_INCREMENT, --Makes "id" a required field, then auto-increments.
username VARCHAR(100) UNIQUE NOT NULL, --Unique forces uniqe names. No copies.
date_joined DATETIME DEFAULT NOW(), --Setting "default", time-of-insertion.
PRIMARY KEY (id) --Which column should be used in order to identify the object.
```
These can be appended to our function.

## INSERT Statements

- Add new records to the table.
```sql
INSERT INTO logins VALUES (1, admin, password, '12-31-2022'); --OR APPEND
INSERT INTO logins(username, password) VALUES ('admin', 'password123!');
```

## SELECT Statements

- Enumeration
```sql
SELECT * FROM table_name; --Select all columns
SELECT column1, column2 FROM table_name; --Select specific columns
```

## DROP Statement

- Removing tables and databases from the server
```sql
DROP TABLE logins;
SHOW TABLES;
```

## ALTER Statement

- Add a new column to the logins table.
```sql
ALTER TABLE logins ADD NewColumnName INT; --Adding the new column w/ datatype.
ALTER TABLE logins RENAME COLUMN NewColumnName TO OldColumn; --Renaming column.
ALTER TABLE logins MODIFY oldColumn DATE; --Changing the columns datatype.
ALTER TABLE logins DROP oldColumn; --Delete the column.
```

## UPDATE Statement

- Changing Table Properties, updating specific records within the table
```sql
UPDATE logins SET password = 'default_password' WHERE id > 1; 
--Updating id's 2 thru n's password in bulk.
```

## Sorting Results

- We can sort the results of any query using ORDER BY and specifying column.
```sql
SELECT * FROM logins ORDER BY password; --sorts by passwords, alphabetically
SELECT * FROM logins ORDER BY password DESC; --sorts descending order. Also ASC!
SELECT * FROM logins ORDER BY password DESC, id ASC; --sort colmns seperate to check duplicates.
```

## LIMIT Results
```sql
SELECT * FROM logins LIMIT 2; --Select first two.
SELECT * FROM logins LIMIT 1, 2; --Offset the first, selecting next 2.
```

## WHERE Clause

- Conditional Statements
```sql
SELECT * FROM logins WHERE id > 1;
SELECT * FROM logins WHERE username = 'admin';
```

## LIKE Clause

- Conditional Statements
```sql
SELECT * FROM logins WHERE username LIKE 'admin%'; --both 'admin' and 'administrator'
SELECT * FROM logins WHERE username LIKE '______'; --match names with exactly 6 chars.
```

# SQL Operators

## AND Operator

- AND returns true only if condition1 and condition2 are met.
```sql
SELECT 1 = 1 AND 'test' = 'test';
1

SELECT 1 = 1 AND 'test' = 'abcdefg';
0
```

## OR Operator

- OR returns true if either condition is met.
```sql
SELECT 1 = 1 OR 'test' = 'abcdefg'
1
```

## NOT Operator

- NOT returns if the opposite is true, similar to !=
```sql
SELECT NOT 1 = 1;
0

SELECT NOT 1 = 2;
1
```

Regular symbol operators can be used such as && || and !
