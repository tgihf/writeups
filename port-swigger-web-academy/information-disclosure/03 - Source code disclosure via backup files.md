# [Lab 3: Source code disclosure via backup files](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files)

---

## Description

This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.

---

## Solution

The leaked source code is in a hidden directory. Use `gobuster` to discovery the hidden directory.

```bash
$ gobuster dir -u https://ac5a1fcc1f198a5780ed87c700c400ce.web-security-academy.net -w /usr/share/wordlists/raft-small-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://ac5a1fcc1f198a5780ed87c700c400ce.web-security-academy.net
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/07 16:00:56 Starting gobuster in directory enumeration mode
===============================================================
/backup               (Status: 200) [Size: 435]
/product              (Status: 400) [Size: 30]
```

`/product?productId=$PRODUCT_ID` renders each product. Navigate to `/backup`.

![](images/Pasted%20image%2020210907160255.png)

It contains a file named `ProductTemplate.java.bak`, which appears to be a backup file of some Java source code.

```java
package data.productcatalog;

import common.db.ConnectionBuilder;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();

        ConnectionBuilder connectionBuilder = ConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "8g3ugbhhjqtrq2nofor9to90rgl1s9zj"
        ).withAutoCommit();
        try
        {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (!resultSet.next())
            {
                return;
            }
            product = Product.from(resultSet);
        }
        catch (SQLException e)
        {
            throw new IOException(e);
        }
    }

    public String getId()
    {
        return id;
    }

    public Product getProduct()
    {
        return product;
    }
}
```

The database password appears to be `8g3ugbhhjqtrq2nofor9to90rgl1s9zj`. Submit it to complete the challenge.
