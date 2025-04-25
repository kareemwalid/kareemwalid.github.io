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

### 🛠️ Command:

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
so let's try to use it to login with it 
we can use this command we will use impacket tool
```bash
impacket-mssqlclient escapetwo.htb/sa:'MSSQLP@ssw0rd!'@10.10.11.51
```