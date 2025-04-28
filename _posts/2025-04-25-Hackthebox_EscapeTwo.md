---
title: "EscapeTwo - Active Directory Machine HTB"
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
_The rest of the writeup will be available since the machine is still active_
