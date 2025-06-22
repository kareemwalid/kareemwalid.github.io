---
title: "My Hacking Diaries"
date: 1337-01-01 00:00:00 
categories: [Hack The Box,Notes]
tags: [HTB,CTFs,Notes]
---
## Init 0x01
![](../whoami.png)


Welcome to **My Hacking Diaries**.  
This is where I write down every note, trick, or idea I come across while learning and practicing offensive security. 
Some notes might come from **CTF** machines, bug bounty hunting, enumeration tips, privilege escalation tricks, or reverse engineering challenges. 
Others might be things I learn from programming, scripting, or random CTF problems. 
I’m mainly writing these for myself because I forget things quickly but I also hope they’ll help beginners, or anyone stuck and needing a hint. At the end of the day, everything here is part of the bigger journey in hacking and offensive security.

---

## Hacking Notes  
**_Date : 27/04/2025_**

- **Subdomain fuzzing**
```bash
ffuf -u http://test.com/ -w ./fuzzDicts/subdomainDicts/main.txt -H "Host:FUZZ.test.com"  -mc 200
```

- Always add any subdomain to /etc/hosts file in order to be able to open it duuh
- remember always `etc/passwd` contain information about the users like this 

- **config file** for ruby on rails most of the time can be found at 
```bash
../../config/database.yml
```
- you can break **bcrypt hash** using this command with hashcat
```bash
hashcat -m 3200 hash.txt wordlist.txt
```
- if you got shell on webserver using any website and the user is www-data to transition to bash you can use python 
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
```
- port forwarding using ssh 

```bash
ssh -L 8500:127.0.0.1:8500 messi@test.com 
```

_`-L`: This flag specifies local port forwarding. It means that you'll forward a local port (on your local machine) to a port on the remote machine._

_<span style="color:red;">8500</span>:<span style="color:green;">127.0.0.1</span>:<span style="color:blue;">8500</span>: This is the actual port forwarding configuration._

_<span style="color:red;">8500</span>: The local port on your machine. When you access localhost:8500 on your computer, the connection will be forwarded to the remote machine._

_<span style="color:green;">127.0.0.1</span>: The address on the remote machine (the loopback address, often referred to as localhost)._

_<span style="color:blue;">8500</span>: The port on the remote machine that you want to forward the local connection to. In this case, it's port 8500 on the remote machine._

- **[LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)** is a script that search for possible paths to escalate privileges on Linux/Unix*/MacOS hosts. The checks are explained on [book.hacktricks.wiki](https://book.hacktricks.wiki)


# Directories Brute force using different tools :
using Gobuster : 
```bash
gobuster dir http://test.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,asp,aspx,html
```

you can use this to internal scan 
```bash
ss -tuln
```
