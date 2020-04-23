# OSCP Cheatsheet

## Table of contents
* <a href="#privilege-escalation">[Privilege escalation](#privilege-escalation)</a>
  * [Linux](#linux)
  * [Windows](#windows)
* ![Miscellaneous](#Miscellaneous)
  * ![Windows](#Windows)
* ![Simple Buffer Overflow](#Simple-Buffer-Overflow)
* [Buffer Overflow](#buffer-overflow)

Useful sources with links

### Windows check architecture
```
wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%
```


## Privilege Escalation[⤴](#table-of-contents)
### Linux
* https://gtfobins.github.io/#+non-interactive%20bind%20shell
* https://book.hacktricks.xyz/linux-unix/privilege-escalation
* https://guif.re/linuxeop
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
* https://www.win.tue.nl/~aeb/linux/hh/hh-8.html
* http://www.dankalia.com/tutor/01005/0100501004.htm
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
* 
### Linux 

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


