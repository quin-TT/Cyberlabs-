[Forensics Report and Documentation](https://docs.google.com/open?id=1u0x02K5dywlJsIMtKK_AsTQpl087zk_yPNpTTvOEqqE)

Forensics Report and Documentation

Case 001 - The Stolen Schezuan Sauce

















Tools used:

FTK Imager 4.7.1: - make exact copies of files and data for investigation 

Registry Explorer v.2.0: helps look into Windows system settings to find unusual changes.

Volatility 3: examines a computer's memory to uncover suspicious activity.

Wireshark 4.4.0: checks internet and network activity to identify harmful data transfers.

Autopsy 4.21.0: for looking through computer files and find hidden/deleted information.

ApiVoid / VirusTotal: Websites that scan files,  internet addresses to see if they are safe

Cloudflare Radar: helps to understand online activity.

Event Viewer 1.0: tracks what happens on a computer(software issues or login attempts)

Cisco Packet Tracer: used to design computer networks





## Incident timeline

| Event | Time |
|----------|----------|
| RDP Brute-Force Attack | 2020-09-19 02:19:26 |
| Successful RDP Server login | 2020-09-19 02:21:47 |
| Data Exfiltration Started | 2020-09-19 02:21:47 |
| Malware Installed on Server | 2020.09.19 02:24:06 |
| Server Initiates RDP connection to desktop and spread malware | 2020-09-19 02:35:55 |
| Data exfiltration Finished | 2020-09-19 02:57:41 |




##  Executive Summary



On September 21, 2020, James Smith reported a cyberattack known as The Case of the Stolen Szechuan Sauce, where sensitive information was stolen.

The investigation found that both a Windows desktop and server were accessed by an attacker using a brute-force method to break into the system through Remote Desktop Protocol (RDP). After gaining access, the attacker stole data and installed harmful software on the systems.

This report explains how the investigation was conducted, outlines the timeline of events, and answers key questions about the cas









Methodology

For this investigation, my groupmate, Deka Farah, and I agreed to work independently but have shared  snippets of findings with one another. Additionally, I consulted with other student Rhemmy to gather further insights.

The digital artifacts for the investigation were provided by Lighthouse Labs and are available at: https://dfirmadness.com/the-stolen-szechuan-sauce/.

Screenshots were collected to support each response, and supplemental evidence was gathered in cases where corroboration was deemed necessary.

The evidence collection process for each question is documented, with  steps provided for  replicability.























### 1. Operating System(Server)



| Windows Server 2012 R2 Standard Evaluation is the operating system of the server found through the registry key path |
|----------|
| 
FTK: Server E01 fileGo to:Partition2/NONAME/root/Windows/System32/configExport SOFTWARE hive
Registry Explorer v.2.0-Import SOFTWARE hiveGo to:SOFTWARE\Microsoft\Windows NT\CurrentVersionWindows Server 2012 R2 Standard Evaluation |




























### 2. Operating System(Desktop)



| Windows 10 Enterprise Evaluation is the operating system of the desktop found through the registry key path.  |
|----------|
| 
In FTK:Desktop E01 fife
Basic data partition/NONAME/root/Windows/System32/config
Export SOFTWARE hive

Registry Explorer v.2.0-
Import Desktop SOFTWARE hive
Go to:
SOFTWARE\Microsoft\Windows NT\CurrentVersionWindows 10 Enterprise Evaluation |










### 3. Local time of the Server



| Pacific Standard Time is the server's system time found through the registry key path. |
|----------|
| 
FTK: E01 fifeGo to:Partition2/NONAME/root/Windows/System32/configExport SYSTEM hiveRegistry Explorer v.2.0-Import SYSTEM hiveGo to:SYSTEM \ControlSet001\TimeZoneInformation
Pacific Standard Time |






### 4.0 Breach - Simple text deduction





"FBI contacted him. They found his recently-developed Szechuan sauce recipe on the dark web."

Based on the case text extract above, the data was stolen,and a  breach has occurred.









### 4.1 Breach - Wireshark IoC analysis



A breach occurred when analysing IoC procedures in Wireshark(checks internet and network activity to identify harmful data transfers). It began with identifying devices through registry key paths, these IPs were cross-checked with details from an interview:

"May I have a network map where the affected systems were located?""Sure. All the systems were located in 10.42 .."

By analyzing network activity for signs of common attack methods, we identified key indicators of compromise (IoCs). To confirm the breach, we checked suspicious IP addresses and downloaded files on VirusTotal, which provided further evidence of unauthorized access. The investigation shows sequence of events: the attacker used brute force to gain access through remote desktop (RDP), then installed malware on the system



| Breach - Wireshark IoC analysis (Server IP) |
|----------|
| 
To find Server IPFTK:Export Server SYSTEM hiveRegistry Explorer:Import Server SYSTEM hiveGo to: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
Confirmed the IP addresses involved in the breach Server IP:  10.42.85.10 |






















| Breach - Wireshark IoC analysis (Desktop IP) |
|----------|
| 
To find Desktop IP
FTK:Export Server SYSTEM hiveRegistry Explorer:Import Server SYSTEM hiveSYSTEM\CurrentControlSet\Services\Tcpip\Parameters\InterfacesConfirmed the IP addresses involved in the breach Desktop IP: 10.42.85.115 |








5. Initial Entry vector



| Successful Server Compromise via RDP Brute-Force AttackEvidence of this entry vector is supported by Wireshark and Event Viewer. |
|----------|
| 
Based on 4.1At the conclusion of the RDP brute-force attack, Wireshark logs indicate a successful TLS handshake at 2020-09-19 02:21:47, followed by a significant exchange of application data between the attacker and the victim.
This activity confirms that the attacker not only established a connection but also gained the ability to transfer data to and from the victim's system
Number of events: 96. Consecutive failed logins

Workstation name as 'kali', Account name: AdministratorAll align with Brute force from an attacker

In FTK:Load E01 fileGo toPartition2/NONAME/root/Windows/System32/winevt/LogsExport Security.evtxIn Event Viewer:Open Security.evtxCreate a filter for Windows Event 4625 (Failed Logon)Windows Event IDs point to a logon bruteforce attack |






### 6.0 Malware used



| Based on 4.1 the malware used is identified as Metasploit by virustotal.com |
|----------|
| 

Using https://www.virustotal.com and apivoid identifies coreupdater.exe asa trojan (metasploit) https://github.com/rapid7/metasploit-framework |




### 

### 6.1 Malware process



| Using volatility, the malware process is identified as the parentless coreupdater.exe.This correlates with 4.1 and 6.0. The created time also matches the breach date. |
|----------|
| 
Volatility 3 Framework 2.5.2
PID	PPID	ImageFileName	Offset(V)	Threads	? CreateTime	                ExitTime
?
3644	2244	coreupdater.ex	0xe00062fe7700	2020-09-19 03:56:37?. 	2020-09-19 03:56:52?.

Wireshark:We know that the downloaded malware is named: coreupdater.exe

Volatility 3:
Command used:
py vol.py -f C:\...\DC01\DC01-memory\citadeldc01.mem windows.pstree
Coreupdater.exe from the observed wireshark download, is in memory as PID 3644.Suspiciously, its parent is not listed in the tree

To analyze the system's memory, we identified a suspicious file named coreupdater.exe that was previously observed being downloaded over the network. This file was found actively running on the system, but its origin or the program that started it could not be directly traced, which we found malicious
 |


















### 6.2 IP address that delivered malware payload



| Based on 4.1 flagged IP 194.61.24.102 delivered the malware payload at 02:24:06 |
|----------|
| 
Wireshark:display filter: ip.src == 194.61.24.102 and httpAttacker IP 194.61.24.102, responds with MIME type application/x-msdos-program to both Local IPs.

This confirms that the payload delivery originated from the attacker?s IP 194.61.24.102 |








### 6.3 IP address called by malware.



| Netscan Analysis: Coreupdater Malware Connects to Malicious IP 203.78.103.109. This IP is flagged as malicious by virustotal.com |
|----------|
| 
Volatility 3:Command chain:py vol.py -f C:\Users\student\Desktop\ForensicsProject\DC01\DC01-memory\citadeldc01.mem windows.netscan | Select-String "coreupdater"
The Netscan memory dump analysis reveals that the malware, coreupdater.exe (PID 3644), established communication with IP address 203.78.103.109 over port 443. This confirms that the malware was actively reaching out to the identified malicious IP

IP  203.78.103.109 is flagged as malicious(cross-referenced in Virustotal) |








### 6.4  Malware location on Disk



| Malware was found at Windows\System32\coreupdater.exe for both server and desktop. |
|----------|
| 


For the ServerFTK:C:\Windows\System32\coreupdater.exe

By looking into a key system folder, file named coreupdater.exe which had already been flagged as potentially harmful and has been revealed that this file had originally been downloaded but was later moved to a system folder typically used for legitimate files, likely to hide it and avoid detection. It shows where the malicious file was placed and how it was disguised to blend in with essential system files.


For the DesktopFTK:C:\Windows\System32\coreupdater.exe

Coreupdater.exe, was also found on the desktop system. Similar to the server, it was hidden within the System32 |










### 6.5 First appearance of malware



| Based on findings from Wireshark (4.1) and Autopsy (6.2), the following timeline has been established for the malware activity |
|----------|
| 

Wireshark Analysis:malware was delivered to the victim system on September 19, 2020, at 02:24:06
Autopsy Analysis:malware's last modification time was recorded as September 19, 2020, at 20:24:06

Additionally, the analysis also shows that the malware was originally created on September 18, 2020, at 8:24:12 PM, which is about 24 hours earlier than its delivery and modification. This timing difference suggests that the malware may have been created or prepared before being sent to the victim

Autopsy:Server .E01 fileC:\Windows\System32\coreupdater.exe.Select coreupdater.exe

On Server Date Created: 9/18/2020 20:24:12On Server Date Modified: 9/19/2020 20:24:06 |










### 6.6 Malware file movement



| Using Autopsy on the server .E01 file, malware was originally in:C:\Users\Administrator\Downloads\coreupdater.exe.The file was finally moved into:C:\Windows\System32\coreupdater.exe(6.4) |
|----------|
| Autopsy: Server .E01 file C:\Windows\System32\coreupdater.exe.File went through indexingUse the Keyword search, search for: coreupdater.exeSelect the V01.log file

Highlighted output, we find the file was originally in:C:\Users\Administrator\Downloads\coreupdater.exe |










### 6.7 Malware capabilities

The Metasploit Framework is an important tool to consider in this case because it can perform many of the same actions seen in the attack. These include breaking into systems, planting malicious software, scanning networks for weaknesses, gaining higher access levels, staying hidden, and collecting sensitive information.

As described by Rapid7:"The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code. The Metasploit Framework contains a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection. At its core, the Metasploit Framework is a collection of commonly used tools that provide a complete environment for penetration testing and exploit development." (Rapid7, n.d.)





### 6.8 Malware is part of metasploit



| Malware Identified as Metasploit Open Source Project (based on 6.0) |
|----------|
| 
Image: Metasploit on Github.
Based on 6.0The malware is a Trojan named Metasploit, an open source project: https://github.com/rapid7/metasploit-frameworkThe malware is easily obtained. |
































6.9 Malware persistence





| Malware Persistence Confirmed in System32 with DelayedAutostart Enabled |
|----------|
| 
Registry Explorer:Import .E01 filePath: C:\Windows\System32\coreupdater.exe
Last write timestamp: 2020-09-19 03:27:49DelayedAutostart : 1
The malware was located in C:\Windows\System32 (DelayedAutostart) parameter set to 1. It is a settings that allow it to start automatically after the computer boots up, but with a slight delay. This delay helps it avoid being noticed and allows it to stay active on the system
Further analysis using Autoruns is recommended to confirm this behavior and check if it is set to run whenever the computer starts. |










7.0 Malicious IPs involved



Evidence confirms involvement of attacker IP 194.61.24.102 and adversary C2 server 203.78.103.109:

- Initial Attacker IP: 194.61.24.102 (Based on 4.0)
- Malware Call IP: 203.78.103.109 (Based on 6.3)
Both IPs are flagged as malicious by VirusTotal.

### 

### 7.1 Adversary infrastructure

Analysis of Attacker and Malware-Associated IPs

The main attacker IP address (194.61.24.102) is linked to an automated system based in Russia. All the activity from this system is generated by bots, with no signs of direct human involvement.

The IP address contacted by the malware (203.78.103.109) is connected to a system in Thailand. Most of the traffic from this IP is also bot-driven, but about 8.3% of its activity shows signs of human interaction, suggesting some level of manual control or oversight



|  IP 194.61.24.102 |  IP 203.78.103.109 |
|----------|----------|
| Go to: https://radar.cloudflare.com/ip/194.61.24.102Related system: https://radar.cloudflare.com/traffic/as41842 | Go to https://radar.cloudflare.com/ip/203.78.103.109Related system: https://radar.cloudflare.com/traffic/as18362 |
| Find the following data:AS: AS41842BGP: MEDIAL-ASGeolocation: Russian FederationBot: 100.0%Human: 0.0% | Find the following data:AS: AS18362BGP: NETWAY-AS-AP ? Netway Communication Co.,Ltd.Geolocation: ThailandBot: 91.7%
Human: 8.3% |






### 

### 7.2 Adversary history

Attacker and Adversary IP Analysis

The investigation revealed that the attacker?s IP address, 194.61.24.102, has a history of being involved in brute-force attacks. According to CleanTalk, this IP has been flagged for spam and attacking over 110 websites, with activity reported between July 2019 and October 2020. This suggests it has been used in similar malicious activities before.

In contrast, the IP address 203.78.103.109, associated with the adversary, does not show any abuse history related to the timeframe of this case..For information on 194.61.24.10(https://cleantalk.org/blacklists/194.61.24.102)



### 

### 8.0 Attacker accessed Desktop from the Server





| Compromised Server IP Connected to Desktop IP via RDP on 2020-09-19 02:35:55; Additional Evidence Available in Desktop Security.evtx |
|----------|
| 

Wireshark:Display filter:
ip.addr == 10.42.85.115 and ip.addr == 10.42.85.10 and rdpUnusual network activity between the compromised server (IP: 10.42.85.115) and the desktop computer (IP: 10.42.85.10) through a remote desktop connection (RDP). This connection occurred on September 19, 2020, at 02:35:55. The network capture file (.pcap) showed only this single RDP connection during the breach period, which is highly suspicious |






### 8.1 Data Exfiltration

Analysis of a file called 'The Case of the Szechuan Sauce.txt' and its modification time strongly indicates that the recipe was stolen. Afterward, the attacker deliberately deleted important system files, including user-related data and others, to damage the system and cover their tracks.

The stolen data was sent through a secure, encrypted connection (TLS1.2) to the attacker?s known IP address. This likely happened shortly after the attacker gained remote access to the system through a login on September 19, 2020, at 2:21:47.



| Stolen and accessed data.
"They found his recently-developed Szechuan sauce recipe on the dark web"-- interview case information |
|----------|
| 
Autopsy:The Szechuan Sauce.txt(last modified on 2020-09-18 18:38:5) aligns the breach date when time adjusted

Autopsy, Server .E01 fileGo to Deleted FilesLooking at the deleted file, we can see modified times of 2020-09-18+ and 0000-00-00.The NTUSER.DAT.LOG.1 registry was deleted along with several others.The modified times also indicate that the attacker scrambled the time in order to hinder forensic analysis

Wireshark:Display filter: ip.dst == 194.61.24.102 and tls.record.content_type == 23Based on 5 following the time after RDP logon success.
tls.record.content_type == 23 means the packet is carrying encrypted application data.This filter shows 17663 application data packets were identified as being sent to the known attacker IP. This significant volume of encrypted traffic strongly suggests data exfiltration.  |






### 































### 9. Victim network layout





| Based on evidence 1 and 2, the machine subnets are 255.255.255.0 or /24. |
|----------|
| 
Based on evidence 1 and 2, the machine subnets are 255.255.255.0 or /24
This diagram shows a simple network setup with a PC (10.42.85.115), a Server (10.42.85.10), and a Router (10.42.85.1) connecting them to the internet. All devices are part of the same network (10.42.85.0/24). The attacker used this network layout to access the server and PC |


## 

## 

## 

## 











## 10. Reference/s

Fellinger, A., & Fellinger, K. (2024, August 27). Forensic report and documentation: The stolen Szechuan sauce.

Ndirangu, G. (2019, March 22). [Redacted] v. [Redacted] Sungundi: Digital forensics report. Retrieved December 16, 2024, from https://online.fliphtml5.com/rllbc/zdmn/#p=1Ovia, P. (2024). Forensic report and documentation: Stolen Szechuan sauce: Case no. sss1.



Pearson, A. (2021, May 10). Volatility 3 cheat sheet: Comparing commands from Vol2 > Vol3. https://blog.onfvp.com/post/volatility-cheatsheet/

Smith, J. (2020, September 21). The case of the stolen Szechuan sauce. DFIR Madness. Retrieved December 16, 2024, from https://dfirmadness.com/the-stolen-szechuan-sauce/



Rapid7. (n.d.). Metasploit framework overview. Rapid7. December 16, 2024, from https://docs.rapid7.com/metasploit/msf-overview



CleanTalk. (n.d.). CleanTalk. Retrieved December 16, 2024, from https://cleantalk.org/Cloudflare Radar. (n.d.). Cloudflare Radar. Retrieved December 16, 2024, from https://radar.cloudflare.com/



Starting a new digital forensic investigation case in Autopsy 4.19+ [Video]. (2022, February 8). YouTube. https://www.youtube.com/watch?v=fEqx0MeCCHg

Windows Geek. (2023, January 27). How to use Event Viewer [Video]. YouTube. https://www.youtube.com/watch?v=kd05aM5BwW8

A guide to digital forensics and cybersecurity tools. Forensics Colleges. (2022, May 19). https://www.forensicscolleges.com/blog/resources/guide-digital-forensics-tools

Cris. (n.d.). The case of the missing Szechuan sauce: Investigation notes. DEV Community. Retrieved December 16, 2024, from https://dev.to/evilcel3ri/the-case-of-the-missing-szechuan-sauce-investigation-notes-1di7

OpenAI. (2024). ChatGPT (Version 4) [Large language model]. https://www.openai.com/chatgpt







