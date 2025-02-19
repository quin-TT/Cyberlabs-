[? Cat Scan Big Dog](https://docs.google.com/open?id=1mD8U2hEAbvuKhsg9vYQgGvciff1npq8qRwdeFaT2gh0)

Security Assessment Report

CAT SCAN BIG DOG II







Executive Summary

This report outlines a prioritized security monitoring solution to enhance Big Dog?s security posture. Emphasis is placed on protecting classified data, minimizing downtime, and detecting unauthorized access. The strategy focuses on assets classified under Privacy, Proprietary, and Security Management (SM), Finance, Administration and Systems and includes recommendations aligned with the MITRE ATT&CK, NIST RMF, and PRTG frameworks.



### 1. Introduction

Background

Big Dog Corporation?s network supports sensitive information requiring industry-standard security measures. The organization?s assets contain Privacy,Proprietary, Administration,Finance and Security management data that must be safeguarded against threats and unauthorized access.

Purpose of Report

This report provides recommendations for sensor deployment across Big Dog?s critical assets. Each recommendation includes sensor descriptions, associated IoCs, prioritization based on Security Impact Level (SIL), and thresholds, aiming to secure data integrity and enhance network security management.



### 2. Security Impact Levels

A. Privacy (P)

Asset: Windows Server supports the MySQL database and PRTG, both containing critical information.

Security Classification:

- MySQL: High in Confidentiality, Integrity; Medium in Availability
- PRTG: Medium in Confidentiality; High in Integrity, Availability
The MySQL database holds sensitive details such as IP information, staff data, and security configurations necessitating robust security controls. If attackers identify that Big Dog?s IP relies on MySQL databases, they may specifically target these to access valuable information.

Vulnerability sample:

CVE-2023-38169 (CVSS Score: 8.8 High): A vulnerability in Microsoft SQL OLE DB that can be exploited through SQL injection. This attack vector allows malicious SQL code to alter database commands, potentially giving attackers arbitrary code execution capabilities. The vulnerability arises from improper memory management, where previously freed memory can be referenced, leading to significant security risks?(National Vulnerability Database, n.d.)



B. Proprietary (P)

Asset: Linux systems are used by developers to create proprietary intellectual property (IP) critical to the organization?s operations.

Security Classification:

- Linux: High in Confidentiality, Integrity, and Availability
The Linux systems host the company?s main products, making all aspects of the CIA triad essential. Compromise in any area could be detrimental, requiring strong monitoring and protection. While Linux is generally well-patched, these critical assets require constant attention.

Vulnerability sample:

- CVE-2023-6932 (CVSS Score: 7.0 High): This vulnerability in the Linux Kernel?s IPv4 IGMP component is a use-after-free (UAF) memory corruption flaw. Exploitation of this vulnerability can lead to arbitrary code execution, system crashes, or unauthorized data access. The Internet Group Management Protocol (IGMP) used in this context allows devices and routers to manage multicast group memberships, commonly utilized for data distribution. Attackers exploiting this flaw can achieve local privilege escalation, potentially causing denial-of-service (DoS) attacks or executing arbitrary code?(National Vulnerability Database, n.d.)


C. Administration (A)

Asset: Windows workstations used by the Management department.

Security Classification:

- Windows Workstation: Medium in Confidentiality, Integrity, and Availability
The Management department oversees IT, development, security, sales, marketing, and accounting, ensuring operational and network security. Although the company focuses on IP product development, a robust management team is vital to maintain organizational structure and end-user security training, an essential component of network resilience.

Vulnerability sample:

- CVE-2018-17462 (CVSS Score: 9.6 Critical): This vulnerability in Google Chrome?s AppCache involves incorrect reference counting, which allowed attackers to escape the sandbox environment through an HTML page. The sandbox, typically isolated from the network, is breached, giving attackers potential access to the OS or applications on the host machine. This flaw can lead to use-after-free (UAF) vulnerabilities, where previously freed memory remains accessible, allowing attackers to execute arbitrary code.(National Vulnerability Database, n.d.)


D. Security Management (SM): Kali Linux and Windows Server

Asset: Kali Linux for IT department use and Windows Server for PRTG monitoring.

Security Classification:

- Kali Linux: Medium in Confidentiality, Integrity, and Availability
- PRTG on Windows Server: Medium in Confidentiality; High in Integrity and Availability
The IT department uses Kali Linux for security operations, and Windows Server runs PRTG to monitor network performance and alert on potential issues. These assets are essential for overseeing the network?s security posture and detecting threats.

Vulnerability sample: 

- CVE-2021-35393 (CVSS Score: 9.8 Critical): A vulnerability in Realtek Jungle SDK, versions up to v3.414B, involves the Wifi Simple Config server implementing UPnP and SSDP protocols. The server is prone to stack buffer overflow issues during UPnP callback header analysis, allowing attackers with remote access to execute arbitrary code by bypassing authentication through these protocols.(National Vulnerability Database, n.d.)




E.Accounting (F)

Asset: Windows workstations are utilized by the Sales and Marketing teams.

Security Classification:

- Sales: Medium in Confidentiality, Integrity; Low in Availability
- Marketing: Medium in Confidentiality, Integrity; Low in Availability
Sales and marketing activities rely on secure and stable systems to manage client and financial data. The classification reflects moderate protection requirements for data integrity and confidentiality, with a lower emphasis on availability.

Vulnerability sample:

- CVE-2024-35133 (CVSS Score: 8.2 High): This vulnerability in IBM Security Verify Access (versions 10.0.0 through 10.0.8) can be exploited by an authenticated attacker using an open redirect attack. In this scenario, users are misled into clicking on what appears to be a legitimate URL but are redirected to a malicious website instead. This technique can be used to conduct phishing attacks by spoofing trusted links.(National Vulnerability Database, n.d.)


F.Systems (S): Kali Linux and Windows Server

Asset: Kali Linux for IT system testing (e.g., patches and updates), and Windows Server for hosting the company website via IIS Web Server.

Security Classification:

- Tests (Kali Linux): Low in Confidentiality, Medium in Integrity, Low in Availability
- IIS on Windows Server: Low in Confidentiality, Integrity, and Availability
Due to the website?s limited web presence, these systems are assigned a lower impact level. However, the IT department relies on them for essential operations, warranting some degree of monitoring.

Vulnerability Sample:

- CVE-2021-27239 (CVSS Score: 8.8 High): This vulnerability affects NETGEAR R6400 and R6700 routers, where the UPnP service running on UDP port 1900 is vulnerable. Without requiring authentication, network-adjacent attackers can exploit this by leveraging a buffer overflow within the SSDP message?s MX (mail exchange header) field. This flaw allows arbitrary code execution, impacting device discovery and communication on local networks, especially in IoT and smart devices.(National Vulnerability Database, n.d.)


## 3. Table of Sensors





Assessment: 

Integrating PRTG enables Cat to manage centralized monitoring efficiently, addressing her limited time for system oversight. The strategy prioritizes each system based on its role and data sensitivity:

- Windows Server (SIL 3): With responsibilities for the SQL database, IIS web server, and PRTG monitoring, the Windows Server is prioritized for high security. Alerts target database integrity, confidentiality, and system availability, focusing on unauthorized access prevention and tampering detection.
- IIS Web Server (SIL 2): As a publicly accessible server, IIS monitoring emphasizes availability and security. HTTP and Ping sensors are employed to quickly identify access issues and detect unauthorized entry attempts.
- Linux Development Server (SIL 4): To protect proprietary intellectual property, this server utilizes sensors monitoring system integrity, network traffic, and SSH access. Given its role in housing sensitive IP data, anomaly detection is critical.
- Workstations (SIL 2-3): Workstations receive moderate monitoring, balancing usability and security. Management workstations with more sensitive data are prioritized higher (SIL 3), while Sales and Marketing receive a slightly lower level (SIL 2)
- Kali Test Systems (SIL 1): Minimal monitoring is applied to test systems due to their lower impact, although basic monitoring ensures that unauthorized access can be identified before vulnerabilities are introduced.




### 4. Recommendations

To further strengthen security, the following measures align with industry standards, including NIST 800-92, IEC 61511, and CIS benchmarks:

- Conduct Regular Log Audits: Consistent log review enables early identification of vulnerabilities or attempted breaches. Using Syslog sensors alongside this practice ensures comprehensive visibility.
- Automate Response Protocols: Implement automated response protocols in PRTG to streamline incident handling. For instance, automatically restarting services or blocking suspicious IPs when thresholds are breached can reduce risk and downtime.
- Implement Role-Based Access Controls: Limit access to critical resources and monitoring settings by role to ensure only authorized personnel can make sensitive adjustments or view data.
- Establish Baseline Traffic Patterns: Developing a network traffic baseline will enhance anomaly detection accuracy and reduce false positives due to normal traffic fluctuations.
- Deploy Network Intrusion Detection Sensors: Adding intrusion detection to monitor known attack signatures and unusual activities provides an extra layer of protection for Windows and Linux systems.
- DNS Query Monitoring: Monitor unauthorized domain requests to detect potential exfiltration or attack vectors.
- Threshold Review: Periodically review thresholds to maintain relevance and reduce alert fatigue.


### 5. Conclusion

By configuring and calibrating sensors in PRTG, Cat ensures a secure and efficient monitoring framework within the client?s environment. This setup balances performance and security, allowing her to focus on critical alerts while minimizing false positives.  By implementing these strategies, Big Dog Corporation can better secure data integrity, maintain asset privacy, and adapt to evolving threats.



Link to presentation



6. References

National Institute of Standards and Technology. (n.d.). National Vulnerability Database (NVD). Retrieved October 29, 2024, from https://nvd.nist.gov/

MITRE. (n.d.). ATT&CK? Matrix for Enterprise. Retrieved October 29, 2024, from https://attack.mitre.org/

Paessler AG. (n.d.). PRTG Network Monitor. Retrieved October 29, 2024, from https://www.paessler.com/manuals/prtg

Paessler AG. (n.d.). Device and Sensor Setup. Retrieved October 29, 2024, from https://www.paessler.com/manuals/prtg/device_and_sensor_setup

Center for Internet Security. (n.d.). CIS Benchmarks. Retrieved October 29, 2024, from https://www.cisecurity.org/cis-benchmarks

CVE Program. (n.d.). Common Vulnerabilities and Exposures (CVE?). Retrieved October 29, 2024, from https://www.cve.org/

Canadian Centre for Cyber Security. (2020). Baseline Cyber Security Controls for Small and Medium Organizations. Retrieved October 29, 2024, from https://www.cyber.gc.ca/en/guidance/baseline-cyber-security-controls-small-and-medium-organizations

Fortinet. (n.d.). CIA Triad. Retrieved October 29, 2024, from https://www.fortinet.com/resources/cyberglossary/cia-triad

Cisco. (n.d.). Indicators of Compromise (IoCs). Retrieved October 29, 2024, from https://sec.cloudapps.cisco.com/security/center/resources/iocs.html





7. Revision History





