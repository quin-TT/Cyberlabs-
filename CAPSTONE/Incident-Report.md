Incident Response Report

Premium House Lights









Executive Summary



## The incident began with an email threatening to release your customer data unless a ransom was paid. Investigations showed that the attacker found a weak spot in your website, which allowed them to take control remotely. Once inside, they explored your network, found another weak point in your database system, and guessed the password to access it. The attacker then copied the customer data and sent it to their own server. This highlights several security issues, including outdated systems, easy-to-guess passwords, and a lack of monitoring to catch unusual activity



Your company experienced a security breach resulting in customer data being exfiltrated. Although the original data remains intact and systems are recoverable, attackers gained unauthorized control, necessitating immediate actions below:



- Immediate Action: Follow the outlined steps to mitigate further risks.
- Recommendations: Refer to the detailed recommendations for long-term security enhancements.
- Technical Analysis: Comprehensive information on the attack








# 

# Incident Response

Based on the technical Analysis of case artifacts,Command-and-control, and Data exfiltration, took place on the network. Use the following steps for immediate incident response.



## Immediate actions 



1. Inform the Team: Notify key staff members and management about the incident and ensure everyone follows company policies for handling the situation.


1. Disconnect Affected Devices: Isolate the impacted systems, such as the web server and database, from the rest of the internal network to prevent the issue from spreading.


1. Remove Malware: Delete any known malicious files or programs from the affected systems. Close unused or vulnerable access points.


1. Update Software: Make sure all systems and software, including antivirus tools and operating systems, are up to date with the latest security patches.


1. Scan for Problems: Check for leftover traces of malware and use tools to scan the systems for other potential vulnerabilities or risks caused by the incident.


1. Secure the Systems: Strengthen your system by improving settings like stronger passwords, managing user accounts carefully, and reviewing the security of applications.


1. Control Access: Ensure only authorized people have access to the network by setting up proper user roles, permissions, and requiring additional verification steps like multi-factor authentication.


1. Separate Networks: Create distinct segments within the network so that different parts cannot affect each other easily. This adds an extra layer of protection.


1. Protect Remote Access: Add a Virtual Private Network (VPN) for any systems that need to be accessed from outside the company.


1. Adjust Firewalls: Set up firewalls to create a safe "buffer zone" (DMZ) where public-facing systems, like the web server, are separated from the internal network.


1. Test Your Fixes: After taking these steps, test the network to ensure all issues are resolved and the systems are functioning securely.




Next: Follow incident response steps

## 

## 

## 

Incident Response Steps

Note: We begin our steps at containment since the incident has been named.From containment, we move to eradication. We then must also update our detection and identification before moving through the IR steps cycle and finally reach recovery



1. Containment


Notify Your Team: Inform your key team members and follow company protocols.



## Disconnect Affected Devices: Isolate devices on VLAN #1 (the affected network area).



## Block Known Attacker IPs: Add IPs like 138.68.92.163 and 178.62.228.28 to a blacklist in the firewall.



## Restore from Backup: Restart devices using clean backups or the last safe version of the system.



## Update Systems: Ensure operating systems, antivirus programs, and other software are up-to-date.



## Close Vulnerable Ports: Shut down unsafe ports like 80 (web server) and 23 (telnet on the database).



1. Eradication


## Delete Malicious Files: Remove the malicious shell.php from the web server.



## Secure Your Systems: Update software, remove unneeded programs like nmap and python, and harden configurations.



## Audit Accounts: Remove unnecessary or weak user accounts and strengthen security for all accounts.



## Scan All Systems: Perform a full scan of devices to ensure no hidden vulnerabilities remain.



1. Detection 


## Update Security Tools: Ensure antivirus and anti-malware tools are current.



## Strengthen Firewalls: Add malicious IPs to the blacklist and improve firewall settings.



## Control Access: Implement systems like Identity and Access Management (IAM) and privileged access controls.



## Monitor Activity: Use tools to continuously monitor devices and networks for unusual behavior such as PRTG. Select sensors to begin monitoring efforts.



## Run Vulnerability Scans: Set up solutions like Greenbone for regular vulnerability checks.Consider implementing a SIEM.



1. Identification 


## Educate Your Team: Train and educate members on identifying suspicious activity and understanding company policies.



## Use Threat Intelligence Tools: Stay informed about potential threats using monitoring tools like SIEM systems.



## Develop Playbooks: Have clear procedures for identifying and responding to incidents.



1. Recovery 


## Encrypt Data: Protect sensitive information with encryption and implement Multi-Factor Authentication (MFA).



## Rebuild Safely: Use secure configurations and follow updated playbooks for system recovery.



## Review Systems: Confirm all fixes are working and ensure systems are fully operational.



1. Post-Incident Activity 


## Review Lessons Learned: Discuss what went wrong, what worked, and what can be improved.



## Update Policies: Make changes to the incident response plan and playbooks based on findings.



## Report Malicious IPs: Notify Digital Ocean (or other relevant parties) about the malicious IPs.



## Plan for the Future: Schedule the next test of the incident response plan and prepare for potential new threats.



### 

### Recommendations



## Following the completion of all Incident Response steps, consider implementing the recommendations outlined below to address the security gaps identified in the Technical Analysis



Network Topology

## The diagram above illustrates the recommended network topology for the organization. Use this structure to guide the necessary network redesign.







## To implement the recommended network topology:

1. Configure firewalls to establish a DMZ, which will house all public-facing services, such as the web server.
1. Disable vulnerable or unused ports and ensure all public-facing endpoints are properly secured.
1. Enforce service separation by utilizing VLANs with proper IP subnetting to segregate and secure network services.
1. Implement VPNs for services that require secure remote access.
## 

## 

## Security Policy



Based on the Technical Analysis the organization lacks a security-first mindset and maturity.Follow the Immediate Action in 11 Steps, and update the Security and Privacy Incident Report.

Once incident response is completed, follow reviewing and applying Critical Security Controls (CIS) (Critical Security Controls v8, 2021).



### Security Policy Documents:

| File Name | File Access |
|----------|----------|
| Security and Privacy Incident Report | PHL security and privacy incident report |
| Critical Security Controls v8 | Critical Security Controls (CIS) |


### 

# 

# Technical Analysis



View the full technical analysis here: Technical Analysis



## Technical summary(Command-and-Control and Data Exfiltration Incident)

Threat Actor Profile:

- The attacker utilized IP addresses without prior malicious history, originating from Digital Ocean.
Initial Exploitation:

- Attacker IP 138.68.92.163 identified a vulnerable web server endpoint /upload/ on port 80 through port scanning and directory enumeration.
Payload Deployment:

- A malicious script was uploaded to the unsecured /upload/ endpoint, creating a foothold in the system.
Reverse Shell Activation:

- The attacker initiated a socket connection, leveraging the www-data user account?s permissions to execute commands and establish a reverse shell.
Internal Network Reconnaissance:

- Using the reverse shell, the attacker employed nmap to perform an internal scan of IPs within VLAN #1, revealing an open telnet port on the database server.
Credential Exploitation:

- The attacker performed a brute-force attack on the database server?s telnet service, successfully accessing the system as user phl.
Database Compromise:

- Default credentials were used to log in as the root user on the MySQL database.
Data Exfiltration:

- The attacker copied the database records, transferring them to IP 178.62.228.28, and then deleted the local copy.
Session Termination:

- The attacker exited the reverse shell, leaving the initial method of access still active and exploitable.


Notes: The original database remains intact on the server.

The method of remote access is still accessible, posing ongoing risks













## Incident Timeline



This timeline outlines the progression of the attack and the key events within the network. The incident occurred on 2020-02-20, between 02:58:12.322138 and 03:02:38.656489, lasting approximately 10 minutes.

| Event | Time | Reference in technical analysis |
|----------|----------|----------|
| IP 138.68.92.163 begins external port scanning of web server | 2022-02-20 02:58:12:322138 | 2.1 |
| IP 138.68.92.163 begins path enumeration of web server | 2022-02-20 02:58:22.249777 | 2.2 |
| Malicious script is delivered to web server | 2022-02-20 02:59:04.17195 | 3 |
| Remote code execution begins on web server | 2022-02-20 02:59:04.191040 | 5.0 |
| Internal nmap scanning on VLAN #1 | 2022-02-20 02:59:45.028702 | 7.0 |
| Attacker logs into Database server via telnet | 2022-02-20 03:00:18.756243 | 6.2 |
| Attacker logs into MySQL with default credentials | 2022-02-20 03:00:55.328005 | 6.2 |
| Attacker exfiltration of database to IP 178.62.228.28 | 2022-02-20 03:02:26.394165 | 6.2 |
| Attacker exits the reverse shell | 2022-02-20 03:02:38.656489 | 6.2 |


## The attack demonstrates a rapid escalation, exploiting vulnerabilities and poor access controls within the network. Each step aligns with findings in the technical analysis.





# Reference/s

Critical Security Controls v8. (2021, May 18). CSF Tools.  Retrieved January 8, 2025 from https://csf.tools/reference/critical-security-controls/version-8/

















































