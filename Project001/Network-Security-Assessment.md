Network Security Assessment Report

Using NMAP and Wireshark to  analyze network traffic 

to improve security posture







1. Executive Summary
1. This report aims to document and analyze network traffic captured in a lab environment to identify vulnerabilities, observe traffic patterns, and propose security improvements. The focus was on assessing the security configurations of a virtual network environment comprising Windows 11, Linux Server, and Kali OpenVAS systems. By understanding these systems' network behaviors and identifying risks, the assessment provides a pathway to enhance overall network security.
1. Key findings from this assessment included the detection of TLS traffic, which reflects adherence to certain security best practices. However, communication over Port 80 was found to involve unencrypted HTTP traffic, making it susceptible to eavesdropping. Instances of TCP retransmissions and packet loss suggested network congestion or inefficiencies, while repeated DNS queries to specific external domains highlighted possible misconfigurations or security risks. On a positive note, no evidence of ARP spoofing was observed, though ARP traffic monitoring remains critical to preventing potential attacks.
1. To address these issues, it is recommended to transition HTTP traffic to HTTPS using TLS/SSL encryption, ensuring data confidentiality and integrity. Enhancing DNS security through filtering tools and adopting DNS-over-HTTPS (DoH) will mitigate domain-based threats. Continuous monitoring using tools like Wireshark and Nmap should be implemented to proactively detect vulnerabilities. Additionally, conducting a network audit to optimize configurations and resolve congestion issues, alongside deploying ARP monitoring tools and enabling Dynamic ARP Inspection (DAI), will further strengthen the network?s security posture. By implementing these recommendations, the organization can ensure resilient network environment.




1. Methodology


Step by step:



1. Initiating and Setting Up the VMs: All virtual machines (Windows 11, Linux Server, and Kali OpenVAS) were initiated, with the Windows 11 VM designated as the host to run Wireshark. Network traffic was captured via Ethernet interface (eth0). Nmap was used to conduct detailed scans, identifying open ports and services. The Kali OpenVAS and Linux Server VMs were also assessed for vulnerabilities.


1. Collecting Device IP Addresses: Using the ip a command on the terminals of Kali OpenVAS and Linux Server and the command prompt of Windows 11, the IP addresses of each device were retrieved. These addresses were critical for targeted scans and communication verification.
1. Verifying Network Connectivity: From the Windows 11 VM, network connectivity across all VMs was confirmed by pinging their respective IP addresses. This ensured communication and set for accurate data collection and analysis.


1. Network Scanning with Nmap: Nmap was utilized to identify open ports, operating systems, and devices on the network. Full scans documented each device's IP address, open ports, operating system, and latency. A significant finding included the Windows 11 device with an open HTTP port, a common vulnerability.


1. Traffic Analysis with Wireshark: Wireshark was employed to capture and analyze packets moving through the network. The focus was on the Windows 11 VM's HTTP communication. Wireshark enabled the detection of suspicious activity, response time measurements, and the monitoring of device communication protocols. 




1. Documentation of Network Devices


OSI Layer Analysis (Specify at which OSI Layer each address and port is observed)







1. Layer 7(Application) 


Protocol observed: 



- Http: The frame shows an HTTP/1.1 200 OK response, indicating that the request made by the client was successfully processed by the server


- Dns: The DNS query captured here with transaction ID 0x965d reflects a standard outbound request from a client device to resolve an external domain


Arp traffic observed:The network capture shows multiple ARP request packets where the source device (PCSSystemtec_1b:76:b0 with MAC 08:00:27:1b:76:b0) is broadcasting a request to identify the MAC address of the device with the IP address 10.0.2.3 







1. Layer 4(Transport)
Protocol used: 



Tcp:The acknowledgment flag indicates that the packet confirms the receipt of previously sent data

Udp: No session establishment as in TCP, making it lightweight and faster for this type of DNS query



1. Layer 3(Network)
The source IP 10.0.2.8 is communicating with the external IP 72.136.196.81, indicating traffic possibly routed to an external server







1. Layer 2(Data Link)
This frame shows a typical Ethernet II packet being transmitted from the source MAC address 08:00:27:1b:76:b0 to the destination 52:54:00:12:35:00. The type field (0x0800) indicates that this packet is carrying an IPv4 payload





### Device Information Table













1. Network Findings
1. The Windows 11 machine, designated as windows11-desktop, operates with IP address 10.0.2.6 and MAC address 08-00-27-CB-20-4A, running Windows 11 OS. It has multiple open ports, including Port 80 (HTTP), Port 135 (MS RPC), Port 139 (NetBIOS), Port 445 (SMB), and Port 8080 (HTTP proxy), with an ARP ping scan time of approximately 3.78 seconds.
1. The Linux Server, named linux-server, has IP 10.0.2.15 and MAC 08:00:27:dd running Ubuntu 22.04.4 LTS. It has open Port 80 (HTTP) and Port 3306 (MySQL), with an ARP ping scan time of 3.02 seconds.
1. Lastly, the KaliOpenVAS machine, designated as kali, is assigned IP 10.0.2.8 and MAC 08:00:27:1b:76 operating on Kali GNU/Linux. No open TCP ports were detected,nmap reports ?ignored states? which implies that no responses were received from targeted ports. Repeated scans with various options were used(-sT, -sV, -A) but showed ports are closed. This could mean ports are filtered(eg by a firewall) which could indicate a secure configuration.. The ARP ping scan took approximately 3.68 seconds.


### Overall, it highlights potential vulnerabilities, such as open ports on the Windows 11 and Linux server, which could be exploited. The closed-port state of the KaliOpenVAS machine suggests positive sign in terms of reducing attack surface The reported ARP ping scan times provide insight into network overall health of device connectivity.

































1. Image Documentation


Nmap Scans on Kali OpenVas









Wireshark Captures on Kali OpenVas







1. Information Collection Process


1. Collection Methods:


1. Nmap for scanning? full scan of the network( IP address, open ports, OS,)
1. Wireshark for packet analysis? monitoring of suspicious events, response times and device communication protocol
1. Data verification by filtering specific traffic interactions in Wireshark(focusing on IP and port-based communication)
1. Details for scanning processes (commands used in Nmap (nmap -A -T4 10.0.2.8 , nmap -sV 10.0.2.8) and filters applied in Wireshark (ip.addr == 10.0.2.8,tcp,udp, arp, dns,)
1. 
1. Nmap & Wireshark Analysis:


1. Captured packets with Tcp flags such as Syn, ack, Fin demonstrated standard connection establishment
1. Nmap scans show mix of open, closed and filtered ports
1. ARP request were observed which is typical for devices discovering MAC addresses
1. Http and Dns showed potential vulnerabilities  if sensitive data is transmitted without encryption






































1. Network Topology










1. Recommendations




1. Switch and configure the server to use HTTPS (port 443) with TLS/SSL encryption for secure data transmission, which will help protect the confidentiality and integrity of the data being exchanged.
1. Continuous Monitoring and log traffic to help any unauthorized communication(TCP connections with keep-alive packets, to detect frequent retransmissions
1. Ensure that firewall rules are in place to restrict traffic to only necessary ports, and network segmentation to reduce  risk of potential threats
1. Regularly audit network security policies and protocols to ensure application of appropriate access controls.
1. Regular measures such as DNS filtering, dns monitoring tools to restrict access to known malicious domains and review DNS traffic  and server logs for unusual activity, such as unexpected DNS queries or responses, which may indicate domain name system attacks or misconfigurations.Enabling DNS over HTTPS (DoH) for more secure DNS queries
1. Verify that only necessary UDP services are running to minimize the potential attack surface
1. ARP Traffic monitoring tools to detect unusual ARP activity, such as duplicate IP addresses or inconsistent MAC addresses and enable Dynamic ARP Inspection (DAI)on network switches to verify the integrity of ARP packets




1. Revision History




