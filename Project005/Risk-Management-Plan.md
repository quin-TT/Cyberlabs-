[DHAEI Risk Management Plan](https://docs.google.com/open?id=1yTv3MJQmzMB1JsuWft1Ie396CNNzYPOrCUAgYX9mmMs)

Risk Management Plan

DHA Enterprise Inc.









Executive Summary





This document outlines the foundational steps toward creating a security management plan for risk assessment and treatment, aligned with ISO 27001. Achieving full compliance with ISO 27001 requires significant effort and organizational maturity, including the implementation of comprehensive policies, controls, and documentation.



The Statement of Applicability (SoA) defines which ISO 27001 controls and policies are applied by an organization and benchmarks them against the Annex A control set (ISMS.online, n.d.). While this document provides an initial framework, it does not include key elements of a comprehensive plan, such as gap assessments, residual risk analyses, a detailed SoA, or access to ISO 27001-specific resources.

DHAEI possesses many foundational components for establishing an Information Security Management System (ISMS), including security personnel, a dedicated budget, resources, and defined security requirements (Chin, n.d.). 



However, these components are not yet integrated into a unified ISMS framework. As such, DHAEI is at the early stages of its journey toward ISO 27001 compliance.The implementation of this focused risk management plan and the use of methodologies outlined in this document will serve as critical first steps toward addressing existing gaps. Over time, DHAEI can build on this foundation to achieve full compliance with ISO 27001 standards.







1. Introduction
1. Purpose: To identify, evaluate, address three main threats facing the organization
1. Scope: This covers risk assessment and treatment methodology for each threat and application of control
1. Intended Users: Intended to  executive management, IT team, security personnel














1. Risk Assessment and Treatment Methodology






A. End of Life Profile

- Process : 
1. High Priority risk: 1500 operation computers 
1. Treatment span: November 13 2025 (1 year-minimizes operational disruptions; managing logistical challenges like scheduling downtime, adequate testing ) 
1. Estimated Cost: ($218, 042) assuming resource allocation and phased execution
- Assets
1. Asset: 1500 main office desktops(Windows 10) for daily operations
- Security Category
1. Asset is an integral part of operations, and requires high availability. While critical data is stored on file servers, desktops may still contain sensitive information, necessitating moderate confidentiality and integrity controls


Calculation

SC 1,500 Desktops= {(Confidentiality: Moderate),(Integrity: Moderate),(Availability: High)}



- Individuals involved
1. Determining Risk owners




- Existing Vulnerability:
1. 1500 main branch desktops(Windows 10) for daily operations will not receive core security updates after Nov 2025
- Existing threat
1. End-of-Life (EOL) vulnerabilities in operating systems (OS) have a significant negative tactical impact on assets. The absence of critical security updates creates a weak defense against OS-related attacks. EOL status also heightens the likelihood of various risks and poses severe strategic consequences, including non-compliance with regulations, reputational damage, and operational disruptions.
- Treatment
1. End-of-Life (EOL) vulnerabilities in operating systems (OS) can have a significant negative tactical impact on assets. The absence of critical security updates creates a weak defense against OS-related attacks. EOL status also heightens the likelihood of various risks and poses severe strategic consequences, including non-compliance with regulations, reputational damage, and operational disruptions
- Risk Strategy
1. Use mitigation before EOL
- Treatment Calculation


1. Devices:
1. Total devices: 1,500.
1. Upgradeable devices: 1,000 (assumes 500 devices are not compatible due to hardware limitations or nearing end-of-life).
1. Labour for Physical Upgrades:
1. Estimated 4 hours per device for hardware upgrades.
1. Compatibility Testing:
1. Time required: 80 hours by IT and security teams combined.
1. Device Identification:
1. Automation tools will reduce manual effort, requiring an estimated 12 hours (midpoint of the original 8?24 hour estimate).
1. Unexpected Costs:
1. Buffer of 10% added to the total estimate for unplanned expenses, such as delays or additional troubleshooting.
1. Labour Costs:
1. Hourly wage: $35
1. Hardware Upgrade Costs:
1. $250 per device for physical upgrades.


Labour Estimates

- Compatibility Testing: 80 hours.
- Device Identification: 12 hours (automation reduces manual work)
- Physical Hardware Upgrades:
1. f(x)=(x?n)?t
1. f(x)=(1,500?1,000)?4
1. f(x)=500?4=2,000
- Total Labour Hours:80+12+2,000=2,092 hours


 Cost Estimation

1. Labour Costs:
1. 2,092?35=73,220
1. Hardware Costs:
1. (x?n)?c
1. (1,500?1,000)?250
1. 500?250=125,000
1. Contingency Buffer:
1. 10%?(73,220+125,000)=19,822
1. Total Cost:
1. 73,220+125,000+19,822=218,042


Formula for Cost (g(x)):

g(x)=(x?n) ? c + f(x) ? h + Buffer(for unexpected labor or material cost)



Where:

- x=1,500 (total devices).
- n=1,000n (upgrade-ready devices)
- c=250(hardware cost per upgrade)
- f(x)=(x?n)?t, t=4t = 4t=4 (labor hours per device)
- h=35 (hourly labor rate)
- Buffer = 10% of total cost


Substituting:



g(x) =(1,500?1,000 )   ? 250 + (500?4) ? 35 + 10% ? (73,220 + 125,000) 

g(x) = 125,000 + 73,220 + 19,822 = 218,042



So, the total estimated cost is $218,042





B. Single Point of Failure(SPOF) Profile: 



- Process : 
1. High impact to operations(server failure/data breach); risk of relying on single component can cause operational disruption
1. Treatment time: TBD
1. Estimate cost: $20,000- $40,000
- Asset
1. File system Interface
- Security Category
1. The FSI server serves as a central data repository utilized across the organization for operational purposes. Since the case details do not specify the exact location of high-value information assets, it is presumed that the FSI server houses the organization's sensitive data.


Calculation

SCFSI = {(Confidentiality: High), (Integrity: High), (Availability: High)}

- Individuals involved
1. Determining Risk owners


- Existing Vulnerability:
1. Reliance on a single FSI server creates a critical single point of failure (SPOF) for the organization-wide file system.
- Threat
1. A failure of the FSI server?due to human error, misconfigurations, or a cyberattack?could result in significant operational disruptions. This SPOF makes the server a high-value target for attackers. The impact includes severe tactical consequences, such as halting operations dependent on the FSI server. If the server contains sensitive information, the strategic implications include non-compliance, reputational damage, and data loss (MITRE, n.d.).
- Risk Strategy
1. Mitigation by introducing redundancy for the FSI server.
- Treatment
1. Deploy a redundant FSI server to eliminate the risk of single-point failure. In the event of a failure, the secondary server will seamlessly take over, ensuring uninterrupted access. Placing the secondary server in a geographically separate location will also provide a robust disaster recovery solution, enhancing overall system resilience.


 Calculation 



1. Hardware (Secondary Server): $8,000 ~ $12,000
Includes a backup FSI server with sufficient storage and processing capabilities.

1. Software and Configuration: $3,000 ~ $5,000
Tools for data replication, failover management, and backup encryption.

1. Implementation and Testing: $5,000 ~ $8,000
Includes setup, integration, and testing of failover scenarios.

1. Optional Cloud-Based Redundancy: $5,000 ~ $10,000
As an alternative to a physical secondary server, consider cloud redundancy with ongoing subscription fees.

1.  Contingency for Future Expansion: $3,000 ~ $5,000
With the addition of the Brampton branch, the system may require scaling.



Treatment estimate and cost:



The range for mitigating the SPOF could be $20,000 ~ $40,000. This estimate reflects cost to address the SPOF while considering DHAEI's budget and the operational importance of the FSI server





C. Understaffing Profile:



- Process : 
1. Limits  ability to address the organization?s security requirements effectively
1. Being managed through interim measures(while pursuing long-term staffing solutions)
- Asset
1. Position vacancy (Security team)
- Security Category
1. With one of the three security technician positions vacant, incident response and monitoring capabilities are significantly impacted, leading to temporary gaps in security operations. This challenge is further amplified as one of the two remaining positions is filled by an intern.


Calculation

SCVacancy in Security Team = {(Confidentiality: Moderate), (Integrity: Moderate), (Availability: Moderate)}

- Individuals involved
1. Determining Risk owners




- Existing Vulnerability:
1. Vacant position within the security team.
- Threat
1. Limited personnel for incident response and monitoring reduces the team's efficiency and effectiveness. This shortage negatively impacts the operational performance of security monitoring and response efforts. If the vacancy persists, it may lead to long-term strategic issues, including non-compliance with industry standards.
- Existing Vulnerability:
1. Vacant position within the security team.
- Risk Strategy
1. Accept with interim coverage.
- Treatment
1. Deploy a temporary resource or assign a cross-functional team to manage security responsibilities until the vacancy is filled


Treatment Calculation



Temporary Hire Duration: 1-Year 

- Competitive Hourly Rate: $45/hour(for temporary hire requiring immediate expertise)
- Work Hours: 40 hours/week
- Duration: 52 weeks


Total Compensation=40?hours/week?52?weeks?45?$/hour

Total Compensation=93,600$











1. Recommendation


To strengthen DHAEI's security posture and align with best practices for risk management, the following recommendations address the identified vulnerabilities and threats:







1. Windows 10 Machines (OS Updates)

- Recommendation: Implement NIST Control SI-02 (Flaw Remediation).
1. Ensure that all company-issued computers receive regular and approved security updates through a centralized update management system. Use tools like WSUS (Windows Server Update Services) or similar automated solutions to streamline this process.
1. Align this effort with the organization's Technical Requirement: "Ensure that all company-issued computers receive all updates approved by the technology department."
1. Action Plan:
1. Evaluate all devices to identify compatibility with Windows 11 or their need for continued Windows 10 support.
1. Schedule regular updates and establish a policy for update approval and deployment to ensure minimal disruption.
1. Outcome: Improved system security by reducing vulnerabilities associated with outdated software.
1. ISO Cross-References: A.6.8, A.8.32, A.8.8.




2. FSI Server (Single Point of Failure)

- Recommendation: Deploy a secondary FSI server with redundancy using NIST Control CP-09 (System Backup).
1. Implement a backup server located at a geographically separate site to ensure data availability and continuity in case of failure.
1. This recommendation supports the Security Requirement: "Files stored on the company file servers must be protected in the event that a file server or the drives from any file server are stolen."
1. Action Plan:
1. Configure automated backups and data replication between the primary and secondary servers.
1. Test failover capabilities regularly to ensure operational continuity during server outages or attacks.
1. Apply encryption to all stored data to protect against theft or unauthorized access.
1. Outcome: Minimized operational disruptions and enhanced resilience against failures or attacks.
1. ISO Cross-References: A.5.29, A.5.33, A.8.13.




3.Vacant Security Role

- Recommendation: Leverage NIST Control PS-03 (Personnel Screening) to ensure the security technician hired temporarily is thoroughly vetted and adequately trained to manage sensitive systems. This recommendation ensures continuity of security operations and mitigates risks during staffing transitions.
1. Action Plan:
1. Temporary Hire:
1. Prioritize onboarding and training the temporary security technician to ensure they can immediately address critical security operations, including incident response and monitoring.
1. Conduct thorough background checks and personnel screening
1. Cross-Training Existing Staff:
1. Provide cross-training to current IT and security team members as a contingency 
1. Permanent Hiring Plan:
1. Develop a detailed hiring plan for recruiting and onboarding a permanent security technician, aligned with DHAEI's long-term operational and security goals.
1. Include measures for enhanced once the permanent hire is in place.
1. Outcome:
Short-Term: Continuity of security operations is ensured through the temporary hire and cross-trained team members.

Long-Term: The permanent hire will stabilize the security team, reducing risks of gaps in monitoring and incident response.

1. ISO Cross-References:A.6.1




Additional Recommendations



- Centralized Monitoring and Alerts:
1. Implement a security information and event management (SIEM) system to centralize monitorings for security events, and improve incident response capabilities.
- Staff Training and Awareness:
1. Conduct regular cybersecurity training for all employees, with a focus on phishing awareness, secure password management, and compliance with security policies.
- Policy Documentation:
1. Develop and formalize security policies, including incident response plans, acceptable use policies, and data classification standards, to ensure a unified approach to risk management.
- Gap Analysis and Future Planning:
1. Perform a gap analysis to identify additional vulnerabilities or areas for improvement, and use these findings to enhance the current risk management plan.




1. Conclusion


Developing a security management plan that aligns with ISO 27001 requires a methodical approach and organizational readiness. DHAEI, while possessing essential elements such as security personnel, resources, and a defined budget, lacks the interconnected systems necessary for a fully operational ISMS.

The organization?s current position represents the initial stages of compliance.



 By starting with this targeted risk management plan and gradually addressing identified gaps, DHAEI can move toward meeting ISO 27001 standards. Typically, organizations begin with frameworks like NIST?s Cybersecurity Framework (CSF) and progress to ISO 27001 as their security maturity evolves. This approach appears well-suited for DHAEI as it scales its information security program.



These recommendations provide DHAEI with a roadmap to enhance its security posture and establish a path toward long-term compliance and operational resilience.







1. Reference/s


MITRE. (n.d.). Update software. MITRE. Retrieved November 14, 2024, from https://attack.mitre.org/mitigations/M1051/

MITRE. (n.d.). Defense evasion (TA0005). MITRE. Retrieved November 14, 2024, from https://attack.mitre.org/tactics/TA0005/

MITRE. (n.d.). Service stop (T1489). MITRE. Retrieved November 14, 2024, from https://attack.mitre.org/techniques/T1489/

MITRE. (n.d.). Impact (TA0040). MITRE. Retrieved November 14, 2024, from https://attack.mitre.org/tactics/TA0040/

National Institute of Standards and Technology Computer Security Resource Center. (n.d.). Mappings to NIST documents. Retrieved November 14, 2024, from https://csrc.nist.gov/projects/olir

National Institute of Standards and Technology. (2023). Cybersecurity and privacy controls for information systems and organizations (NIST SP 800-53 Rev. 5.1.1). Retrieved November 14, 2024, from https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home

Rocket Software. (n.d.). File system interface. Rocket Software. Retrieved November 14, 2024, from https://www3.rocketsoftware.com/rocketd3/support/documentation/d3nt/102/userguide/File_System_Interface.htm

Statista. (2024). How long does it take your organization to fill a cybersecurity position with a qualified candidate? Retrieved November 14, 2024, from https://www.statista.com/statistics/1322366/cybersecurity-staffing-time-to-fill-vacancy-worldwide/

ISMS.online. (n.d.). ISO 27001 ? Annex A controls. ISMS.online. Retrieved November 14, 2024, from https://www.isms.online/iso-27001/annex-a-controls/

Microsoft. (n.d.). End of support for Windows 10, Windows 8.1, and Windows 7. Retrieved November 14, 2024, from https://www.microsoft.com/en-ca/windows/end-of-support?r=1#:~=Support%20for%20Windows%2010%20will,technical%20support%20for%20Windows%2010

Lighthouse Labs. (n.d.). Sample risk management methodology document. Retrieved November 14, 2024, from 

https://learningimages.lighthouselabs.ca/Cyber+BC/Cyber+BC+C5/Cyber+BC+C5.2/Sample+Risk+Management+Plan.pdf

ISMS.online. (n.d.). ISO 27001 requirements. Retrieved November 14, 2024, from https://www.isms.online/iso-27001/requirements/#:~

=ISO%2027001%20Requirement%206.2%20requires,the%20organisation's%20overall%20business%20objectives.

OneTrust. (n.d.). ISO 27001 vs. NIST cybersecurity framework. Retrieved November 14, 2024, from https://www.onetrust.com/blog/iso-27001-vs-nist-cybersecurity-framework/

CCS Learning Academy. (n.d.). What is gap analysis in cybersecurity? Retrieved November 14, 2024, from https://www.ccslearningacademy.com/what-is-gap-analysis-in-cybersecurity/

Government of Canada. (n.d.). Wages: Security systems technicians in Ontario. Job Bank. Retrieved November 14, 2024, from https://www.nu.jobbank.gc.ca/marketreport/wages-occupation/26101/ON

ZipRecruiter. (2024). Security technician salary. Retrieved November 14, 2024, from https://www.ziprecruiter.com/Salaries/Security-Technician-Salary

ZipRecruiter. (n.d.). Security technician salary in Ontario. Retrieved November 15, 2024, from https://www.ziprecruiter.com/Salaries/Security-Technician-Salary--in-Ontario

Drata. (n.d.). What are the ISO 27001 security controls? Retrieved November 15, 2024, from https://drata.com/grc-central/iso-27001/controls#heading-what-are-the-iso-27001-security-controls

Job Bank Canada. (n.d.). Wages for security systems technicians in Ontario. Retrieved November 15, 2024, from https://www.nu.jobbank.gc.ca/marketreport/wages-occupation/26101/ON

IT Convergence. (n.d.). The risks of using outdated operating systems. Retrieved November 15, 2024, from https://www.itconvergence.com/blog/risks-of-using-outdated-operating-system/

Chin, K. (n.d.). What is an ISMS (Information Security Management System)? UpGuard. Retrieved November 14, 2024, from https://www.upguard.com/blog/isms







1. Revision Table


| Date of Change | Responsible | Summary of Change |
|----------|----------|----------|
| Nov 2024 | Quin | Converted to new format  |




