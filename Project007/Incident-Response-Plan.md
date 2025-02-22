[Link to IR Plan](https://docs.google.com/open?id=1dcCtGipLNxlhgDEfwrYFvdq-AR5hr2KNMDD-PpBrWHI)

Incident Response Plan

The Medical Society of Prince Edward Island 





1. Test & Review Cycle
It is crucial to perform bi-annual testing of the Incident Response Plan (IRP) to ensure the Cyber Security Incident Response Team (CSIRT) remains aware of its roles and responsibilities. Regular testing ensures that the team can effectively execute the plan during an actual incident.

While real incidents serve as the most comprehensive test, the Incident Response Plan can also be evaluated through walkthroughs and practical simulations of potential cybersecurity events. These mock incidents will test the team?s ability to respond appropriately to various scenarios.

The Incident Response Plan will be subjected to a full review at least once every 6 to 9 months. The tests will assess the team's responses to potential cybersecurity incidents, helping to identify gaps in processes and areas that need improvement.

The CSIRT will keep a record of all observations during testing. These notes will highlight areas where the team performed poorly or misunderstood procedures, and they will serve as the basis for future improvements. For example, if certain steps were not carried out effectively, the plan will be updated to address those issues.

Once the testing phase is complete, the MSPEI CSIRT Executive will review the results, make the necessary adjustments to the Security Incident Response Plan, and ensure it is redistributed to all CSIRT members for continued training and preparedness.



1. Related Policies
As the Incident Response Plan is updated, additional policies may be required and developed to ensure a comprehensive approach to cybersecurity management





| Policy Document | Link Status | Related File/s |
|----------|----------|----------|
| Incident Response Plan Policy |  | Incident Response Plan Policy |
|  |  |  |
|  |  |  |




1. Purpose & Scope


Purpose

The Incident Response Plan (IRP) is designed to ensure that the Medical Society of Prince Edward Island (MSPEI) is ready to effectively and efficiently manage any cybersecurity incident. Given the rising frequency and sophistication of cyberattacks, this plan outlines the procedures and responsibilities for responding to potential threats.

MSPEI, despite not having a dedicated IT department, should form a Cyber Security Incident Response Team (CSIRT). This team can consist of in-house personnel trained to handle cybersecurity incidents. Even if the resources are limited, having a plan in place ensures that the organization is prepared to detect, respond to, and recover from cybersecurity incidents.

Cybersecurity incidents are inevitable, and no organization is immune. By establishing a formal plan, creating a team, and conducting regular exercises, MSPEI will be better equipped to minimize damage, contain the incident, and mitigate further risk to the organization.

The Incident Response Plan aims to ensure that MSPEI is organized to respond quickly and efficiently to any cybersecurity incident.



Scope

This Incident Response Plan applies to all of MSPEI?s networks, systems, data, and stakeholders, including employees, contractors, and third-party vendors. It sets out the roles and responsibilities of the Cyber Security Incident Response Team (CSIRT), which will lead or assist in responding to cybersecurity incidents.

All CSIRT members must familiarize themselves with this document and be ready to collaborate with other team members to minimize the negative effects of incidents on MSPEI. This plan is not intended to provide an exhaustive list of every action to take in response to an incident, but it serves as a general framework for handling common cybersecurity issues.



1. Authority
The responsibility for the security of MSPEI?s information and systems is assigned to the President. However, in the case of a high-severity or critical cybersecurity incident, this responsibility will shift to the Chief Executive Officer (CEO).



| Title | Role | Name | Contact |
|----------|----------|----------|----------|
| President | President | Dr. Krista Cassell | president@mspei.org |
| CEO | CEO | Dr. Krista Cassell | lea@mspei.org |
|  |  |  |   |








1. Definitions




| Term | Definition |
|----------|----------|
| Confidentiality | A data classification that typically refers to personally identifiable information (PII). This includes sensitive information such as social insurance numbers, driver?s license numbers, etc. |
| Cyber Security Incident | Any event, whether accidental or intentional, that disrupts the functioning of communication or information systems. Such incidents may threaten the confidentiality, integrity, or availability of data, systems, or services used or provided by MSPEI. This can include unauthorized access, modification, disclosure, or destruction of data. |
| Identifying Security Incidents | The process of recognizing potential cybersecurity breaches, system compromises, unauthorized activities, or misuse. Key indicators may include unusual system behavior, alerts, or evidence of potential vulnerabilities within the organization or with third-party vendors |
| Integrity | The assurance that data remains accurate, consistent, and accessible to authorized users throughout its lifecycle. This concept is key to preventing unauthorized modifications or loss of information. |
| Managed Security Service Provider (MSSP) | A specialized third-party provider offering comprehensive security services to protect an organization's systems, people, and data. MSSPs ensure compliance with security standards, and implement proactive security measures to prevent, detect, and respond to cybersecurity threats. |
| Managed Service Provider (MSP) | A third-party service provider contracted to ensure that IT systems are operational and supported. The MSP typically handles the management of IT infrastructure, ensuring systems run smoothly and securely. |
| Response Playbook | A set of structured cybersecurity practices and guidelines that can be implemented to strengthen the organization?s security posture. This playbook outlines the standards to be followed, as well as methods for improving existing systems and introducing new ones. |
| Service Availability | Refers to the ability of a system or service to remain functional and responsive to users. This metric often reflects the reliability of systems or network resources, and it?s often represented as a percentage of time the service is operational (e.g., 99.97% service availability indicates that the system is available 99.97% of the time) |




1. Definitions


Indicators of Potential Cybersecurity Incidents

Some signs that a security incident may have occurred or is in progress could include, but are not limited to:

- Automated alerts: Alerts generated by security monitoring systems that detect anomalies or potential threats.
- Multi-factor authentication (MFA) alerts: Unusual MFA alerts triggered by failed login attempts or unauthorized access.
- Suspicious activity related to malware: Detection of malicious software, new/unapproved files, or strange behavior of system programs.
- Point-of-Sale (POS) system anomalies: Signs of tampering with POS terminals or card readers, such as unusual modifications or unapproved devices attached to them.
- Lost or stolen media devices: Computers, laptops, or storage devices containing sensitive information that are misplaced or stolen.
- Excessive or unusual log-in/system activity: Logins from inactive or unauthorized user accounts, or unexpected spikes in system activity.
- Unusual remote access activity: Any unapproved remote access to business systems, whether from internal staff or third-party vendors.
- New or unknown wireless networks: Appearance of new wireless (Wi-Fi) networks within the organization?s premises.
- Presence of hardware/software keyloggers: Discovery of keyloggers on systems, either hardware devices or malicious software.
- Suspicious web-facing system behavior: Unexpected or unusual activity observed on publicly accessible systems, such as e-commerce websites.
- Card-skimming devices: Discovery of unauthorized card-skimming devices within the organization?s payment systems.
- Lost or stolen transaction records: Loss or theft of merchant receipts or documents that contain sensitive payment data (e.g., full card numbers, security codes).


1. Response Team


Medical Society of Prince Edward Island (MSPEI) Organization Diagram

















Cyber Security Incident Response Team (CSIRT) Roles

The Medical Society of Prince Edward Island (MSPEI) should designate individuals to fill the necessary roles and become part of the Cyber Security Incident Response Team (CSIRT). The composition of the CSIRT will depend on MSPEI?s available resources and organizational structure.

Key positions within the CSIRT must be established to ensure that the Incident Response Plan can be executed effectively. The Executive Role, specifically held by the MSPEI President and CEO, is essential for directing the organization?s response to critical incidents.

The Incident Handler role is a versatile position that can be handled by a variety of staff members, depending on the circumstances.



CSIRT Roles Overview





| Role | Role Description |
|----------|----------|
| Board | The Board members support the executives by promoting cybersecurity efforts, ensuring alignment between security initiatives and the organization?s financial and operational decisions. |
| Communications Expert | Responsible for both internal and external communications during an incident. Ensures all stakeholders and the public are informed in a timely, compliant, and accurate manner. |
| Executive | The Executive is the accountable individual for safeguarding cybersecurity within the organization. This role oversees all critical decisions related to security and reports to the board. |
| Incident Handler | The primary triage role within the CSIRT, the Incident Handler organizes and initiates responses to cyber incidents, ensuring effective investigation and mitigation actions. |
| Incident Response Planner | Responsible for developing, updating, and maintaining the Incident Response Plan. This role ensures the plan is aligned with organizational needs and regulations while coordinating CSIRT member contributions. |
| Note-Taker | Records all relevant information throughout the incident handling process, from meeting minutes to post-mortem evaluations, ensuring that detailed records are available for review. |






1. CSIRT Responsibilities
Below is a breakdown of the roles and their respective responsibilities within the MSPEI Incident Response Plan:



MSPEI Board Responsibilities

- Align cybersecurity priorities with the organization?s strategic goals and budgetary constraints.
- Facilitate board-level escalations for cybersecurity incidents.
- Ensure cybersecurity efforts are in line with business objectives and regulatory requirements.
MSPEI Executives Responsibilities

- The executive team holds ultimate responsibility for the organization's cybersecurity, ensuring that decisions are made in alignment with business needs.
- Regularly brief the board of directors on cybersecurity matters, incidents, and the necessary responses.
- Ensure that the Incident Response Plan is continually updated, tested, and aligned with organizational needs.
- Make key decisions based on insights provided by the CSIRT, ensuring the plan is implemented effectively.
- Facilitate the coordination of cybersecurity training for staff members, ensuring readiness for potential incidents.
- Authorize investigations by law enforcement or forensic personnel during high-severity incidents.
MSPEI Incident Response Planner Responsibilities

- Regularly review and maintain the Incident Response Plan, ensuring it reflects organizational policies, security regulations, and feedback from CSIRT members.
- Develop and document the escalation procedures and response strategies to be followed in case of an incident.
- Use lessons learned from past incidents to refine and improve the Incident Response Plan.
MSPEI Incident Handlers Responsibilities

- Initiate the Incident Response Plan whenever a cybersecurity incident is reported or suspected.
- Manage the response to incidents, ensuring they are handled effectively and within the prescribed timelines.
- Comply with the escalation procedures outlined in the relevant playbooks or SOPs.
- Record the progression of the incident, keeping the CSIRT updated and informed about actions taken and decisions made.
- Ensure adherence to internal laws and policies throughout the incident response process.
Communications Expert Responsibilities

- Ensure the timely and accurate dissemination of information about the incident to both internal and external stakeholders.
- Communicate incident details to the appropriate authorities if necessary.
- Interface with executives and team members to provide clear updates on incident status and impact.
- Manage post-incident communications and collect feedback from staff, partners, and stakeholders for lessons learned.
Note-Taker Responsibilities

- Document all steps taken during the incident, including the timeline of actions, decisions made, and any relevant observations.
- Ensure that all notes are readily available for review and analysis by CSIRT members.
General CSIRT Responsibilities for All Team Members

- Understand and familiarize themselves with the Incident Response Plan and their specific roles within the plan.
- Participate in incident response activities, ensuring communication and collaboration across teams.
- Report any suspected or confirmed security incidents to the Incident Handler or another CSIRT member.
- Follow established security policies and procedures, adapting them as necessary to mitigate the impact of incidents.
- Ensure proper documentation of incidents, including evidence collection and chain of custody, as well as comprehensive incident reports.


1. MSPEI CSIRT Team Responsibilities
The members of the Medical Society of Prince Edward Island (MSPEI) Cyber Security Incident Response Team (CSIRT) have specific duties that ensure the organization is prepared to handle cybersecurity incidents:

- Study and understand the plan: CSIRT members must thoroughly familiarize themselves with this Incident Response Plan and their individual responsibilities.
- Communication: Members must maintain effective communication throughout the incident response process and ensure all relevant incident response resources are utilized.
- Staff Education: Ensure all staff members are trained to recognize and report potential or actual security incidents.
- Escalation Procedures: Be aware of how to escalate an incident report if necessary.
- Minimize Risk: Take steps to limit exposure to sensitive information, such as personally identifiable information (PII) or payment card data, and work to reduce any associated risks.
- Incident Documentation: Maintain thorough records of the incident, including all actions taken in response, and ensure these records are available for future analysis.
- Reporting: Report all incidents and findings to relevant parties, including third-party vendors, partners, law enforcement, or other stakeholders as needed.
- Cooperation with Law Enforcement: Assist law enforcement and forensic teams during investigations, including evidence handling and analysis.
- Policy Feedback: Provide input on policies, processes, and technologies that need updating to prevent future incidents or improve the current mitigation strategies.
- Leverage Security Resources: If needed, use external security resources to mitigate risks during an incident.
All Staff Responsibilities

All staff members at MSPEI have key roles to play in the cybersecurity incident response process:

- Recognizing and Reporting Incidents: All employees must know how to recognize a security incident and report it to the Incident Handler or a CSIRT member.
- Escalation: If a staff member discovers or suspects an incident, they should escalate it according to the established reporting procedures.
- Reporting Security Issues: Staff must report any security-related concerns to management or the CSIRT.
- Compliance: Staff members must adhere to MSPEI?s security policies and procedures, including any temporary measures put in place in response to a security incident, such as business continuity or recovery protocols.
MSPEI CSIRT Contact Information

The following table outlines the recommended CSIRT roles and the corresponding contact details for the team members. Multiple fallback contacts are available.



| Title | CSIRT Role(s) | Name | Contact Information |
|----------|----------|----------|----------|
| Board Chair | MSPEI Board | Dr. Scott Cameron | chair@mspei.org |
| President | Executive, Incident Handler | Dr. Krista Cassell | president@mspei.org |
| Chief Executive Officer | Executive, Incident Handler, Incident Response Planner | Lea Bryden |  lea@mspei.org |
| Office Manager
 | Communications Expert, Incident Handler, Incident Response Planner | Samantha Holmes | donna@mspei.org |
| Director of Physician Health | Incident Response Planner | Karen Pyra | karenp@mspei.org |
| Director of Physician Compensation | Master Agreement, Negotiations, EMR | Samantha Holmes | sam@mspei.org |
| Associate Director of Communications | Communications Expert, Incident Handler, Note-Taker | Sheila Kerry | sheila@mspei.org |
| Economics Advisor | Incident Response Planner | Derek Law | derek@mspei.org |
| Physician Navigator | Incident Response Planner | Corinne Verleun | corinne@mspei.org |
| Finance Manager | Incident Response Planner, Incident Handler | Doug Carr | finance@mspei.org |








MSPEI Company Contact Information

Here are key contacts at MSPEI for general inquiries and specific departmental roles:



| Title | CSIRT Role(s) | Name | Contact Information |
|----------|----------|----------|----------|
| Board Chair | MSPEI Board | Dr. Scott Cameron | chair@mspei.org |
| President | Presient | Dr. Krista Cassell | president@mspei.org |
| Chief Executive Officer | CEO | Lea Bryden |  lea@mspei.org |
| Office Manager
 | General Inquiries, CME, CMPA, Member Benefits | Samantha Holmes | donna@mspei.org |
| Director of Physician Health | Physician Wellness, Health Policy | Karen Pyra | karenp@mspei.org |
| Director of Physician Compensation | Master Agreement, Negotiations, EMR | Samantha Holmes | sam@mspei.org |
| Associate Director of Communications | Media Relations, Physician Communications | Sheila Kerry | sheila@mspei.org |
| Economics Advisor | Economic Data Analysis, Master Agreement Administration | Derek Law | derek@mspei.org |
| Physician Navigator | Member and Practice Support | Corinne Verleun | corinne@mspei.org |
| Finance Manager | Accounts Payable/Receivable | Doug Carr | finance@mspei.org |






1. Incident Types
Below is a summary of potential cybersecurity incidents that MSPEI may face, along with brief descriptions of each:

- Phishing: A fraudulent attempt to obtain sensitive information by impersonating a trustworthy entity.
- Unauthorized Access or Usage: Gaining unauthorized access to systems, networks, or data.
- Service Interruption or Denial of Service: Attack preventing access to services or impairing their normal operation.
- Malicious Code: The installation of harmful software, such as viruses, worms, or Trojans.
- Ransomware: A type of malicious software that demands payment in exchange for restoring functionality to affected systems.
- Distributed Denial of Service (DDoS): Overloading servers or networks to make them unavailable to users.
- Network System Failures (Widespread): Incidents affecting the availability, confidentiality, or integrity of networks.
- Application System Failures: Incidents impacting the availability, confidentiality, or integrity of applications or systems.
- Unauthorized Disclosure or Loss of Information: Any event resulting in unauthorized disclosure or loss of sensitive data.
- Privacy Breach: The loss or exposure of personal information.
- Information Security/Data Breach: Incidents involving unauthorized access or exposure of sensitive data.
- Account Data Compromise: A breach involving payment card data.
- Other: Any additional incident affecting the organization's systems, networks, or data.




1. Incident Severity Matrix
The severity of an incident is ultimately determined by MSPEI?s Executive Team, or in certain cases, escalated to third parties such as law enforcement or a contracted Managed Security Service Provider (MSSP).

Key factors considered in determining incident severity include:

- Whether the incident affects a single system or multiple systems.
- The criticality of the affected system(s).
- Whether the incident impacts an individual, a small group, or the entire organization.
- Whether the incident affects one team or department, multiple departments, or the entire organization.
- The context of the organization at the time of the incident, which can help to fully assess the scope and urgency of remedial actions.
The CSIRT will gather all relevant information to determine the scale of the impact, estimate the potential spread of the incident, and evaluate its pace. Additionally, the CSIRT will consider the potential consequences for the organization, such as financial, reputational, or operational damage.

Incidents can vary in sophistication, ranging from simple nuisances or vandalism to complex, automated or manual cyber-attacks. Each type of incident must be considered in terms of both its immediate impact and long-term consequences.

When evaluating an incident, the following questions should be addressed:

1. Is there evidence that the vulnerability is being actively exploited?
1. Is there a known patch or fix for the vulnerability?
1. Is this incident caused by a new (zero-day) threat or a known one?
1. What is the estimated effort required to contain the incident?


Incident Severity Categories

The Incident Severity Matrix helps categorize incidents based on their scope and impact. Below are the categories and actions associated with each severity level:



| Category | Indicators | Scope | Action |
|----------|----------|----------|----------|
| 1 ? Critical | Data loss, Malware | Widespread, affecting critical servers or resulting in stolen data or unauthorized access | Activate CSIRT, implement Incident Response Plan, declare a Cyber Security Incident organization-wide. |
| 2 ? High | Theoretical threat becomes active | Widespread, involving critical systems or sensitive data | Activate CSIRT, implement Incident Response Plan, declare a Cyber Security Incident organization-wide |
| 3 ? Medium | Email phishing, or active spreading infection | Widespread but not necessarily affecting critical systems |  Activate CSIRT, implement Incident Response Plan, declare a Security Incident organization-wide. |
| 4 ? Low | Malware or phishing | Affects individual host or person | Notify CSIRT, initiate Cyber Security Incident. |




1. Incident Handling Process
Overview

In the event of a cyber security incident, the Cyber Security Incident Response Team (CSIRT) will adhere to the PICERL process, as outlined by Innovation, Science, and Economic Development Canada.

Please refer to NIST Cyber Incident Response Cycle image (NIST, 2012) for more guidance.







Preparation

To ensure preparedness for cyber security incidents, our organization commits to the following actions:

- Develop an Incident Response Plan: Establish clear mandates, decision-making authority, and chain of command.
- Plan Documentation: Create both physical and digital copies of the Incident Response Plan. The physical copy will be stored at the Head Office, on the Office Manager's desk.
- Annual Review & Updates: The Incident Response Plan will be reviewed and updated annually. The revision history will be recorded.
- Establish a Cyber Security Incident Response Team (CSIRT): This may include internal staff or external vendors, depending on capacity.
- Training and Education: Provide necessary training for all members, ensuring they are prepared for their roles and responsibilities.
- Drills and Exercises: Conduct regular exercises and simulations to practice and evaluate the response to potential cyber incidents.
- Understand the Environment: Familiarize the team with critical systems, network diagrams, data locations, and vendor dependencies. Ensure visibility into the organization's network to detect potential incidents early.
- Impact Assessment: Define Maximum Tolerable Downtime (MTD) and Acceptable Interruption Window (AIW) for critical systems.
- Prepare for Communication: Establish a war room, conference bridge, and communication channels to manage the incident. Ensure all personnel involved in handling the incident are well-informed.
- Incident Reporting Procedures: All employees must report cyber security incidents immediately to the Incident Handler or a CSIRT member. The CSIRT will maintain a central point of contact to ensure swift responses.


Identification

When a potential cyber security incident is identified, our organization commits to:

- Gathering Key Information: Immediately bring together individuals who are aware of the incident to ensure proper investigation and communication.
- Engage CSIRT Members: Activate the Cyber Security Incident Response Team to confirm the occurrence of an incident.
- Effective Communication: Ensure that all relevant parties are informed on a need-to-know basis, preventing misinformation from spreading.
- Incident Investigation: Investigate the incident by gathering and analyzing relevant data. The CSIRT will work to confirm the nature and extent of the incident by reviewing logs, conducting research, and prioritizing the actions to contain and mitigate the impact.


Containment

To prevent further damage, the organization commits to the following containment actions:

- Communication Plan: Implement the established communications plan and ensure information is disseminated accurately.
- Identify the Source: Identify the root cause of the incident, determine the exploited vulnerabilities, and take immediate corrective actions.
- Preserve Evidence: Secure and document all evidence, preserving the chain of custody for future investigations.
- Continue Assessment: Continuously evaluate the incident?s impact and scope while taking steps to prevent its escalation.


Eradication

The organization commits to eradicating the cyber security incident as follows:

- Complete Removal: Remove all traces of the incident, including malware, unauthorized access, or any exploited vulnerabilities.
- Eliminate Exploited Vulnerabilities: Ensure all identified vulnerabilities are patched or mitigated to prevent recurrence.
- Secure Affected Systems: If any compromised systems are identified, they will be removed from service, reformatted, and cleaned before reintroduction to the network.
- Assistance if Needed: If required, the CSIRT will engage external support, such as Network Security Vendors, for additional assistance.


Recovery

The organization commits to restoring normal operations through the following actions:

- Restoration of Systems: Gradually restore systems to operational status, prioritizing the most critical ones.
- Monitoring: Closely monitor the systems to ensure the incident does not recur and that all systems are functioning properly.
- Insurance Claim: If necessary, initiate claims with the cyber security insurance provider to mitigate the financial impact.


Lessons Learned

After a cyber security incident, the organization commits to the following actions:

- Post-Incident Review: Within two weeks of the incident, the CSIRT will conduct a meeting to review the handling of the incident.
- Create a Report: Document the incident from detection to resolution, including the steps taken and lessons learned.
- Continuous Improvement: Identify areas for improvement and ensure that corrective actions are implemented to prevent similar incidents in the future.
- Accountability: Ensure that any identified gaps or weaknesses in the process are addressed, and that improvements are tracked and followed up on.




1. Incident Specific Handling Process
Available Playbook/s





| Playbook Type | Link Status | Link to Playbook |
|----------|----------|----------|
| Custom Phishing Playbook |  | Phishing playbook |
|  |  |  |
|  |  |  |






1. Approvals


Responsible Party



The responsibility for the security of company and customer information rests with the following individual:



| Responsible Party Name and Title | Responsible Party Signature | Version | Date |
|----------|----------|----------|----------|
| President | Dr. Krista Cassell | 1.0 | 26 November 2024 |
|  |  |  |  |




The Responsible Party has reviewed the Incident Response Plan and delegates the responsibility for mitigating harm to the organization to the Incident Handler. In the event of a high or critical cyber security incident, this responsibility is transferred to the Incident Handler or their delegate.



MSPEI Executive Approval

The MSPEI Executive has reviewed the Security Incident Response Plan and acknowledges that, when a high or critical cyber security incident occurs, the responsibility for managing the incident is entrusted to the Incident Handler or their delegate. The Executive or their delegate is expected to oversee the handling of the incident, ensuring all actions?identification, containment, eradication, recovery, and lessons learned?are carried out effectively to mitigate further exposure to the organization.





| MSPEI Executive Name and Title | MSPEI Executive Signature | Version | Date |
|----------|----------|----------|----------|
| Chief Executive Officer | Lea Bryden | 1.0 | 26 November 2024 |
|  |  |  |  |








1. References


Innovation, Science and Economic Development Canada. (n.d.). Develop an incident response plan: Fillable template and example. CyberSecure Canada. Retrieved November 26, 2024 from https://ised-isde.canada.ca/site/cybersecure-canada/en/certification-tools/develop-incident-response-plan-fillable-template-and-example

National Institute of Standards and Technology. (2012). Computer security incident handling guide (Special Publication 800-61 Revision 2). U.S. Department of Commerce. Retrieved November 26, 2024 from 

https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf



Swimlane. (n.d.). Incident response: A guide to improving your process. Retrieved November 24, 2024, from https://swimlane.com/blog/incident-response/



1. Revision History




| Date | Version | Modification | Modifier |
|----------|----------|----------|----------|
| 26 November 2024 | 1.0 | Document created | Quin Fabros |
| 27 November 2024 | 1.1 | Document Updated | Quin Fabros |
|  |  |  |   |




