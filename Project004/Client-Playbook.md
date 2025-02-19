[Playbook-Cat and Box](https://docs.google.com/open?id=10znLJBkURZb7IJJCGfs11SJpIwqKeDq5TL-ThfRyIvA)

Client Playbook

Cat and Box







1. Executive Summary
1. Overview: Box Manufacturing has limited in-house cybersecurity capabilities. To address their security needs, the client requests clear workflow and communication templates. They also need MSSP(Managed Security Service Provider to oversee their security needs. 
1. Objective: To develop custom incident response workflow for Box and stakeholders so that they can be informed in a structure way through clear communication channels, role definitions and escalation procedures
1. Key Points: SOC(Security operations Center) manages detection and containment and Cat oversees escalation. Misha(production manager) handles incidents about operations. Pery(Ceo) receives updates on severe and unresolved issues.




1. Incident Response Workflow


1. Incident Type Selection: Phishing attack

- Trigger points:: Unusual login attempts, suspicious emails reported by employees, or unauthorized access attempts.
















 SOC Organizational Chart(Box Company)



SOC Methodology



- Client (Box Manufacturing)
1. Mr. Percy F., CEO: Informed only in urgent cases, after 48 hours, or if escalation is necessary.
1. Miss Misha F., Production Manager: Informed of incidents during working hours, receiving an executive summary if an issue could impact production.
1. Dusty, Database Specialist: Handles issues affecting database integrity.
1. Lucky, IT Support Specialist: First responder for user-related technical issues.
1. Ned, Network Administrator: Manages network-related incidents.
- Third-Party Provider (MSSP & SOC)
1. Cat, Lead Security Consultant: Handles escalations, approves playbooks, and manages communications with external entities.




1. Incident Response Workflow Steps


### SOC EIR Handbook

Alert plans



1. Detection

Conditions: Phishing attempts, or suspected breaches

Contact: Misha (Production Manager)

Action: Send an executive summary and incident details highlighting major security events it?s potential impacts on the company



2. Triage

Process: SOC assesses the incident severity and gathers initial data (e.g., IP addresses, email sources) to determine impact level.

If high severity (e.g.,sensitive data exposed), proceed with alert escalation)



3. Escalation

Conditions: Cases of major incidents or 48+ hours unresolved breaches

Contact: Percy (CEO)

Action: Send a summary to Percy, detailing unresolved issues, severity updates, potential impact, and mitigation efforts.



4. Containment

Process: SOC isolates affected systems, resets compromised accounts, and restricts network access to prevent the spread of the incident.

Involved Parties: Lucky (IT Support Specialist) and Ned (Network Administrator) for technical containment actions.



5. Communication

Process: Cat (SOC Lead Consultant) keeps Misha informed during business hours, and Minka after hours, with updates if operations are at risk. 

If escalation conditions are met, provide updates to Percy(Ceo)

Action: Issue vigilance notice to employees and coordinate with MSSP for further containment and investigation.



6.Resolution

Process: SOC, along with Dusty (Database Specialist), Lucky, and Ned, implements necessary remediation steps to restore system security and address vulnerabilities.

Action: Document actions taken, finalize remediation, and secure compromised systems.



7. Follow-Up

Process: SOC provides a final report to Cat for review, including a detailed incident timeline, lessons learned, and preventive recommendations.

Action: Cat summarizes and communicates findings to Box?s leadership. Update operational handbooks with insights from the incident.









SOC Operational Handbook



Directive: Follow each step below, using Y/N options (mark as ?Yes? if checked and ?No? if unchecked)





1.Detection



1.0 Confirm Incident Occurrence

- If a security incident has taken place.
1.1 Information Gathering

- Collect relevant details and information from the reported incident (e.g., suspicious email).
- Document:
1. Sender?s email address
1. Date and time of the email
1. Content of the email
- Access Check: Do you have immediate, authorized access to the email server?
1. If Yes, collect:
1. Source|destination IP addresses
1. Ports associated with the reported email
1.2 Phishing Indicators Analysis

- Review the email for phishing indicators 
If indicators are present, proceed immediately to next step

- Key indicators to check:
1. Pressure tactics, deadlines, or promises of rewards
1. Vague language, typographical errors, indirect references, inconsistencies
1. Spoofed email address
- Ask the user if they:
1. Click any links, or opened attachments, followed any URLs in the email, 
1. Noticed any unusual behavior (e.g., abnormal CPU usage, device heat, slowness, increased bandwidth usage)
1.3 Assess Information Leakage

- User Inquiry: Ask the user if they responded with any sensitive information or secrets.
1. If Yes, label as "Information Leak."
1. Document the type of information leaked and escalate this information as needed.




1. 
2. Extract URLs and Assess IP Reputations

- Extract all embedded URLs from the email content and resolve the URLs to their associated IP addresses.
- Check each collected IP.
If an IP is flagged as malicious, mark it as a ?true positive? and escalate the relevant information.

1. True Positive (if identified as a bad IP)




3. Notify MSSP (Managed Security Service Provider)

- Use the appropriate contacts and communication channels listed in the SOC EIR Handbook (MSSP's preferred communication protocol).
Use multiple contact points if necessary to ensure a timely response.





3.1 SOC Analyst Ticket Creation

- As a SOC analyst, open a ticket for a suspected breach and phishing attack.
- Forward all collected information to the MSSP by attaching the relevant data to the ticket.










3.2 Initiate alert plan

- Complete 'Suspected phishing' template with necessary information
- Locate Day-time Production Manager?s contact details in EIR Handbook and send finalized executive summary to Day-time Production Manager






3.3 Increase awareness

- Use the short notice template to inform organization members.To preemptively prevent or slow the spread of potential threats and employee awareness of risk
- Send notice to relevant production employees listed in EIR handbook.








4. Gather Additional Information & Check for Phishing Campaign on Web Server Access



4.1 Review Step 1.1

- If ?Reported Email Source and Destination IP/Port? was not collected, do so now:
1. Forward this information to the open ticket.
4.2 Query the Email Server for Correlation

- Contact IT as needed.
- Collect and attach to ticket
1. Emails from the same source address or IP;emails containing the same malicious URLs; emails with similar content (subject, body)
4.3 Check for Information Leakage

- For each suspicious email, verify if recipients replied or shared sensitive information.
1. If sensitive data was leaked, mark ?Information Leakage.?
1. Status: Information Leakage
1. Collect details on leaked information, attach to the ticket, and increase ticket priority based on the severity levels
4.4 Check for Phishing Campaign Indicators

- For each email identified in the phishing attack, gather:
1. Source email, IP, and port
1. Destination email, IP, and port
1. Resolved IPs of embedded URLs
1. Email content (headers and body)
- Review reputation for all collected IPs:
1. Resolved URL IP reputation
1. Source email IP reputation
- Forward the phishing campaign analysis to the open ticket.




5. Analyze URLs

- Analyze malicious URLs in a sandbox to observe:
1. Unusual processes, performance anomalies, suspicious behavior
- Document findings, compile a report, and attach it to the ticket.




6. MSSP Response

- Ensure timely compliance with MSSP requests or guidelines.
- MSSP will determine one of two outcomes:
Outcome 1) No Incident Detected	Follow MSSP's de-escalation procedures. Notify relevant stakeholders as needed and close the phishing response playbook.Document updates in the operational handbook.

Outcome 2) Confirmed Incident	If MSSP confirms an incident, mark ?Incident Confirmed.? Status: Incident Confirmed .Record date and time. Incident confirmed on. Note the official name of the attack.Incident Name.





6.1 MSSP Guidance and Directives

- Important: MSSP takes the lead.
- Follow MSSP directives and prioritize them within this playbook?s processes.


6.2 Compile Incident Report Information Based on MSSP Guidance

- Document:
1. Severity level (SVE Level), Incident impact
1. Operational relevance (effect and duration), effect of MSSP directives on operations
1. Summary of the current incident response


6.3 Activate EIR Handbook Alert Plan on Confirmed Breach

- Use designated message templates for alert notifications.
- Use the ?Confirmed Incident Executive Summary? template to inform the CEO
1. Locate CEO contact in the EIR Handbook.
1. Send the completed executive summary to the Box CEO.








6.4 Notify Operations if Production is Impacted

- Assess if the incident could potentially affect production.
1. If Yes, mark as "Production Impact."
1. Status: Production Impact
- If production impact is confirmed, complete the following details:
1. Changes to operations: ______
1. Estimated duration of operational changes: ______
- Use the ?Operations Impact? template below.
1. Locate the Production Manager's contact in the EIR Handbook.
1. Send the completed Operations Impact form to the Box Production Manager.
1. 








6.5 Notify Executive if Breach Remains Unresolved After 48 Hours

- Confirm if 48 hours have passed since the MSSP?s initial response (refer to step 6)
1. If Yes, mark "48 Hours Elapsed."
1. Status: 48 Hours Elapsed
- Verify if the breach remains active or unresolved.
1. If Yes, mark "Breach Unresolved."
1. Status: Breach Unresolved
- Document changes since the MSSP?s initial response:
1. Severity of incident: increased / decreased / no change
1. Impact of incident: increased / decreased / no change
1. Current stage of incident response: _______ / no change
- If both "48 Hours Elapsed" and "Breach Unresolved" are marked, use the "48-Hour Unresolved Breach" template below.
1. Locate the CEO's contact in the EIR Handbook.
1. Send the completed template to the Box CEO.






7. Follow MSSP Directives for Next Stages

- The MSSP will outline the next steps and procedures to follow. Adhere to MSSP?s directives for each phase:
1. Containment|Eradication|Recovery|Post-Incident Activity
- If "Post-Incident Activity" is selected:
1. Close the phishing playbook.
1. Document everything in the operational handbook.
1. 




1. Conclusions
This  outlines an incident response workflow tailored to Box Manufacturing's cybersecurity needs, ensuring effective communication and resolution of security incidents, specifically phishing attacks. By establishing roles, escalation procedures, and alert plans, the SOC can effectively manage incidents while minimizing impact on operations. The collaboration with a third-party MSSP enhances the organization?s security posture, providing both immediate response capabilities and preventive strategies. 





1. Reference/s


SecureGlobal. (n.d.). The SOC methodology. Retrieved November 8, 2024, from https://secureglobal.de/the-soc-methodology



PagerDuty. (n.d.). Incident workflows. Retrieved November 8, 2024, from https://support.pagerduty.com/main/docs/incident-workflows



Li, B. (2023, August 23). Create a playbook. In Introduction to security orchestration, automation, and response (SOAR). LinkedIn Learning. Retrieved November 8, 2024, from https://www.linkedin.com/learning/introduction-to-security-orchestration-automation-and-response-soar/create-a-playbook?u=0



Microsoft Press, & Nemnom, C. (2024, September 18). Trigger playbooks manually from alerts and incidents. In Microsoft security operations analyst associate (SC-200) cert prep. LinkedIn Learning. Retrieved November 8, 2024, from https://www.linkedin.com/learning/microsoft-security-operations-analyst-associate-sc-200-cert-prep-by-microsoft-press/trigger-playbooks-manually-from-alerts-and-incidents?u=0



Lighthouse Labs. (2022). Top security playbooks 2022. Retrieved November 11, 2024, from https://learningimages.lighthouselabs.ca/Cyber+BC/Cyber+BC+C4/Top_Security_Playbooks_2022.pdf



National Institute of Standards and Technology. (2012). Computer security incident handling guide (NIST Special Publication 800-61 Revision 2). U.S. Department of Commerce. Retrieved November 9, 2024, from https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf



Treasury Board of Canada Secretariat. (n.d.). Security playbook for information system solutions. Government of Canada. Retrieved November 9, 2024, from https://www.canada.ca/en/government/system/digital-government/digital-government-innovations/cloud-services/security-playbook-information-system-solutions-cloud.html

Public Safety Canada. (n.d.). Real examples of fake emails. Get Cyber Safe. Retrieved November 9, 2024, from https://www.getcybersafe.gc.ca/en/resources/real-examples-fake-emails

PagerDuty. (n.d.). Severity levels. Retrieved November 10, 2024, from https://response.pagerduty.com/before/severity_levels/



Splunk. (n.d.). Incident severity levels. Retrieved November 10, 2024, from https://www.splunk.com/en_us/blog/learn/incident-severity-levels.html









1. Revision Table




