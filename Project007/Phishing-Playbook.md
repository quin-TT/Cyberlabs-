[Phishing Playbook](https://docs.google.com/open?id=16KfYp5orfxhwr0MEBDb-B8iRoPv84eVAfqcaQCM96-Y)

Phishing Playbook

The Medical Society of Prince Edward Island











1. Related Policies
Add further policies as required and developed.



| Playbook Type | Link Status | Link to Playbook |
|----------|----------|----------|
| Email Policy |  | E-mail Policy |
| Alert Email Policy |  | Alert E-mail  Policy |








1. Playbook Test & Review Cycle
Annual testing of the Phishing Playbook is essential to ensure that the Cyber Security Incident Response Team (CSIRT) is well-prepared and understands their roles and responsibilities.

- Testing Frequency: The Phishing Playbook will be tested at least once per year.
- Testing Methodology: The testing will simulate potential phishing incidents to assess and identify process gaps.
- Evaluation: Observations during testing will be documented by the CSIRT to highlight areas requiring improvement.
- CSIRT Responsibility: Incident Handlers must adhere to the procedures in the Phishing Playbook, and the MSPEI CSIRT Executive will ensure that the playbook is updated and distributed accordingly.


III.   Phishing Playbook



This playbook is a manual process guide. Follow the steps outlined and use the checkboxes:

Example:

1. unchecked
1. checked 






1. Detection and Analysis



1. From Human or System Detection Sources:
1. Determine whether an incident has occurred.
1. Actions:
1. Gather the reported email:


1. Date and time of received email
1. Recipient and sender email addresses
1. Content (code as text)
1. If authorized access to email servers is available, collect:
1. Source and destination IP/port of reported email


1. Analyze the Email for Indicators of Phishing:
1. Look for:
1. Spoofed email addresses
1. Urgency, deadlines, or rewards
1. Vague content, typos, or inconsistent references
1. On the victim?s machine, check:
1. Whether any URLs were followed, clicks made, or unusual processes observed.


1. Information Leak Check:
1. Ask the user if sensitive information was shared. If yes, escalate immediately and collect leaked information.






2. Collect Identifying Information



1. Extract all URLs from the email content.
1. Resolve URLs to IPs and check for reputations.
1. Mark the incident as a "True Positive" if bad IP addresses are identified and escalate the information accordingly.


1. True Positive




3. Escalate



Based on the Escalation Policy( Incident Response Plan) use appropriate channels to escalate:

1. Select escalation contact.
1. Select the communication channel (email, phone, etc.).
1. Once both are selected, proceed to 3.1


3.1 Initial Escalation Communication

- Send an email to the escalation contact.
- Fill out the "First Escalation Template" with required information.
- Send the template to the designated escalation contact.


Escalation Template Example:

Please complete and attach the necessary details into the 'Initial Escalation Template,' replacing information inside <> with the gathered data:











Send the completed template to the Escalation Contact:

1. Completed 'First Escalation Template' email and sent








3.2 Alert Plan Policy Trigger



1. Send internal notification of the suspected phishing attack to all relevant MSPEI employees.
1. Fill-in required information


Email Content Example:











4. Escalation Response



- Outcome a: If the escalation authority declares no incident, follow de-escalation procedures and close the playbook.
- Outcome b: If a confirmed incident is declared, continue to 4.1.
a) Escalation authority declares that no incident is in place.

1. Follow MSPEI descalations directives and guidelines.
1. Provide de-escalation email to contacted members, if needed.
1. Close the Phishing Playbook.
1. Report learnings in the Phishing Playbook handbook (see end of document).
b) Escalation authority declares a confirmed named Incident.Mark 'confirmed named Incident', if escalation authority declared a confirmed named Incident.

1. confirmed named incident(Phishing, Unauthorized Access, Malicious Code, etc.).


If 'confirmed named incident' if checked, continue to 4.1





4.1 Confirm the Named Incident



1. Phishing
1. Malicious Code
1. Ransomware
1. Privacy Breach
1. Unauthorized Disclosure or Loss of Information
1. Service Interruption or Denial of Service
1. Distributed Denial of Service (DDoS)
1. Network System Failures 
1. Application System Failures
1. Unauthorized Access or Usage
1. Information Security/Data Breach
1. Account Data Compromise
1. Other/s




4.2 The Alert Plan Policy is triggered.Send an 'Confirmed phishing' email alert.

1. Send to relevant organization employees.


1. Confirm the nature of the incident (Phishing, Unauthorized Access, Malicious Code, etc.).
1. Prepare a Confirmed Incident Alert email to MSPEI employees.














Email Content Example:



















5. Post-Escalation



- Follow the guidance through the next phases of the Incident Response Life Cycle:
1. Containment
1. Eradication
1. Recovery
1. Post-Incident Activity
- Report lessons learned and close the playbook once Post-Incident Activity is completed.


If 'Post-Incident Activity' is checked,

1. Close the phishing playbook.
1. Report learnings in the Phishing Playbook handbook (see end of document).




IV.  Learning Reports History Table





| Date | Paybook Version | Lessons learned | Author |
|----------|----------|----------|----------|
|  | 1.0 | [Summary of Lesson Learned] |  |
|  |  |  |  |
|  |  |  |   |






V.  Reference/s



SANS Institute. (2022, July 25). The use of playbooks in the incident response process. https://www.sans.org/white-papers/the-use-of-playbooks-in-the-incident-response-process/



Atlassian. (n.d.). How to create an incident response playbook. Atlassian. https://www.atlassian.com/incident-management/incident-response/how-to-create-an-incident-response-playbook#incident-response-lifecycle







VI . Revision History Table



| Date | Version | Modification | Modifier |
|----------|----------|----------|----------|
| 26 November 2024 | 1.0 | Document created | Quin Fabros |
| 27 November 2024 | 1.1 | Document Updated | Quin Fabros |
|  |  |  |   |






