[link](https://docs.google.com/open?id=1vcR-gbN_uv7Xk0couyh7yqsen1_ACVwl3TbpqLqCWYg)

Secure Architecture and Recommendations Report

Premium House Lights









## Executive Summary



Premium House Lights (PHL) currently operates without any security measures in place. This initiative aims to establish robust security controls and address existing vulnerabilities. The success of this operation depends on the implementation of the outlined Action Plan.

The framework utilized in this document is the NIST Cybersecurity Framework (CSF), as depicted. For a comprehensive overview, refer to the Security Architecture Goals section.

## 



## Intended Audience & purpose

This document is intended for individuals and teams responsible for securing Premium House Lights. The Action Plan table provides detailed security controls recommended for implementation.



|  |  |
|----------|----------|


## Authority

Responsibility for the security of company and customer information resides with the President.



| Title | Role | Name | Contact |
|----------|----------|----------|----------|
| President | President of Premium House Lights | Owner  | president@premiumhouselights.ca |
| I.T specialist | Operates Premium House Lights? network | TBD | TBD |
|  |  |  |  |












Implementation timeline / Roadmap



| Phase | Timeline | Key Activities |
|----------|----------|----------|
| Immediate actions | 1 day | Disclose data breach and
Isolate network |
| Core Implementations | 5-20 days | Segregate network
Update and Harden Systems |
| Security Education | 20-40 days | Educate organization on security
Build security culture |
| Monitoring | 5-20 days | Establish Monitoring |










Security Architecture GoalsThe following goals are reflected in the Control Table and Action Plan:

- Data compliance for PII
- Data breach disclosure policy
- System hardening, maintenance
- Service monitoring
- Network segregation and Target Topology
- Risk-aware security culture


| Current topology | Target Topology  |
|----------|----------|
|  | 

 |








Controls Table





| Frameworks | NIST CSF 2.0 - NIST CSF 2.0CIS CSC V.8.0 - CSC V.8.0NIST RMF Various |  |  |
|----------|----------|----------|----------|
| Approach | Internal Controls Approach |  |  |
| Function | Category
Identifier | Subcategory
 | Control & Related Controls |
| GV:Govern | GV.RR:Roles, Responsibilities,Authorities | GV.RR-01 | Leadership is responsible and accountable for cybersecurity risk and promotes a culture that is risk-aware, ethical, and continually improving.

NIST CSF:NIST SP 800-53
GV.RR-01: AT-2: Literacy Training         and Awareness
  |
| ID:Identify |  |  |  |
| PR:Protect | PR.DS:Data Security | PR.DS-01 | Encrypt Sensitive Data at Rest.

NIST CSF:PR.DS-01
CIS CSC:CSC 3.11 |
|  | PR.IR:Technology Infrastructure Resilience | PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage.

NIST CSF: PR.IR-01 |
|  | PR.PS:Platform Security | PR.PS-02 | Operating system and Software is maintained, replaced, and removed commensurate with risk
NIST CIF: PR.PS-02 |
| DE:Detect | DE.CM:
Continuous Monitoring | DE.CM-09
 | Hardware and software, runtime environments, and their data are monitored to find potentially adverse events

NIST CIF:DE.CM-09 |
| RS:Respond |  |  |  |
| RC:Recover | RC.CO: Incident Recovery Communication | RC.CO-04 | Public updates on incident recovery are shared using approved methods and messaging.

NIST CSF:RC.CO-04 |


# 

# Action Plan

## 

The action plan is separated by NIST CSF functions (GV,ID,PR,DE,RS,RC).Guide: Use or edit implementation guidelines and enforce controls through reviews. See Control?s table.



| GV: Govern |  |  |  |  |  |
|----------|----------|----------|----------|----------|----------|
| Control | Threat | Implementation | RiskOwner | ImplementDate | Last ReviewDate |
| GV.RR-01 | Non-Compliance | Leaders establish clear roles and responsibilities for developing, implementing and evaluating cybersecurity strategy.
Communicate risk management expectations to foster a secure culture, considering current events and challenges | President |  |  |




| ID: Identify |  |  |  |  |  |
|----------|----------|----------|----------|----------|----------|
| Control | Threat | Implementation | RiskOwner | ImplementDate | Last ReviewDate |
|  |  |  |  |  |  |




| PR: Protect |  |  |  |  |  |
|----------|----------|----------|----------|----------|----------|
| Control | Threat | Implementation | RiskOwner | ImplementDate | Last ReviewDate |
| PR.DS-01 | Data integrity, confidentiality | Encrypt Sensitive Data at Rest using AES-128. | President |  |  |
| PR.IR-01 | Lateral Movement | Create and maintain a secure network setup that separates parts of the network using tools(IP subnets and VLANs), limits access to only what?s needed, and ensures the system remains reliable and accessible  | IT Specialist |  |  |
| PR.PS-02 | Unauthorizedaccess | Harden and update systems.Uninstall and remove unauthorized software (nmap) and services that pose undue risks.  | IT Specialist |  |  |






| DE:Detect |  |  |  |  |  |
|----------|----------|----------|----------|----------|----------|
| Control | Threat | Implementation | RiskOwner | ImplementDate | Last ReviewDate |
| DE.CM-09 | Exfiltration.Unauthorizedaccess. | Monitor for signs of tampering with the database, and the MySQL Tables. Consider using a monitor such as PRTG MySQL V2.0. | IT Specialist |  |  |




| RS: Respond |  |  |  |  |  |
|----------|----------|----------|----------|----------|----------|
| Control | Threat | Implementation | RiskOwner | ImplementDate | Last ReviewDate |
|  |  |  |  |  |  |




| RC: Recover |  |  |  |  |  |
|----------|----------|----------|----------|----------|----------|
| Control | Threat | Implementation | RiskOwner | ImplementDate | Last ReviewDate |
| RC.CO-04 | Data Breach | Follow the organization's breach notification procedures when responding to a data breach incident. Clearly outline the actions being taken to recover from the breach and the measures implemented to prevent recurrence. | President |  |  |


# 

# Reference/s

NIST. (2024, February 26). Cybersecurity framework v2.0. Retrieved January 6, 2025 https://csf.tools/reference/nist-cybersecurity-framework/v2-0/

SANS Institute. (n.d.). Critical security controls version 8. Retrieved January 6, 2025 , from https://csf.tools/controlset/csc-v8/



SANS Institute. (n.d.). STRIDE-LM threat model. Retrieved January 6, 2025 , from https://csf.tools/reference/stride-lm/









## Version Control table



| Date | Version | Assessor?s Name | Contact | Last Reviewed Date |
|----------|----------|----------|----------|----------|
| 6 January 2025 | 1.0 | Quin Fabros | quinfabros@premiumhouselights.ca | 6 January 2025 |
|  |  |  |  |  |
















