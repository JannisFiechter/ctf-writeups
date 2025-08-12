
The KQL query event.code:4625 filters data in Kibana to show events that have the Windows event code 4625. This Windows event code is associated with failed login attempts in a Windows operating system.
## KQL Query examples
- event.code:4625
- "svc-sql1"
- event.code:4625 AND winlog.event_data.SubStatus:0xC0000072
- event.code:4625 AND winlog.event_data.SubStatus:0xC0000072 AND @timestamp >= "2023-03-03T00:00:00.000Z" AND @timestamp <= "2023-03-06T23:59:59.999Z"
- event.code:4625 AND user.name: admin*

### Filters out Computer accounts
- NOT user.name: *$ AND winlog.channel.keyword: Security


### How to identify the available fields and values?
#### Data and field identification approach 1: Leverage KQL's free text search
[Windows securitylog id's](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)

Using KQL's free text search we can search for "4625". In the returned records we notice event.code:4625, winlog.event_id:4625, and @timestamp
- event.code is related to the Elastic Common Schema (ECS)
- winlog.event_id is related to Winlogbeat
	- If the organization we work for is using the Elastic stack across all offices and security departments, it is preferred that we use the ECS fields in our queries for reasons that we will cover at the end of this section.
- @timestamp typically contains the time extracted from the original event and it is different from event.created


# What is MITRE ATT\&CK?

MITRE ATT\&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary behavior based on real-world observations.
[MITRE ATT\&CK](https://attack.mitre.org/)

## Purpose

* Helps organizations understand, detect, and respond to cyber threats.
* Standardizes how threats are described and analyzed.

## Structure

MITRE ATT\&CK is organized into:

* **Tactics**: The "why" of an attack (e.g., Initial Access, Execution).
* **Techniques**: The "how" an attacker achieves a tactic (e.g., Phishing, PowerShell).
* **Sub-techniques**: More specific ways a technique is carried out.

## Use Cases

* Threat detection
* Red/blue teaming
* Security gap analysis
* Threat intelligence mapping

## Versions

There are multiple matrices, including:

* Enterprise
* Mobile
* ICS (Industrial Control Systems)

MITRE ATT\&CK is maintained by the MITRE Corporation and is freely available at [attack.mitre.org](https://attack.mitre.org).


## How to Build SIEM Use Cases

1. **Assess Needs and Risks**
   Identify your organization’s requirements, key assets, and potential threats. Ensure alert coverage across all critical systems.

2. **Define Priorities and Map to Frameworks**
   Evaluate the impact and urgency of threats. Map alerts to the MITRE ATT\&CK framework or cyber kill chain to provide context.

3. **Set Detection and Response Metrics**
   Define Time to Detection (TTD) and Time to Response (TTR) to measure SIEM efficiency and analyst performance.

4. **Create SOPs for Alerts**
   Develop Standard Operating Procedures (SOPs) for handling each alert type to ensure consistent and effective responses.

5. **Refine Alerts Continuously**
   Monitor alert behavior and refine rules to reduce false positives and improve accuracy.

6. **Develop an Incident Response Plan (IRP)**
   Prepare a clear response strategy for confirmed incidents to minimize damage and recovery time.

7. **Set SLAs and OLAs**
   Define Service Level Agreements (SLAs) and Operational Level Agreements (OLAs) to coordinate alert response efforts across teams.

8. **Implement Audit and Review Processes**
   Establish a process for reviewing alerts and incident handling, ensuring compliance and performance tracking.

9. **Document Logging and Alert Details**
   Maintain records of system logging status, alert logic, and frequency to support tuning and audits.

10. **Build a Knowledge Base**
    Create a centralized resource with relevant information, alert handling procedures, and case management tool updates.

