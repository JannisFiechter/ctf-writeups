# Incident Handling

## Examples
- Data theft
- Funds theft
- Unauthorized access to data
- Installation and usage of malware and remote access tools


Other types of incidents, such as those caused by malicious insiders, availability issues, and loss of intellectual property, also fall within the scope of incident handling. A comprehensive incident handling plan should address various types of incidents and provide appropriate measures to identify, contain, eradicate, and recover from them to restore normal business operations as quickly and efficiently as possible.
<br>
Incident handling is a clearly defined set of procedures to manage and respond to security incidents in a computer or network environment.

## Cyber Kill Chain
The cyber kill chain consists of seven (7) different stages

### recon 
This phase involes where the attacker chooses his target and also does information gathering

### weaponize
Some exploit or deliverable payload is crafted

### delivery
In the delivery stage, the exploit or payload is delivered to the victim

### exploiteation
The exploitation stage is the moment when an exploit or a delivered payload is triggered

### installation
installation stage can be carried out in various ways, depending on the attacker's goals and the nature of the compromise. Some common techniques used in the installation stage include:
- Droppers: A dropper is a small piece of code that is designed to install malware on the system
- Backdoors: The backdoor may be installed by the attacker during the exploitation stage or delivered through a dropper. Once installed, the backdoor can be used to execute further attacks or steal data from the compromised system.
- Rootkits: A rootkit is a type of malware that is designed to hide its presence on a compromised system

### command & control
In the command and control stage, the attacker establishes a remote access capability to the compromised machine

### action
The objective of each attack can vary. Some adversaries may go after exfiltrating confidential data, while others may want to obtain the highest level of access possible within a network to deploy ransomware. 


## Incident Handling Process Overview

### Preparation
- Network Protection
- Privilege Identity Management
- Vulnerability Scanning
- User Awareness Training
- Active Directory Security Assessment

### Detection & Analysis
It is highly recommended to create levels of detection by logically categorizing our network as follows.
- Detection at the network perimeter (using firewalls, internet-facing network intrusion detection/prevention systems, demilitarized zone, etc.)
- Detection at the internal network level (using local firewalls, host intrusion detection/prevention systems, etc.)
- Detection at the endpoint level (using antivirus systems, endpoint detection & response systems, etc.)
- Detection at the application level (using application logs, service logs, etc.)

#### Initial Investigation
- Date/Time when the incident was reported. Additionally, who detected the incident and/or who reported it?
- How was the incident detected?
- What was the incident? Phishing? System unavailability? etc.
- Assemble a list of impacted systems (if relevant)
- Document who has accessed the impacted systems and what actions have been taken. Make a note of whether this is an ongoing incident or the suspicious activity has been stopped
- Physical location, operating systems, IP addresses and hostnames, system owner, system's purpose, current state of the system
- (If malware is involved) List of IP addresses, time and date of detection, type of malware, systems impacted, export of malicious files with forensic information on them (such as hashes, copies of the files, etc.)

| Date       | Time of the event | Hostname     | Event description                    | Data source        |
|-----------|------------------|-------------|--------------------------------------|-------------------|
| 09/09/2021 | 13:31 CET        | SQLServer01 | Hacker tool 'Mimikatz' was detected   | Antivirus Software |

#### Incident Severity & Extent Questions
- What is the exploitation impact?
- What are the exploitation requirements?
- Can any business-critical systems be affected by the incident?
- Are there any suggested remediation steps?
- How many systems have been impacted?
- Is the exploit being used in the wild?
- Does the exploit have any worm-like capabilities?

IOC = indicator of compromise 
### Containment, Eradication, & Recovery Stage

#### Containment
In this stage, we take action to prevent the spread of the incident. We divide the actions into short-term containment and long-term containment. It is important that containment actions are coordinated and executed across all systems simultaneously. Otherwise, we risk notifying attackers that we are after them, in which case they might change their techniques and tools in order to persist in the environment.
<br>
In short-term containment, the actions taken leave a minimal footprint on the systems on which they occur. Some of these actions can include, placing a system in a separate/isolated VLAN, pulling the network cable out of the system(s) or modifying the attacker's C2 DNS name to a system under our control or to a non-existing one. The actions here contain the damage and provide time to develop a more concrete remediation strategy. Additionally
<br>
In long-term containment actions, we focus on persistent actions and changes. These can include changing user passwords, applying firewall rules

#### Eradication
Once the incident is contained, eradication is necessary to eliminate both the root cause of the incident and what is left of it to ensure that the adversary is out of the systems and network. Some of the activities in this stage include removing the detected malware from systems, rebuilding some systems, and restoring others from backup. 

#### Recovery
In the recovery stage, we bring systems back to normal operation. Of course, the business needs to verify that a system is in fact working as expected and that it contains all the necessary data.
<br>
Typical suspicious events to monitor for are:

- Unusual logons (e.g. user or service accounts that have never logged in there before)
- Unusual processes
- Changes to the registry in locations that are usually modified by malware

### Post-Incident Activity Stage

In this stage, our objective is to document the incident and improve our capabilities based on lessons learned from it.

#### Reporting

The final report is a crucial part of the entire process. A complete report will contain answers to questions such as:

- What happened and when?
- Performance of the team dealing with the incident in regard to plans, playbooks, policies, and procedures
- Did the business provide the necessary information and respond promptly to aid in handling the incident in an efficient manner? What can be improved?
- What actions have been implemented to contain and eradicate the incident?
- What preventive measures should be put in place to prevent similar incidents in the future?
- What tools and resources are needed to detect and analyze similar incidents in the future?

## Documents
- NIST's Computer Security Incident Handling Guide: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf