# Security Information Management and Security Event Management (SIEM)
## SIEM Introduction
Security Information and Event Management (SIEM) is a cornerstone of modern cybersecurity operations. It centralizes the collection, normalization, and analysis of security-relevant data from diverse systems, enabling real-time threat detection, incident response, and compliance reporting. By correlating events across an organization’s infrastructure, SIEM helps security teams identify, contextualize, and respond to potential attacks before they cause damage.

## Elastic Stack
### Elasticsearch
Json based search engine, it handles indexing, storing, and querying
### Logstash
responsible for collecting, transforming, and transporting log file records
### Kibana
responsible for visualisation
### Beats
is additional, is for forwarding logs from remote maschines
### The Elastic Stack As A SIEM Solution
#### Kibana Query Language (KQL)
KQL queries are made out of a field:value pair.
```
event.code:4625
```