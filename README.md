# CTI Automation Platform

## Planned Platform Stack (Stage 1):
* MISP deployment via Docker Compose
  * Base OS: Ubuntu Focal
  * MISP_Web Container: 2GB RAM
  * MySQL Server Container: 2GB Memory Limit
* Elastic SIEM (agent based)
* Windows-based Malware Analysis Virtual Machine (VM)
  * Deployed via Vagrant (for quick teardown and re-creation)
  * Provisioned via Ansible (Chocolatey) and Powershell Scripts
  * Would include tools such as Regshot, TShark/TCPDump, Process Hacker etc.
  * Would be running the Elastic SIEM agent for log collection and analysis
* Node for storing encrypted payloads (this may be possible within MISP itself)
* PyMISP based scripts for deploying payloads to the sandbox for threat emulation (fixed scenarios)
* Jupyter Notebooks for dashboarding and generating various CTI-related metrics, and performing link analysis (graph visualization), MITRE ATT&CK Heatmap

## MISP Threat Intel Platform (TIP)

https://www.misp-project.org/features/

MISP provides capabilities for managing Indicators of Compromise (IOC) and curating a knowledgebase to enable efficient tracking of entities related to Cybersecurity Threats (Malware Families, Threat Actors, Incidents, Campaigns). Additionally, MISP can be integrated with security controls to aid in detecting malicious behavior. 

Features:

- STIX Data Model enables efficient correlation of indicators and entities.
- Existing integrations with many popular threat data feeds.
- Python-based Expansion modules aimed at extending the platform's functionality.
- User Interface for creation and management of threat data

API: [PyMISP SDK](https://github.com/MISP/PyMISP)

MISP Instance Architectural Components:

[MISP dependencies](https://wlcg-soc-wg-doc.web.cern.ch/misp/deployment.html)
- Redis
- MySQL Server

Ingesting logs into ELK:
https://unicornsec.com/home/siem-home-lab-series-part-2
