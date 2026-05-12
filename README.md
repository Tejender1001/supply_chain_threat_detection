# supply_chain_threat_detection
SOC based supply chain threat detection using SBOM analysis, Trivy, Wazuh SIEM, FIM and automated CI/CD security gate
# Supply Chain Threat Detection Lab

## Overview
This project is a DevSecOps-based Supply Chain Threat Detection Lab designed to identify vulnerable dependencies, classify CVEs by severity, and automatically block code pushes when critical vulnerabilities are detected.

The system integrates vulnerability scanning, monitoring, and automated policy enforcement to strengthen software supply chain security during development and deployment.

---

## Key Features

- Detected **54 CVEs** across project dependencies
- Classified vulnerabilities into:
  - Low
  - Medium
  - High
  - Critical
- Automatically blocked code push/build when critical vulnerabilities were found
- Real-time monitoring and alerting using Wazuh
- Automated dependency scanning using Trivy
- Isolated testing using Virtual Machines

---

## Technologies Used

| Technology | Purpose |
|------------|---------|
| Wazuh | Security monitoring and alerting |
| Trivy | Vulnerability and dependency scanning |
| Linux | Host operating system |
| Bash Scripting | Automation |
| Virtual Machines | Isolated lab environment |
| Git/GitHub | Version control |

---

## Project Architecture

```text
                +-------------------+
                | Developer Pushes  |
                |      Code         |
                +---------+---------+
                          |
                          v
                +-------------------+
                |   Trivy Scanner   |
                | Dependency Scan   |
                +---------+---------+
                          |
                          v
                +-------------------+
                | CVE Classification|
                | Low/Med/High/Crit |
                +---------+---------+
                          |
               +----------+----------+
               |                     |
               v                     v
      Critical Vulnerability?      No Critical CVE
               |                     |
             YES                     NO
               |                     |
               v                     v
      +----------------+     +----------------+
      | Block Code Push|     | Allow Push     |
      +----------------+     +----------------+
                          |
                          v
                +-------------------+
                | Wazuh Monitoring  |
                | & Alerting        |
                +-------------------+
