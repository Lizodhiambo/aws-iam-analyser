<<<<<<< HEAD
\# AWS IAM Analyser



A Python security tool that connects to AWS IAM and audits 

my account for misconfigurations and security risks.



\# What it does



\- Connects to AWS IAM using boto3

\- Lists all IAM users, roles, and customer-managed policies

\- (Phase 2) Detects wildcard permissions and unused roles

\- (Phase 3) Outputs findings with severity ratings

\- (Phase 4) Detects privilege escalation paths



\# Security framework



Findings mapped to:

\- CIS AWS Foundations Benchmark

\- MITRE ATT\&CK for Cloud (TA0004 Privilege Escalation)



\# Tech stack



\- Python 3.12

\- boto3 (AWS SDK)

\- rich (terminal output)

\- python-dotenv (credential management)



\# Setup



1\. Clone the repo

2\. Install dependencies

&#x20;   pip install boto3 python-dotenv rich

3\. Create a .env file (never commit this)

&#x20;   AWS\_ACCESS\_KEY\_ID=my\_key

&#x20;   AWS\_SECRET\_ACCESS\_KEY=my\_secret

&#x20;   AWS\_DEFAULT\_REGION=ap-southeast-2

4\. Run

&#x20;   python phase1\_connect.py



\# Project status



\- \[x] Phase 1 — AWS connection and IAM inventory

\- \[x] Phase 2 — Misconfiguration scanning

\- \[x] Phase 3 — Reporting with severity levels

\- \[ ] Phase 4 — Privilege escalation detection

=======
# aws-iam-analyser
Identity and accsess management
>>>>>>> a0c11853af4d397cdb6439c294b962fa8cb41d45
