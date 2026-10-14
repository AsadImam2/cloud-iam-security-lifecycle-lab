\# Cloud IAM Security \& Identity Lifecycle Lab



\## Overview



This project is a Python-based educational simulation of Identity and Access Management (IAM) concepts commonly used in cloud security environments.



It demonstrates identity lifecycle management, Role-Based Access Control (RBAC), least privilege, Separation of Duties (SoD), Just-in-Time (JIT) privileged access, approval workflows, and persistent audit logging.



\*\*Note:\*\* This is a local learning lab, not a production-ready cloud IAM system.



\## Features



\- \*\*Identity lifecycle:\*\* Create, deactivate, and reactivate identities.

\- \*\*RBAC:\*\* Assign roles and evaluate permissions.

\- \*\*Least privilege:\*\* Deny actions that an identity is not permitted to perform.

\- \*\*Separation of Duties (SoD):\*\* Detect conflicting roles and block conflicting role assignments.

\- \*\*JIT access:\*\* Grant eligible privileged actions for a limited duration.

\- \*\*Approval workflow:\*\* Support pending, approved, and rejected access requests.

\- \*\*Approval safeguards:\*\* Block self-approval and require an active admin approver.

\- \*\*Inactive identity protection:\*\* Deny access to inactive identities.

\- \*\*Audit logging:\*\* Record access decisions and workflow events in a persistent JSON Lines log file.

\- \*\*Automated tests:\*\* Test expected behavior and security controls.



\## Project Structure



```text

cloud-iam-lifecycle-lab/

├── iam\_lab/

│   ├── identity.py

│   ├── lifecycle.py

│   ├── policies.py

│   ├── audit.py

│   ├── security\_checks.py

│   ├── jit\_access.py

│   └── jit\_approval.py

├── tests/

│   └── test\_iam.py

├── logs/

├── main.py

├── .gitignore

└── README.md

```



\## Requirements



\- Python 3.10 or newer

\- No external cloud account is required



\## Setup



Clone the repository, then open its directory.



Create a virtual environment:



```powershell

python -m venv .venv

```



Activate it in Windows PowerShell:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



\## Run the Lab



```powershell

python main.py

```



The demonstration prints example authorization decisions and audit events.



\## Run Automated Tests



```powershell

python -m unittest discover -s tests -v

```



At the time of documentation, \*\*22 automated tests passed\*\* in the local environment.



\## Audit Logs



Audit events are stored in:



```text

logs/iam\_audit.log

```



Each line contains a JSON event with a timestamp, action, username, outcome, and details.



To inspect the log:



```powershell

Get-Content .\\logs\\iam\_audit.log

```



The application appends new events to the log file. Review `.gitignore` before publishing generated logs.



\## Security Concepts Demonstrated



\- Identity and access management

\- Role-based authorization

\- Least privilege

\- Separation of Duties

\- Identity lifecycle controls

\- Temporary privileged access

\- Approval workflows

\- Audit trails and security event recording

\- Automated security testing



\## Limitations



This project is an educational simulation. It does not integrate with AWS, Azure, or Google Cloud IAM, and it does not implement production identity storage, distributed authorization, enterprise approval policies, or tamper-resistant audit storage.



The current in-memory identity store is reset when the application restarts. The audit log file persists locally, but it is not protected against modification by a user with sufficient filesystem permissions.



\## Disclaimer



This lab is intended for educational purposes and authorized security learning. It should not be used as a production access-control system.



\## Author



Developed as a hands-on cloud security and IAM learning project.

