# pcs-cwp-agentless
Prisma Cloud API management of Cloud Accounts, specifically around agentless. 

## Usage
```python3 configAgentless.py --account-ids $ROOT_ACCOUNT $MEMBER_ACCOUNTS --auto-scale false --regions us-east-1 us-east-2 --include-tags Environment=production --custom-tags environment=agentless --scan-non-running false --scanners 1```
