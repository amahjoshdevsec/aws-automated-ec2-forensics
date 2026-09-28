# Interview guide

How to present this project in a recruiter screen, a hiring manager conversation or a technical deep dive.

## 30 second pitch

"I built an automated, approval-gated EC2 forensics pipeline on AWS with Terraform. When an instance is suspected of compromise, one command or a GuardDuty finding starts a Step Functions workflow. After a human approves, it preserves every EBS volume as encrypted evidence, analyses a disposable copy on an isolated workstation over SSM with no SSH, and produces a report plus a hashed chain-of-custody record. It is based on the pattern OneMain Financial described in an AWS case study, where this approach cut time from alert to investigation by 97.5 percent. It deploys into a personal account in about five minutes and scales to a multi-account AWS Organization."

## Two minute walkthrough (use the architecture diagram)

1. **Trigger**: analyst CLI call or EventBridge rule on high severity GuardDuty EC2 findings.
2. **Validate**: account allow-list, region, instance state, refuses to investigate the workstation itself.
3. **Approve**: Step Functions callback pattern with `waitForTaskToken`. The token stays in DynamoDB; the email carries a single-use random id; GET is side-effect free so email link scanners cannot approve.
4. **Preserve**: termination protection, snapshot every volume, re-encrypt with a customer managed key. That re-encryption is what allows cross-account sharing, because `aws/ebs` snapshots can never be shared.
5. **Analyse**: create disposable volumes, attach to the workstation, `blockdev --setro`, hash the raw device, Sleuth Kit timeline, ClamAV, YARA, persistence and artifact collection, all through SSM Run Command.
6. **Record**: S3 with SSE-KMS and versioning, custody manifest hash in DynamoDB, image hash tagged on the evidence snapshot.
7. **Contain**: optional quarantine security group, previous groups recorded so it can be reverted.

## Design decisions worth discussing

| Decision | Why | Trade-off |
|---|---|---|
| Step Functions Standard, not Lambda chains | Visual audit trail, native retries/catches, waits up to a year, callback pattern for humans | State transitions cost more than Express; irrelevant at forensics volume |
| Small single-purpose Lambdas passing one state document | Easy to unit test, easy to reason about in an incident review | More functions to deploy (Terraform `for_each` keeps it to one block) |
| Polling loops for snapshots and SSM | Snapshot and scan durations are unpredictable; Wait states cost nothing while waiting | Up to 30/60 seconds of added latency |
| Re-encrypt with a CMK | Only way to move evidence across accounts; separates evidence from workload key admins | KMS key policy must trust member roles |
| Analyse a copy, never the evidence | Evidence snapshot stays pristine; analysis volume is disposable | Extra volume creation time |
| SSM instead of SSH | No keys, no inbound ports, every command logged | Depends on SSM agent health |
| IAM tag conditions on delete | Automation physically cannot delete evidence snapshots | Tags must be set at creation (done via TagSpecifications) |
| Email approval in the lab | Zero dependencies for a personal account | Not strong authentication; production uses ChatOps/ITSM/Cognito |
| Public IP on workstation in the lab | Avoids ~$30/month NAT or ~$50/month of interface endpoints | Production design uses private subnets and endpoints |

## Likely questions and strong answers

**How do you prove the evidence was not altered?** The raw device SHA-256 is computed on a read-only block device that is a bit-for-bit restore of the evidence snapshot, tagged onto that snapshot, written into `chain-of-custody.json`, and the manifest's own SHA-256 is stored in DynamoDB. Every output file is listed in `manifest.sha256`. Approval identity, IP and time are in the manifest. Automation roles cannot delete evidence snapshots or case objects.

**What if the attacker notices?** Snapshots are taken from the control plane with no agent on the instance, so nothing runs inside the suspect. Isolation happens only after the evidence is preserved, and only if requested.

**How does this work across 100 accounts?** A responder role in every account (deployed by AFT or StackSets), trusted only by the forensics orchestrator role and protected by an SCP. The KMS key policy trusts those roles; snapshots are re-encrypted, shared to the forensics account and copied so the forensics account owns the evidence.

**What would you add next?** Memory acquisition (AVML through SSM before snapshot), per-case ephemeral workstations from an Image Builder SIFT AMI, Slack approval with identity, Security Hub custom action trigger, EBS direct API hashing, and Security Lake integration for the findings.

**How did you test it?** 26 Python unit tests with mocked AWS clients, a structural test of the state machine, Terraform tests with a mocked AWS provider, Checkov and ShellCheck in CI, and an end-to-end smoke test that deploys a deliberately compromised (inert) instance, runs a real case with programmatic approval and asserts the expected YARA and ClamAV hits.

**What did the case study measure and how would you measure it here?** Time from alert to investigation (97.5 percent reduction), people involved (33 percent fewer), cost versus licensed tools (98.8 percent lower). Here: Step Functions execution duration from start to `FinalizeCase`, approval wait from the cases table, and the cost table in the README.

## Demo script (10 minutes)

1. Show the architecture diagram and the Step Functions graph in the console.
2. Run `bash scripts/start-investigation.sh` against the demo target.
3. Open the approval email on your phone, show the confirmation page, approve.
4. Show the execution progressing through the snapshot loop.
5. While it runs, walk through `forensic-scan.sh` and the IAM tag conditions.
6. Open `report.md` and `chain-of-custody.json` from a previous completed case.
