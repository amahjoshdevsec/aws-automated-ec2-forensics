# Capturing screenshots from your deployment

The diagrams in `docs/images/` are generated from code. After you deploy and run a case, capture these console screenshots into `docs/screenshots/` and link them in the README's "Run an investigation end to end" section. They make the project much more convincing to reviewers because they prove it ran.

| File name | Where | What to show |
|---|---|---|
| `01-stepfunctions-graph-success.png` | Step Functions, state machine, a succeeded execution, Graph view | All states green |
| `02-stepfunctions-snapshot-loop.png` | Same execution, Events or Table view | Repeated WaitForSnapshots / CheckSnapshots |
| `03-approval-email.png` | Your inbox | The approval email (blur your address) |
| `04-approval-page.png` | Browser | The Approve / Reject confirmation page |
| `05-evidence-snapshots.png` | EC2, Snapshots, filter tag `ManagedBy = aws-automated-ec2-forensics` | Evidence snapshot with `EvidenceSha256` tag |
| `06-s3-case-folder.png` | S3, evidence bucket, `cases/<id>/` | chain-of-custody.json and analysis/ |
| `07-report.png` | report.md opened | Verdict and YARA / ClamAV detections |
| `08-ssm-command.png` | Systems Manager, Run Command, command history | Successful forensic scan command |
| `09-quarantine-sg.png` | EC2, instance, Security tab (after a case with `isolate: true`) | `forensics-quarantine` group |
| `10-dynamodb-case.png` | DynamoDB, cases table, explore items | Case record with status COMPLETE |
| `11-github-actions.png` | GitHub Actions | Green CI and Deploy smoke-test runs |

Before publishing, blur account ids, email addresses and any public IPs.
