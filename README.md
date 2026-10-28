# aws-misconfig-scanner

A read-only Python scanner for AWS security misconfigurations. It runs 29 checks across IAM, S3, EC2/VPC, CloudTrail, KMS and RDS, and maps each one to its AWS Security Hub control and to the matching requirement in the CIS AWS Foundations Benchmark v5.0.0 and v3.0.0. It scans one account or every account in an AWS Organization.

Each result says what is wrong, on which resource, and how to fix it. A check that cannot run because a permission is missing is reported as ERROR, so a gap in access never reads as a pass.

## Try it without an AWS account

`examples/demo_lab.py` builds a deliberately misconfigured account in [moto](https://github.com/getmoto/moto), which emulates AWS in-process, and scans it:

```
$ python examples/demo_lab.py
[FAIL] CRITICAL rds-public-access  (RDS.2, CIS v5 2.2.3)
    arn:aws:rds:us-east-1:123456789012:db:orders-db  [us-east-1]
    PubliclyAccessible is true
    fix: Set PubliclyAccessible to false and reach the database through private networking.
[FAIL] CRITICAL s3-public-bucket  (S3.2/S3.3, no CIS mapping)
    arn:aws:s3:::acme-public-assets  [global]
    policy allows s3:GetObject to anyone
[FAIL] HIGH     ec2-sg-admin-ports-ipv4  (EC2.53, CIS v5 5.3)
    sg-9d27b238b3c70b40c (default, us-east-1)  [us-east-1]
    0.0.0.0/0 can reach port(s) [22]
...
8 results: 0 passed, 8 failed (CRITICAL 2, HIGH 6), 0 errors
```

## Usage

```bash
pip install .            # or pip install '.[login]' for profiles created by `aws login`
misconfig --profile audit --regions all
misconfig --services s3,iam --format json > findings.json
misconfig --list-checks

# Every active account in the organization, four at a time
misconfig --profile management --org --regions all --workers 4

# Specific accounts through a dedicated role and external ID
misconfig --accounts 111111111111,222222222222 --role-name MisconfigScannerRole --external-id "$EXTERNAL_ID"
```

| Option | Meaning |
|---|---|
| `--profile` | AWS profile to use |
| `--regions` | comma-separated regions, or `all`; defaults to the profile's region |
| `--checks`, `--services` | run a subset |
| `--format text\|json` | human report or machine-readable output with a summary |
| `--show-pass` | include passing results in the text report |
| `--org` | scan every active account in the organization; run it from the management account or a delegated administrator |
| `--accounts` | scan these account ids instead |
| `--role-name`, `--external-id` | role to assume in the other accounts (default `OrganizationAccountAccessRole`) and its external ID |
| `--workers` | accounts scanned in parallel (default 4) |
| `--fail-on SEVERITY` | exit 1 if any check fails at that severity or above, for CI |

Account-wide checks (IAM, S3, the multi-region CloudTrail check) run once per account. Regional checks run in every selected region, and `--regions all` is resolved separately in each account because opt-in regions differ.

Account-wide calls go to the profile's region, or to the first region you scan if the profile has none. Accounts under a service control policy that denies most regions still work: scan the allowed regions with `--regions`, and any call an SCP blocks is reported as an ERROR that says so.

In a multi-account scan, the account you are signed in to is scanned with your own credentials, and every other account through the role. Each finding carries its account id, the text report groups results by account, and the JSON output adds a summary per account.

## Permissions

The scanner only reads. [`examples/scanner-policy.json`](examples/scanner-policy.json) lists the 32 IAM actions it calls, taken from the code. `iam:GenerateCredentialReport` is the one that is not a Get, List or Describe call: it asks IAM to build the credential report that the user checks read.

For an organization:

- Deploy [`examples/scanner-role.yaml`](examples/scanner-role.yaml) to the member accounts with a CloudFormation StackSet. It creates `MisconfigScannerRole` with the same 32 read actions, trusted only by the scanning account and optionally bound to an external ID. Then run with `--role-name MisconfigScannerRole`.
- Give the identity that runs the scanner [`examples/orchestrator-policy.json`](examples/orchestrator-policy.json): `organizations:ListAccounts` and `sts:AssumeRole` on that role.
- The default `OrganizationAccountAccessRole` works without any setup in accounts created through Organizations, but it has administrator access, so a dedicated read-only role is the better choice.

## Checks

| Check | Severity | Security Hub | CIS v5.0.0 | CIS v3.0.0 | What it checks |
|---|---|---|---|---|---|
| `cloudtrail-multi-region` | HIGH | CloudTrail.1 | 3.1 | 3.1 | A multi-region trail logs all management events |
| `cloudtrail-log-validation` | MEDIUM | CloudTrail.4 | 3.2 | 3.2 | CloudTrail log file validation is enabled |
| `cloudtrail-kms-encryption` | MEDIUM | CloudTrail.2 | 3.5 | 3.5 | CloudTrail logs are encrypted with KMS |
| `cloudtrail-bucket-access-logging` | LOW | CloudTrail.7 | 3.4 | 3.4 | The CloudTrail bucket has access logging |
| `ec2-sg-admin-ports-ipv4` | HIGH | EC2.53 | 5.3 | 5.2 | No security group allows 0.0.0.0/0 to SSH or RDP |
| `ec2-sg-admin-ports-ipv6` | HIGH | EC2.54 | 5.4 | 5.3 | No security group allows ::/0 to SSH or RDP |
| `ec2-nacl-admin-ports` | MEDIUM | EC2.21 | 5.2 | 5.1 | No network ACL allows 0.0.0.0/0 to SSH or RDP |
| `ec2-default-sg-restricted` | MEDIUM | EC2.2 | 5.5 | 5.4 | Default security groups allow no traffic |
| `ec2-vpc-flow-logs` | MEDIUM | EC2.6 | 3.7 | 3.7 | VPC flow logging is enabled |
| `ec2-ebs-default-encryption` | MEDIUM | EC2.7 | 5.1.1 | 2.2.1 | EBS encryption by default is enabled |
| `ec2-imdsv2` | HIGH | EC2.8 | 5.7 | 5.6 | EC2 instances require IMDSv2 |
| `iam-root-access-key` | CRITICAL | IAM.4 | 1.3 | 1.4 | Root user has no access keys |
| `iam-root-mfa` | CRITICAL | IAM.9 | 1.4 | 1.5 | Root user has MFA enabled |
| `iam-user-console-mfa` | HIGH | IAM.5 | 1.9 | 1.10 | IAM users with a console password have MFA |
| `iam-access-key-rotation` | MEDIUM | IAM.3 | 1.13 | 1.14 | Active access keys are rotated within 90 days |
| `iam-unused-credentials` | MEDIUM | IAM.22 | 1.11 | 1.12 | Credentials unused for 45 days are disabled |
| `iam-password-length` | MEDIUM | IAM.15 | 1.7 | 1.8 | Password policy requires 14 or more characters |
| `iam-password-reuse` | LOW | IAM.16 | 1.8 | 1.9 | Password policy prevents reuse |
| `iam-user-attached-policies` | LOW | IAM.2 | 1.14 | 1.15 | IAM users get permissions only through groups or roles |
| `iam-cloudshell-full-access` | MEDIUM | IAM.27 | 1.21 | 1.22 | No identity has AWSCloudShellFullAccess |
| `iam-full-admin-policy` | HIGH | IAM.1 | - | - | No attached customer managed policy allows *:* |
| `kms-key-rotation` | MEDIUM | KMS.4 | 3.6 | 3.6 | Customer managed symmetric KMS keys rotate |
| `rds-public-access` | CRITICAL | RDS.2 | 2.2.3 | 2.3.3 | RDS instances are not publicly accessible |
| `rds-encryption` | HIGH | RDS.3 | 2.2.1 | 2.3.1 | RDS instances are encrypted at rest |
| `rds-minor-version-upgrade` | LOW | RDS.13 | 2.2.2 | 2.3.2 | RDS automatic minor version upgrades are on |
| `s3-block-public-access` | HIGH | S3.1/S3.8 | 2.1.4 | 2.1.4 | S3 buckets have Block Public Access enabled |
| `s3-public-bucket` | CRITICAL | S3.2/S3.3 | - | - | No S3 bucket is open to the public |
| `s3-tls-only` | MEDIUM | S3.5 | 2.1.1 | 2.1.1 | S3 bucket policies deny requests without TLS |
| `s3-mfa-delete` | LOW | S3.20 | 2.1.2 | 2.1.2 | S3 buckets have MFA delete enabled |

The Security Hub and CIS numbers come from AWS's mapping table in [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html). Checks marked `-` have no requirement in that CIS version.

Some behaviour worth knowing:

- **Public S3 buckets** account for Block Public Access at both bucket and account level. A bucket with a public policy fails only if `RestrictPublicBuckets` is off, and a public ACL fails only if `IgnorePublicAcls` is off.
- **SSH and RDP exposure** covers "all traffic" rules and port ranges that include 22 or 3389, not only rules for exactly those ports. Network ACLs are evaluated in rule-number order, so a deny entry placed before a broad allow protects the port.
- **CloudTrail** accepts classic and advanced event selectors. A trail with no selectors counts as logging all management events, which is the CloudTrail default.
- **Root MFA** passes when the root user has no password, access keys or signing certificates, which is how accounts look after centralized root access management removes root credentials. The live run below found this case.
- **KMS rotation** skips keys that cannot rotate: AWS managed, disabled, asymmetric, and imported key material.

## Use in CI

```bash
misconfig --regions all --fail-on HIGH --format json > findings.json
```

The command exits 1 when a HIGH or CRITICAL check fails, so the pipeline stops. It exits 2 if any account could not be scanned, for example because the role could not be assumed; that account is listed with an `assume-role` ERROR and the other accounts are still scanned.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

The 42 tests run against moto. Each check has a misconfigured resource that must fail and a hardened one that must pass, and the error path is tested with an AccessDenied client. The multi-account tests build an organization with member accounts, plant a misconfiguration in one member through an assumed role, and check that the finding is attributed to that account and not the others. Adding a check means writing a generator decorated with `@check(...)` in `misconfig/checks/` that yields `(status, resource, detail)`.

## Limitations

- The test suite runs against moto, which follows the AWS APIs closely but not exactly; for example, it returns no event selectors at all for a new trail. The scanner has also been run against one live account, a new account whose service control policy allows a single region, where the first run showed that account-wide calls must not be hard-coded to us-east-1, and that the root MFA check must allow for root credentials that were removed. Organization scans have only been tested in moto.
- The root MFA check reports whether MFA is on, not whether it is a hardware device (Security Hub IAM.6).
- Results reflect the API at scan time. The IAM credential report can be up to four hours old.

## License

Apache-2.0
