"""Build a deliberately misconfigured AWS account in moto and scan it.

Runs entirely offline: moto emulates AWS in-process, so no account or credentials are used.
    python examples/demo_lab.py
"""
import json
import os

for k, v in {"AWS_ACCESS_KEY_ID": "demo", "AWS_SECRET_ACCESS_KEY": "demo", "AWS_DEFAULT_REGION": "us-east-1"}.items():
    os.environ[k] = v
os.environ.pop("AWS_PROFILE", None)

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from misconfig.cli import main  # noqa: E402

with mock_aws():
    s3, ec2, iam, rds = (boto3.client(s) for s in ("s3", "ec2", "iam", "rds"))

    # A bucket that serves its objects to anyone.
    s3.create_bucket(Bucket="acme-public-assets")
    s3.put_bucket_policy(Bucket="acme-public-assets", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-public-assets/*"}]}))

    # SSH open to the internet, and an instance that still allows IMDSv1.
    ec2.authorize_security_group_ingress(GroupName="default", IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "optional"})

    # A console user without MFA, and a policy that grants everything.
    iam.create_user(UserName="deploy-bot")
    iam.create_login_profile(UserName="deploy-bot", Password="Summer-2026-password")
    arn = iam.create_policy(PolicyName="AdminEverything", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))["Policy"]["Arn"]
    iam.attach_user_policy(UserName="deploy-bot", PolicyArn=arn)

    # A public, unencrypted database.
    rds.create_db_instance(DBInstanceIdentifier="orders-db", Engine="postgres", DBInstanceClass="db.t3.micro",
                           AllocatedStorage=20, MasterUsername="admin1", MasterUserPassword="demo-password-1",
                           PubliclyAccessible=True, StorageEncrypted=False)

    raise SystemExit(main(["--checks", ",".join([
        "s3-public-bucket", "ec2-sg-admin-ports-ipv4", "ec2-imdsv2", "iam-user-console-mfa",
        "iam-full-admin-policy", "rds-public-access", "rds-encryption", "cloudtrail-multi-region"]),
        "--fail-on", "HIGH"]))
