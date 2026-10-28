from misconfig.models import Status

from .conftest import client


def _trail(name, multi_region=True, validation=False, kms=None, log=True):
    s3 = client("s3")
    s3.create_bucket(Bucket=f"{name}-logs")
    ct = client("cloudtrail")
    args = {"Name": name, "S3BucketName": f"{name}-logs", "IsMultiRegionTrail": multi_region,
            "EnableLogFileValidation": validation}
    if kms:
        args["KmsKeyId"] = kms
    arn = ct.create_trail(**args)["TrailARN"]
    if log:
        ct.start_logging(Name=name)
    return arn


def test_no_trail_fails(scan, ctx):
    r = scan("cloudtrail-multi-region")
    assert r[f"account {ctx.account_id}"] == (Status.FAIL, "no multi-region trail")


def test_multi_region_trail_logging_passes(scan):
    arn = _trail("org")
    assert scan("cloudtrail-multi-region")[arn][0] is Status.PASS


def test_stopped_or_single_region_trail_fails(scan, ctx):
    _trail("stopped", log=False)
    _trail("local", multi_region=False)
    status, detail = scan("cloudtrail-multi-region")[f"account {ctx.account_id}"]
    assert status is Status.FAIL and "stopped" in detail


def test_write_only_selector_fails(scan, ctx):
    arn = _trail("writes")
    client("cloudtrail").put_event_selectors(TrailName="writes", EventSelectors=[
        {"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}])
    assert scan("cloudtrail-multi-region")[f"account {ctx.account_id}"][0] is Status.FAIL
    client("cloudtrail").put_event_selectors(TrailName="writes", EventSelectors=[
        {"ReadWriteType": "All", "IncludeManagementEvents": True}])
    assert scan("cloudtrail-multi-region")[arn][0] is Status.PASS


def test_trail_validation_kms_and_bucket_logging(scan):
    key = client("kms").create_key()["KeyMetadata"]["Arn"]
    good = _trail("good", validation=True, kms=key)
    bad = _trail("bad")
    s3 = client("s3")
    s3.create_bucket(Bucket="access-logs")
    s3.put_bucket_acl(Bucket="access-logs", ACL="log-delivery-write")
    s3.put_bucket_logging(Bucket="good-logs", BucketLoggingStatus={
        "LoggingEnabled": {"TargetBucket": "access-logs", "TargetPrefix": "ct/"}})
    v = scan("cloudtrail-log-validation")
    assert v[good][0] is Status.PASS and v[bad][0] is Status.FAIL
    k = scan("cloudtrail-kms-encryption")
    assert k[good][0] is Status.PASS and k[bad][0] is Status.FAIL
    b = scan("cloudtrail-bucket-access-logging")
    assert b["arn:aws:s3:::good-logs"][0] is Status.PASS
    assert b["arn:aws:s3:::bad-logs"][0] is Status.FAIL


def test_kms_rotation_skips_keys_that_cannot_rotate(scan):
    kms = client("kms")
    off = kms.create_key()["KeyMetadata"]
    on = kms.create_key()["KeyMetadata"]
    kms.enable_key_rotation(KeyId=on["KeyId"])
    asym = kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]
    disabled = kms.create_key()["KeyMetadata"]
    kms.disable_key(KeyId=disabled["KeyId"])
    r = scan("kms-key-rotation")
    assert r[off["Arn"]] == (Status.FAIL, "rotation disabled")
    assert r[on["Arn"]][0] is Status.PASS
    assert asym["Arn"] not in r and disabled["Arn"] not in r


def _db(name, public=False, encrypted=True, minor=True):
    return client("rds").create_db_instance(
        DBInstanceIdentifier=name, Engine="postgres", DBInstanceClass="db.t3.micro", AllocatedStorage=20,
        MasterUsername="admin1", MasterUserPassword="not-a-real-password-1", PubliclyAccessible=public,
        StorageEncrypted=encrypted, AutoMinorVersionUpgrade=minor)["DBInstance"]["DBInstanceArn"]


def test_rds(scan):
    bad = _db("bad", public=True, encrypted=False, minor=False)
    good = _db("good")
    for check_id in ("rds-public-access", "rds-encryption", "rds-minor-version-upgrade"):
        r = scan(check_id)
        assert r[bad][0] is Status.FAIL, check_id
        assert r[good][0] is Status.PASS, check_id
