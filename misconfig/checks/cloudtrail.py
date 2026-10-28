from __future__ import annotations

from ..context import ScanContext
from ..models import Severity, Status
from ..registry import check


def _logs_all_management_events(selectors: dict) -> bool:
    if not selectors.get("EventSelectors") and not selectors.get("AdvancedEventSelectors"):
        # With no selectors configured, a trail logs all management events by default.
        return True
    for sel in selectors.get("EventSelectors") or []:
        if sel.get("IncludeManagementEvents", True) and sel.get("ReadWriteType", "All") == "All":
            return True
    for adv in selectors.get("AdvancedEventSelectors") or []:
        fields = {f["Field"]: f for f in adv.get("FieldSelectors", [])}
        category = fields.get("eventCategory", {})
        # A management selector without a readOnly filter captures both reads and writes.
        if "Management" in category.get("Equals", []) and "readOnly" not in fields:
            return True
    return False


@check("cloudtrail-multi-region", "A multi-region trail logs all management events", "cloudtrail", Severity.HIGH,
       "CloudTrail.1", "3.1", "3.1",
       "Create a multi-region trail that is logging and records read and write management events.", scope="global")
def multi_region_trail(ctx: ScanContext, region: str):
    trails = ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)["trailList"]
    checked = []
    for trail in trails:
        if not trail.get("IsMultiRegionTrail"):
            continue
        home = ctx.client("cloudtrail", trail["HomeRegion"])
        logging = home.get_trail_status(Name=trail["TrailARN"]).get("IsLogging", False)
        selectors = home.get_event_selectors(TrailName=trail["TrailARN"])
        if logging and _logs_all_management_events(selectors):
            yield Status.PASS, trail["TrailARN"], "multi-region, logging, read and write management events"
            return
        checked.append(trail["Name"])
    detail = "no multi-region trail" if not checked else "multi-region trail(s) not logging all management events: " + ", ".join(checked)
    yield Status.FAIL, f"account {ctx.account_id}", detail


def _home_trails(ctx: ScanContext, region: str) -> list[dict]:
    # Without shadow trails, each trail is reported only in its home region.
    return ctx.client("cloudtrail", region).describe_trails(includeShadowTrails=False)["trailList"]


@check("cloudtrail-log-validation", "CloudTrail log file validation is enabled", "cloudtrail", Severity.MEDIUM,
       "CloudTrail.4", "3.2", "3.2", "Enable log file validation on every trail.")
def log_validation(ctx: ScanContext, region: str):
    for trail in _home_trails(ctx, region):
        if trail.get("LogFileValidationEnabled"):
            yield Status.PASS, trail["TrailARN"], "log file validation enabled"
        else:
            yield Status.FAIL, trail["TrailARN"], "log file validation disabled"


@check("cloudtrail-kms-encryption", "CloudTrail logs are encrypted with KMS", "cloudtrail", Severity.MEDIUM,
       "CloudTrail.2", "3.5", "3.5", "Set a customer managed KMS key on every trail.")
def kms_encryption(ctx: ScanContext, region: str):
    for trail in _home_trails(ctx, region):
        if trail.get("KmsKeyId"):
            yield Status.PASS, trail["TrailARN"], "encrypted with " + trail["KmsKeyId"]
        else:
            yield Status.FAIL, trail["TrailARN"], "logs use S3 default encryption only"


@check("cloudtrail-bucket-access-logging", "The CloudTrail bucket has access logging", "cloudtrail", Severity.LOW,
       "CloudTrail.7", "3.4", "3.4", "Enable server access logging on the bucket that receives CloudTrail logs.")
def bucket_access_logging(ctx: ScanContext, region: str):
    s3 = ctx.client("s3")
    for trail in _home_trails(ctx, region):
        bucket = trail.get("S3BucketName")
        if not bucket:
            continue
        logging = s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled")
        if logging:
            yield Status.PASS, f"arn:aws:s3:::{bucket}", f"access logs go to {logging.get('TargetBucket')}"
        else:
            yield Status.FAIL, f"arn:aws:s3:::{bucket}", f"bucket for trail {trail['Name']} has no access logging"
