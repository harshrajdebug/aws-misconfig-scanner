from __future__ import annotations

from ..context import ScanContext
from ..models import Severity, Status
from ..registry import check


@check("kms-key-rotation", "Customer managed symmetric KMS keys rotate", "kms", Severity.MEDIUM,
       "KMS.4", "3.6", "3.6", "Enable automatic key rotation on each enabled customer managed symmetric key.")
def key_rotation(ctx: ScanContext, region: str):
    kms = ctx.client("kms", region)
    for page in kms.get_paginator("list_keys").paginate():
        for key in page["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            spec = meta.get("KeySpec", meta.get("CustomerMasterKeySpec"))
            # Rotation exists only for enabled, customer managed, symmetric keys with AWS key material.
            if (meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled"
                    or spec != "SYMMETRIC_DEFAULT" or meta.get("Origin") != "AWS_KMS"):
                continue
            if kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]:
                yield Status.PASS, meta["Arn"], "rotation enabled"
            else:
                yield Status.FAIL, meta["Arn"], "rotation disabled"
