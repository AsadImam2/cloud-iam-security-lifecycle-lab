
from datetime import datetime, timedelta, timezone


PRIVILEGED_ACTIONS = {
    "manage_identities",
    "manage_policies",
    "approve_payment",
}


class TemporaryAccessManager:
    def __init__(self):
        self.grants = {}

    def grant_access(
        self,
        identity_id: str,
        action: str,
        duration_seconds: int,
    ) -> bool:
        if not identity_id:
            raise ValueError("Identity ID is required")

        if action not in PRIVILEGED_ACTIONS:
            raise ValueError("Action is not eligible for JIT access")

        if duration_seconds <= 0:
            raise ValueError("Duration must be greater than zero")

        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=duration_seconds
        )

        self.grants[(identity_id, action)] = expires_at
        return True

    def has_access(self, identity_id: str, action: str) -> bool:
        expires_at = self.grants.get((identity_id, action))

        if expires_at is None:
            return False

        if datetime.now(timezone.utc) >= expires_at:
            del self.grants[(identity_id, action)]
            return False

        return True

