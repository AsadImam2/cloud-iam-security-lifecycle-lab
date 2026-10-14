
from datetime import datetime, timezone
from uuid import uuid4

from iam_lab.policies import ROLES
from iam_lab.security_checks import check_sod_conflicts


class IdentityManager:
    def __init__(self):
        self.identities = {}

    def create_identity(self, username: str, role: str) -> dict:
        if role not in ROLES:
            raise ValueError(f"Unknown role: {role}")

        identity_id = str(uuid4())

        identity = {
            "id": identity_id,
            "username": username,
            "roles": {role},
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        self.identities[identity_id] = identity
        return identity

    def get_identity(self, identity_id: str) -> dict | None:
        return self.identities.get(identity_id)

    def assign_role(self, identity_id: str, role: str) -> bool:
        identity = self.get_identity(identity_id)

        if identity is None:
            raise ValueError("Identity not found")

        if role not in ROLES:
            raise ValueError(f"Unknown role: {role}")

        proposed_roles = identity["roles"] | {role}

        conflicts = check_sod_conflicts(proposed_roles)
        if conflicts:
            raise ValueError("; ".join(conflicts))

        identity["roles"] = proposed_roles
        return True
