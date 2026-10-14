
from iam_lab.policies import ROLES


SOD_CONFLICTS = [
    {"payment_creator", "payment_approver"},
    {"user_admin", "security_auditor"},
]


def check_unknown_role(role: str) -> list[str]:
    if role not in ROLES:
        return [f"Unknown role: {role}"]

    return []


def check_sod_conflicts(roles: set[str]) -> list[str]:
    findings = []

    for conflict in SOD_CONFLICTS:
        if conflict.issubset(roles):
            findings.append(
                f"SoD conflict detected: {', '.join(sorted(conflict))}"
            )

    return findings


def check_inactive_identity(identity: dict) -> list[str]:
    if not identity.get("active", False):
        return [f"Inactive identity: {identity.get('username', 'unknown')}"]

    return []

