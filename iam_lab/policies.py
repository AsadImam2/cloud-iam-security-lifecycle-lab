
ROLES = {
    "viewer": {
        "view_records",
    },
    "analyst": {
        "view_records",
        "analyze_records",
    },
    "admin": {
        "view_records",
        "analyze_records",
        "manage_identities",
        "manage_policies",
    },
    "payment_creator": {
        "create_payment",
    },
    "payment_approver": {
        "approve_payment",
    },
    "user_admin": {
        "manage_identities",
    },
    "security_auditor": {
        "view_audit_logs",
    },
}


def is_authorized(role: str, action: str) -> bool:
    return action in ROLES.get(role, set())


def are_roles_authorized(roles: set[str], action: str) -> bool:
    for role in roles:
        if action in ROLES.get(role, set()):
            return True

    return False
