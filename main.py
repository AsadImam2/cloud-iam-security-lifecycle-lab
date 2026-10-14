
from iam_lab.audit import AuditLogger
from iam_lab.identity import IdentityManager
from iam_lab.lifecycle import LifecycleManager
from iam_lab.jit_access import TemporaryAccessManager
from iam_lab.policies import are_roles_authorized


identity_manager = IdentityManager()
lifecycle_manager = LifecycleManager(identity_manager)
jit_manager = TemporaryAccessManager()
audit = AuditLogger()


def authorize_request(identity_id: str, action: str) -> bool:
    identity = identity_manager.get_identity(identity_id)

    if identity is None:
        audit.log_event(
            "access_check", identity_id, "failure", "Unknown identity"
        )
        return False

    if not identity["active"]:
        audit.log_event(
            "access_check",
            identity["username"],
            "failure",
            "Inactive identity",
        )
        return False

    role_allowed = are_roles_authorized(identity["roles"], action)
    jit_allowed = jit_manager.has_access(identity_id, action)
    allowed = role_allowed or jit_allowed

    access_source = (
        "permanent role"
        if role_allowed
        else "temporary JIT grant"
        if jit_allowed
        else "no matching permission"
    )

    audit.log_event(
        "access_check",
        identity["username"],
        "success" if allowed else "failure",
        (
            f"Action: {action}; "
            f"Roles: {', '.join(sorted(identity['roles']))}; "
            f"Access source: {access_source}"
        ),
    )

    return allowed


if __name__ == "__main__":
    user = identity_manager.create_identity("ali", "viewer")

    print("Viewer can view:", authorize_request(user["id"], "view_records"))
    print(
        "Viewer can manage policies:",
        authorize_request(user["id"], "manage_policies"),
    )

    identity_manager.assign_role(user["id"], "analyst")
    print(
        "Viewer + analyst can analyze:",
        authorize_request(user["id"], "analyze_records"),
    )

    jit_manager.grant_access(
        user["id"],
        "manage_policies",
        duration_seconds=10,
    )
    print(
        "Temporary policy access:",
        authorize_request(user["id"], "manage_policies"),
    )

    lifecycle_manager.deactivate_identity(user["id"])
    print(
        "Inactive user can view:",
        authorize_request(user["id"], "view_records"),
    )

    print("\nAudit events:")
    for event in audit.get_events():
        print(event)
