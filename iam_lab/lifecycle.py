
from datetime import datetime, timezone


class LifecycleManager:
    def __init__(self, identity_manager):
        self.identity_manager = identity_manager

    def deactivate_identity(self, identity_id: str) -> bool:
        identity = self.identity_manager.get_identity(identity_id)

        if identity is None:
            return False

        identity["active"] = False
        identity["deactivated_at"] = datetime.now(timezone.utc).isoformat()
        return True

    def reactivate_identity(self, identity_id: str) -> bool:
        identity = self.identity_manager.get_identity(identity_id)

        if identity is None:
            return False

        identity["active"] = True
        identity.pop("deactivated_at", None)
        return True
