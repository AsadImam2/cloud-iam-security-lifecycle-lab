
from uuid import uuid4
from iam_lab.jit_access import PRIVILEGED_ACTIONS


class JITApprovalManager:
    def __init__(self, identity_manager, jit_manager, audit):
        self.identity_manager = identity_manager
        self.jit_manager = jit_manager
        self.audit = audit
        self.requests = {}

    def request_access(
        self,
        requester_id: str,
        action: str,
        duration_seconds: int,
    ) -> str:
        requester = self.identity_manager.get_identity(requester_id)

        if requester is None or not requester["active"]:
            raise ValueError("Requester identity is invalid or inactive")

        if action not in PRIVILEGED_ACTIONS:
            raise ValueError("Action is not eligible for JIT access")

        if duration_seconds <= 0:
            raise ValueError("Duration must be greater than zero")

        request_id = str(uuid4())

        self.requests[request_id] = {
            "requester_id": requester_id,
            "action": action,
            "duration_seconds": duration_seconds,
            "status": "pending",
            "approver_id": None,
        }

        self.audit.log_event(
            "jit_request",
            requester["username"],
            "pending",
            f"Request ID: {request_id}; Action: {action}",
        )

        return request_id

    def approve_request(
        self,
        request_id: str,
        approver_id: str,
    ) -> bool:
        request = self.requests.get(request_id)
        approver = self.identity_manager.get_identity(approver_id)

        if request is None or request["status"] != "pending":
            raise ValueError("Request not found or already processed")

        if approver is None or not approver["active"]:
            raise ValueError("Approver identity is invalid or inactive")

        if approver_id == request["requester_id"]:
            raise ValueError("Self-approval is not allowed")

        if not self.identity_manager.get_identity(
            request["requester_id"]
        )["active"]:
            raise ValueError("Requester is inactive")

        if "admin" not in approver["roles"]:
            raise ValueError("Approver must have the admin role")

        self.jit_manager.grant_access(
            request["requester_id"],
            request["action"],
            request["duration_seconds"],
        )

        request["status"] = "approved"
        request["approver_id"] = approver_id

        self.audit.log_event(
            "jit_approval",
            approver["username"],
            "approved",
            f"Request ID: {request_id}; Action: {request['action']}",
        )

        return True

    def reject_request(
        self,
        request_id: str,
        approver_id: str,
    ) -> bool:
        request = self.requests.get(request_id)
        approver = self.identity_manager.get_identity(approver_id)

        if request is None or request["status"] != "pending":
            raise ValueError("Request not found or already processed")

        if approver is None or not approver["active"]:
            raise ValueError("Approver identity is invalid or inactive")

        if approver_id == request["requester_id"]:
            raise ValueError("Self-rejection is not allowed")
        requester = self.identity_manager.get_identity(
            request["requester_id"]
        )

        if requester is None or not requester["active"]:
            raise ValueError("Requester is inactive")

        if "admin" not in approver["roles"]:
            raise ValueError("Approver must have the admin role")

        request["status"] = "rejected"
        request["approver_id"] = approver_id

        self.audit.log_event(
            "jit_approval",
            approver["username"],
            "rejected",
            f"Request ID: {request_id}; Action: {request['action']}",
        )

        return True
