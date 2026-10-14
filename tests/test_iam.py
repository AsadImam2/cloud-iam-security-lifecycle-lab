
import unittest

from iam_lab.audit import AuditLogger
from iam_lab.identity import IdentityManager
from iam_lab.jit_approval import JITApprovalManager
from iam_lab.jit_access import TemporaryAccessManager
from iam_lab.lifecycle import LifecycleManager
from iam_lab.policies import is_authorized
from iam_lab.security_checks import (
    check_inactive_identity,
    check_sod_conflicts,
    check_unknown_role,
)


class TestIAMLab(unittest.TestCase):
    def setUp(self):
        self.manager = IdentityManager()
        self.lifecycle = LifecycleManager(self.manager)
        self.audit = AuditLogger()
        self.user = self.manager.create_identity("ali", "viewer")

    def test_viewer_can_view_records(self):
        self.assertTrue(is_authorized("viewer", "view_records"))

    def test_viewer_cannot_manage_policies(self):
        self.assertFalse(is_authorized("viewer", "manage_policies"))

    def test_deactivated_identity_is_inactive(self):
        self.lifecycle.deactivate_identity(self.user["id"])
        self.assertFalse(self.user["active"])

    def test_inactive_identity_is_detected(self):
        self.user["active"] = False
        self.assertTrue(check_inactive_identity(self.user))

    def test_sod_conflict_is_detected(self):
        roles = {"payment_creator", "payment_approver"}
        self.assertTrue(check_sod_conflicts(roles))

    def test_unknown_role_is_detected(self):
        self.assertTrue(check_unknown_role("superuser"))
    def test_sod_conflicting_role_assignment_is_blocked(self):
        user =self.manager.create_identity("payment_user","payment_creator")

        with self.assertRaisesRegex(ValueError, "SoD conflict detected"):
            self.manager.assign_role(user["id"], "payment_approver")

        self.assertEqual(user["roles"], {"payment_creator"})

    def test_audit_event_is_recorded(self):
        self.audit.log_event("access_check", "ali", "failure")
        self.assertEqual(len(self.audit.get_events()), 1)


    def test_multiple_roles_allow_combined_permissions(self):
        user = self.manager.create_identity("ali", "viewer")
        self.manager.assign_role(user["id"], "analyst")

        self.assertIn("viewer", user["roles"])
        self.assertIn("analyst", user["roles"])

        from iam_lab.policies import are_roles_authorized
        self.assertTrue(
            are_roles_authorized(user["roles"], "analyze_records")
        )

    def test_unknown_identity_is_denied_and_logged(self):
        from main import authorize_request, audit

        audit.events.clear()

        result = authorize_request("non-existent-id", "view_records")

        self.assertFalse(result)
        self.assertEqual(len(audit.get_events()), 1)
        self.assertEqual(audit.get_events()[0]["outcome"], "failure")

    def test_inactive_identity_is_denied_by_authorization(self):
        from main import authorize_request, identity_manager, lifecycle_manager

        user = identity_manager.create_identity("inactive_test", "viewer")
        lifecycle_manager.deactivate_identity(user["id"])

        self.assertFalse(authorize_request(user["id"], "view_records"))

    def test_jit_grant_allows_temporary_access(self):
        jit = TemporaryAccessManager()

        jit.grant_access(
            self.user["id"],
            "manage_policies",
            duration_seconds=30,
        )

        self.assertTrue(
            jit.has_access(self.user["id"], "manage_policies")
        )

    def test_jit_access_expires(self):
        from unittest.mock import patch
        from datetime import datetime, timedelta, timezone

        jit = TemporaryAccessManager()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)

        with patch("iam_lab.jit_access.datetime") as mock_datetime:
            mock_datetime.now.return_value = start

            jit.grant_access(
                self.user["id"],
                "manage_policies",
                duration_seconds=10,
            )

            mock_datetime.now.return_value = start + timedelta(seconds=11)

            self.assertFalse(
                jit.has_access(self.user["id"], "manage_policies")
            )

    def test_jit_rejects_non_privileged_action(self):
        jit = TemporaryAccessManager()

        with self.assertRaisesRegex(ValueError, "not eligible"):
            jit.grant_access(
                self.user["id"],
                "view_records",
                duration_seconds=30,
            )

    def test_expired_jit_grant_is_denied_by_authorization(self):
        from unittest.mock import patch
        from datetime import datetime, timedelta, timezone
        from main import authorize_request, identity_manager, jit_manager

        user = identity_manager.create_identity(
            "jit_expiry_test",
            "viewer",
        )

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)

        with patch("iam_lab.jit_access.datetime") as mock_datetime:
            mock_datetime.now.return_value = start

            jit_manager.grant_access(
                user["id"],
                "manage_policies",
                duration_seconds=10,
            )

            mock_datetime.now.return_value = start + timedelta(seconds=11)

            self.assertFalse(
                authorize_request(user["id"], "manage_policies")
            )

    def test_jit_approval_grants_access(self):
        from iam_lab.jit_access import TemporaryAccessManager

        jit = TemporaryAccessManager()
        approval = JITApprovalManager(self.manager, jit, self.audit)
        admin = self.manager.create_identity("admin_user", "admin")

        request_id = approval.request_access(
            self.user["id"], "manage_policies", 30
        )

        self.assertFalse(jit.has_access(self.user["id"], "manage_policies"))
        self.assertTrue(approval.approve_request(request_id, admin["id"]))
        self.assertTrue(jit.has_access(self.user["id"], "manage_policies"))

    def test_jit_self_approval_is_blocked(self):
        from iam_lab.jit_access import TemporaryAccessManager

        jit = TemporaryAccessManager()
        approval = JITApprovalManager(self.manager, jit, self.audit)

        request_id = approval.request_access(
            self.user["id"], "manage_policies", 30
        )

        with self.assertRaisesRegex(ValueError, "Self-approval"):
            approval.approve_request(request_id, self.user["id"])

        self.assertFalse(jit.has_access(self.user["id"], "manage_policies"))

    def test_rejected_jit_request_does_not_grant_access(self):
        from iam_lab.jit_access import TemporaryAccessManager

        jit = TemporaryAccessManager()
        approval = JITApprovalManager(self.manager, jit, self.audit)
        admin = self.manager.create_identity("admin_user", "admin")

        request_id = approval.request_access(
            self.user["id"], "manage_policies", 30
        )

        self.assertTrue(approval.reject_request(request_id, admin["id"]))
        self.assertFalse(jit.has_access(self.user["id"], "manage_policies"))

    def test_jit_request_cannot_be_approved_twice(self):
        from iam_lab.jit_access import TemporaryAccessManager

        jit = TemporaryAccessManager()
        approval = JITApprovalManager(self.manager, jit, self.audit)
        admin = self.manager.create_identity("admin_user", "admin")

        request_id = approval.request_access(
            self.user["id"], "manage_policies", 30
        )

        approval.approve_request(request_id, admin["id"])

        with self.assertRaisesRegex(ValueError, "already processed"):
            approval.approve_request(request_id, admin["id"])

    def test_non_admin_cannot_approve_jit_request(self):
        from iam_lab.jit_access import TemporaryAccessManager

        jit = TemporaryAccessManager()
        approval = JITApprovalManager(self.manager, jit, self.audit)
        analyst = self.manager.create_identity("analyst_user", "analyst")

        request_id = approval.request_access(
            self.user["id"], "manage_policies", 30
        )

        with self.assertRaisesRegex(ValueError, "admin role"):
            approval.approve_request(request_id, analyst["id"])

        self.assertFalse(
            jit.has_access(self.user["id"], "manage_policies")
        )

    def test_inactive_requester_cannot_be_approved(self):
        from iam_lab.jit_access import TemporaryAccessManager

        jit = TemporaryAccessManager()
        approval = JITApprovalManager(self.manager, jit, self.audit)
        admin = self.manager.create_identity("admin_user", "admin")

        request_id = approval.request_access(
            self.user["id"], "manage_policies", 30
        )

        self.lifecycle.deactivate_identity(self.user["id"])

        with self.assertRaisesRegex(ValueError, "Requester is inactive"):
            approval.approve_request(request_id, admin["id"])

        self.assertFalse(
            jit.has_access(self.user["id"], "manage_policies")
        )

    def test_inactive_requester_cannot_be_rejected(self):
        from iam_lab.jit_access import TemporaryAccessManager

        jit = TemporaryAccessManager()
        approval = JITApprovalManager(self.manager, jit, self.audit)
        admin = self.manager.create_identity("admin_user", "admin")

        request_id = approval.request_access(
            self.user["id"], "manage_policies", 30
        )

        self.lifecycle.deactivate_identity(self.user["id"])

        with self.assertRaisesRegex(ValueError, "Requester is inactive"):
            approval.reject_request(request_id, admin["id"])

        self.assertEqual(
            approval.requests[request_id]["status"],
            "pending",
        )
        self.assertFalse(
            jit.has_access(self.user["id"], "manage_policies")
        )







if __name__ == "__main__":
    unittest.main()
