from unittest import mock

from oslo_config import fixture as cfg_fixture
from oslo_policy.policy import PolicyNotAuthorized
from oslotest import base

from tunelo import PROJECT_NAME
from tunelo.common import context as tunelo_context
from tunelo.common import policy


class PolicyTest(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        self.cfg = self.useFixture(cfg_fixture.Config(policy.CONF))
        # The enforcer requires a parsed CONF to locate the policy file.
        # The API service parses CONF at startup; tests must do it here.
        policy.CONF([], project=PROJECT_NAME, default_config_files=[])

        enforcer_patch = mock.patch.object(policy, "_ENFORCER", None)
        self.addCleanup(enforcer_patch.stop)
        enforcer_patch.start()

    def _make_context(self, project_id, roles):
        return tunelo_context.RequestContext(
            project_id=project_id, roles=roles, overwrite=False
        )

    def test_owner_allowed(self):
        ctx = self._make_context("proj-a", ["member"])
        self.assertTrue(
            policy.authorize("channel:get", ctx, {"project_id": "proj-a"})
        )

    def test_non_owner_rejected(self):
        ctx = self._make_context("proj-a", ["member"])
        for rule in (
            "channel:get",
            "channel:create",
            "channel:update",
            "channel:delete",
        ):
            self.assertRaises(
                PolicyNotAuthorized,
                policy.authorize,
                rule,
                ctx,
                {"project_id": "proj-b"},
            )

    def test_admin_allowed_for_other_project(self):
        ctx = self._make_context("admin-proj", ["admin"])
        self.assertTrue(
            policy.authorize("channel:delete", ctx, {"project_id": "proj-b"})
        )

    def test_admin_allowed_for_null_project_target(self):
        ctx = self._make_context("admin-proj", ["admin"])
        self.assertTrue(
            policy.authorize("channel:get", ctx, {"project_id": None})
        )

    def test_non_admin_rejected_for_null_project_target(self):
        ctx = self._make_context("proj-a", ["member"])
        self.assertRaises(
            PolicyNotAuthorized,
            policy.authorize,
            "channel:get",
            ctx,
            {"project_id": None},
        )
