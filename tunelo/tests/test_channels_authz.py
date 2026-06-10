from unittest import mock

from flask import Flask, request
from oslo_config import fixture as cfg_fixture
from oslotest import base

from tunelo import PROJECT_NAME
from tunelo.api import channels
from tunelo.common import context as tunelo_context
from tunelo.common import policy

SPOKE_UUID = "11111111-1111-4111-8111-111111111111"
HUB_UUID = "22222222-2222-4222-8222-222222222222"
PROJECT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJECT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def fake_port(
    uuid=SPOKE_UUID,
    device_owner="channel:wireguard:spoke",
    project_id=PROJECT_A,
    peers=None,
):
    return {
        "id": uuid,
        "device_owner": device_owner,
        "project_id": project_id,
        "status": "ACTIVE",
        "fixed_ips": [{"ip_address": "10.0.0.2", "subnet_id": "subnet-1"}],
        "binding:profile": {
            "public_key": "dGVzdC1wdWJsaWMta2V5",
            "peers": peers or [],
        },
    }


class ChannelsAuthzTestBase(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        self.cfg = self.useFixture(cfg_fixture.Config(channels.CONF))
        # The enforcer requires a parsed CONF to locate the policy file.
        # The API service parses CONF at startup; tests must do it here.
        policy.CONF([], project=PROJECT_NAME, default_config_files=[])

        enforcer_patch = mock.patch.object(policy, "_ENFORCER", None)
        self.addCleanup(enforcer_patch.stop)
        enforcer_patch.start()

        client_patch = mock.patch.object(channels, "get_neutron_client")
        self.addCleanup(client_patch.stop)
        self.neutron = client_patch.start().return_value

        self.app = Flask(__name__)

    def _request_context(self, path="/channels", roles=None, **kwargs):
        ctx = self.app.test_request_context(path, **kwargs)

        class _ContextInjector:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                rv = self.inner.__enter__()
                request.context = tunelo_context.RequestContext(
                    project_id=PROJECT_A,
                    roles=roles or ["member"],
                    overwrite=False,
                )
                return rv

            def __exit__(self, *exc):
                return self.inner.__exit__(*exc)

        return _ContextInjector(ctx)

    @staticmethod
    def _status_code(res):
        # Handlers return ("", 200) tuples on empty success, dicts on JSON
        # success, and flask Response objects (via make_error_response) on
        # error.
        if isinstance(res, tuple):
            return res[1]
        if isinstance(res, dict):
            return 200
        return res.status_code


class TestListChannels(ChannelsAuthzTestBase):
    def test_member_list_is_scoped_to_own_project(self):
        self.neutron.list_ports.return_value = {
            "ports": [fake_port(peers=[HUB_UUID])]
        }

        with self._request_context():
            res = channels.list_channels()

        self.neutron.list_ports.assert_called_once_with(project_id=PROJECT_A)
        self.assertEqual(1, len(res["channels"]))

    def test_member_all_projects_rejected(self):
        with self._request_context("/channels?all_projects=1"):
            res = channels.list_channels()

        self.assertEqual(403, self._status_code(res))
        self.neutron.list_ports.assert_not_called()

    def test_admin_all_projects_unscoped(self):
        self.neutron.list_ports.return_value = {"ports": []}

        with self._request_context(
            "/channels?all_projects=1", roles=["admin"]
        ):
            res = channels.list_channels()

        self.neutron.list_ports.assert_called_once_with()
        self.assertEqual({"channels": []}, res)


class TestGetChannel(ChannelsAuthzTestBase):
    def setUp(self):
        super().setUp()
        self.neutron.list_ports.return_value = {"ports": []}

    def test_owner_allowed(self):
        self.neutron.show_port.return_value = {"port": fake_port()}

        with self._request_context(f"/channels/{SPOKE_UUID}"):
            res = channels.get_channel(SPOKE_UUID)

        self.assertEqual(200, self._status_code(res))
        self.assertEqual(SPOKE_UUID, res["uuid"])

    def test_non_owner_rejected(self):
        self.neutron.show_port.return_value = {
            "port": fake_port(project_id=PROJECT_B)
        }

        with self._request_context(f"/channels/{SPOKE_UUID}"):
            res = channels.get_channel(SPOKE_UUID)

        self.assertEqual(403, self._status_code(res))

    def test_admin_allowed_for_other_project(self):
        self.neutron.show_port.return_value = {
            "port": fake_port(project_id=PROJECT_B)
        }

        with self._request_context(f"/channels/{SPOKE_UUID}", roles=["admin"]):
            res = channels.get_channel(SPOKE_UUID)

        self.assertEqual(200, self._status_code(res))


class TestDestroyChannel(ChannelsAuthzTestBase):
    def setUp(self):
        super().setUp()
        self.neutron.list_ports.return_value = {"ports": []}

    def test_non_spoke_port_not_deleted(self):
        # Regression test: arbitrary Neutron ports must not be deletable
        # through this endpoint.
        self.neutron.show_port.return_value = {
            "port": fake_port(device_owner="compute:nova")
        }

        with self._request_context(f"/channels/{SPOKE_UUID}"):
            res = channels.destroy_channel(SPOKE_UUID)

        self.assertEqual(404, self._status_code(res))
        self.neutron.delete_port.assert_not_called()

    def test_non_owner_rejected(self):
        self.neutron.show_port.return_value = {
            "port": fake_port(project_id=PROJECT_B)
        }

        with self._request_context(f"/channels/{SPOKE_UUID}"):
            res = channels.destroy_channel(SPOKE_UUID)

        self.assertEqual(403, self._status_code(res))
        self.neutron.delete_port.assert_not_called()

    def test_owner_allowed(self):
        self.neutron.show_port.return_value = {"port": fake_port()}

        with self._request_context(f"/channels/{SPOKE_UUID}"):
            res = channels.destroy_channel(SPOKE_UUID)

        self.assertEqual(200, self._status_code(res))
        self.neutron.delete_port.assert_called_once_with(SPOKE_UUID)


class TestUpdateChannel(ChannelsAuthzTestBase):
    def setUp(self):
        super().setUp()
        self.neutron.list_ports.return_value = {"ports": []}

    def test_non_owner_rejected(self):
        self.neutron.show_port.return_value = {
            "port": fake_port(project_id=PROJECT_B)
        }

        with self._request_context(
            f"/channels/{SPOKE_UUID}",
            method="PATCH",
            json={"name": "new-name"},
        ):
            res = channels.update_channel(SPOKE_UUID)

        self.assertEqual(403, self._status_code(res))
        self.neutron.update_port.assert_not_called()

    def test_owner_allowed(self):
        self.neutron.show_port.return_value = {"port": fake_port()}

        with self._request_context(
            f"/channels/{SPOKE_UUID}",
            method="PATCH",
            json={"name": "new-name"},
        ):
            res = channels.update_channel(SPOKE_UUID)

        self.assertEqual(200, self._status_code(res))
        self.neutron.update_port.assert_called_once()


class TestCreateChannel(ChannelsAuthzTestBase):
    def setUp(self):
        super().setUp()

        for helper in ("get_or_create_subnet", "resolve_hub", "create_spoke"):
            patcher = mock.patch.object(channels, helper)
            self.addCleanup(patcher.stop)
            setattr(self, helper, patcher.start())

        self.get_or_create_subnet.return_value = {
            "id": "subnet-1",
            "cidr": "10.0.0.0/24",
            "network_id": "net-1",
        }
        self.resolve_hub.return_value = fake_port(
            uuid=HUB_UUID, device_owner="channel:wireguard:hub"
        )
        self.create_spoke.return_value = fake_port(peers=[HUB_UUID])

    def _body(self, project_id=None):
        body = {
            "channel_type": "wireguard",
            "properties": {"public_key": "dGVzdC1wdWJsaWMta2V5"},
        }
        if project_id:
            body["project_id"] = project_id
        return body

    def test_project_id_defaults_to_caller(self):
        with self._request_context(
            "/channels", method="POST", json=self._body()
        ):
            res = channels.create_channel()

        self.assertEqual(200, self._status_code(res))
        self.assertEqual(PROJECT_A, self.create_spoke.call_args.args[0])

    def test_member_mismatched_project_rejected(self):
        with self._request_context(
            "/channels", method="POST", json=self._body(project_id=PROJECT_B)
        ):
            res = channels.create_channel()

        self.assertEqual(403, self._status_code(res))
        self.create_spoke.assert_not_called()

    def test_admin_may_create_in_other_project(self):
        with self._request_context(
            "/channels",
            method="POST",
            json=self._body(project_id=PROJECT_B),
            roles=["admin"],
        ):
            res = channels.create_channel()

        self.assertEqual(200, self._status_code(res))
        self.assertEqual(PROJECT_B, self.create_spoke.call_args.args[0])
