from unittest import mock

from oslo_config import fixture as cfg_fixture
from oslotest import base

from tunelo.api import hooks


class GetNeutronClientTest(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        self.cfg = self.useFixture(cfg_fixture.Config(hooks.CONF))

        # hooks caches the client and session after the first call.
        for cached in ("_NEUTRON_CLIENT", "_NEUTRON_SESSION"):
            cache_patch = mock.patch.object(hooks, cached, None)
            self.addCleanup(cache_patch.stop)
            cache_patch.start()

        auth_patch = mock.patch.object(hooks.keystone, "get_auth")
        self.addCleanup(auth_patch.stop)
        self.get_auth = auth_patch.start()

        session_patch = mock.patch.object(hooks.keystone, "get_session")
        self.addCleanup(session_patch.stop)
        self.get_session = session_patch.start()

        client_patch = mock.patch.object(hooks.neutron_client, "Client")
        self.addCleanup(client_patch.stop)
        self.neutron_client = client_patch.start()

    def test_uses_neutron_config_section(self):
        """kolla sets [neutron] valid_interfaces = internal; honour it."""
        self.cfg.config(
            group="neutron",
            valid_interfaces=["internal"],
            region_name="RegionOne",
            endpoint_override="https://neutron.example:9696",
        )

        hooks.get_neutron_client()

        self.get_session.assert_called_once_with(
            "neutron", auth=self.get_auth.return_value
        )
        self.neutron_client.assert_called_once_with(
            session=self.get_session.return_value,
            interface=["internal"],
            region_name="RegionOne",
            endpoint_override="https://neutron.example:9696",
            raise_errors=False,
        )
