from unittest import mock

from neutronclient.common.exceptions import NotFound as NeutronNotFound
from oslo_config import fixture as cfg_fixture
from oslotest import base

from tunelo.api import channels
from tunelo.common import exception


class BootstrapDefaultHubTest(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        self.cfg = self.useFixture(cfg_fixture.Config(channels.CONF))

        client_patch = mock.patch.object(channels, "get_neutron_client")
        self.addCleanup(client_patch.stop)
        self.neutron = client_patch.start().return_value

    def test_returns_none_when_default_subnet_unset(self):
        self.cfg.config(default_subnet=None)

        self.assertIsNone(channels.bootstrap_default_hub())
        self.neutron.find_resource.assert_not_called()

    def test_raises_invalid_when_subnet_owned_by_wrong_project(self):
        self.cfg.config(default_subnet="tunelo-calico-subnet")
        self.neutron.find_resource.return_value = {
            "id": "subnet-uuid",
            "project_id": "owner-project",
            "network_id": "net-uuid",
        }
        self.neutron.session.get_project_id.return_value = "tunelo-project"

        self.assertRaises(exception.Invalid, channels.bootstrap_default_hub)

    def test_raises_not_found_when_subnet_does_not_exist(self):
        self.cfg.config(default_subnet="tunelo-calico-subnet")
        self.neutron.find_resource.side_effect = NeutronNotFound()

        self.assertRaises(exception.NotFound, channels.bootstrap_default_hub)
