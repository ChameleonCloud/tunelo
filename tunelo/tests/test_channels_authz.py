from unittest import mock

from flask import Flask
from oslotest import base

from tunelo.api import channels

SPOKE_UUID = "11111111-1111-4111-8111-111111111111"
PROJECT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


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


class TestDestroyChannel(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        client_patch = mock.patch.object(channels, "get_neutron_client")
        self.addCleanup(client_patch.stop)
        self.neutron = client_patch.start().return_value
        self.neutron.list_ports.return_value = {"ports": []}

        self.app = Flask(__name__)

    def test_non_spoke_port_not_deleted(self):
        # Regression test: arbitrary Neutron ports must not be deletable
        # through this endpoint.
        self.neutron.show_port.return_value = {
            "port": fake_port(device_owner="compute:nova")
        }

        with self.app.test_request_context(f"/channels/{SPOKE_UUID}"):
            res = channels.destroy_channel(SPOKE_UUID)

        self.assertEqual(404, res.status_code)
        self.neutron.delete_port.assert_not_called()

    def test_spoke_port_deleted(self):
        self.neutron.show_port.return_value = {"port": fake_port()}

        with self.app.test_request_context(f"/channels/{SPOKE_UUID}"):
            res = channels.destroy_channel(SPOKE_UUID)

        self.assertEqual(("", 200), res)
        self.neutron.delete_port.assert_called_once_with(SPOKE_UUID)
