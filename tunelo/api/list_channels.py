from flask import Blueprint

from tunelo.api.hooks import get_neutron_client
from tunelo.api.hooks import route
from tunelo.api.schema import hub_device_owner_pattern
from tunelo.api.schema import spoke_device_owner_pattern
from tunelo.api.utils import create_channel_representation
from tunelo.api.utils import filter_ports_by_device_owner
from tunelo.api.utils import get_channel_peers_spokes
from tunelo.api.utils import get_channel_uuid

bp = Blueprint("ListChannels", __name__)


@route("/ListChannels", bp)
def list_channels():
    """Implements API function ListChannels

    All Neutron ports are pulled down and then channel spokes and hubs are derived
    locally. Peer hubs for each spoke are mapped, and then a list of
    channel representations is returned for all of the spokes
    """
    neutron = get_neutron_client()
    ports = neutron.list_ports()
    spokes = filter_ports_by_device_owner(spoke_device_owner_pattern, ports['ports'])
    hubs = filter_ports_by_device_owner(hub_device_owner_pattern, ports['ports'])

    spoke_peers = get_channel_peers_spokes(spokes, hubs)

    return {
        "channels": [
            create_channel_representation(spoke, spoke_peers[get_channel_uuid(spoke)])
            for spoke in spokes
        ]
    }
