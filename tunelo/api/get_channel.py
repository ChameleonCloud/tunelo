from typing import List
from typing import Tuple

from neutronclient.common.exceptions import PortNotFoundClient

from tunelo.api import schema
from tunelo.api.hooks import channel_endpoint_blueprint
from tunelo.api.hooks import get_neutron_client
from tunelo.api.hooks import route
from tunelo.api.schema import spoke_device_owner_pattern
from tunelo.api.utils import create_channel_representation
from tunelo.api.utils import get_channel_device_owner
from tunelo.api.utils import get_channel_peers_spokes
from tunelo.api.utils import get_channel_project_id
from tunelo.api.utils import get_channel_type
from tunelo.common.exception import NotFound


@route("/channels/<uuid>", blueprint=channel_endpoint_blueprint, methods=["GET"])
@schema.validate(uuid=schema.uuid)
def get_channel(uuid):
    """Gets a channel by UUID

    Returns a channel representation for a spoke port

    Args:
        uuid:
            The UUID of the channel must be equivalent to the ``id`` field of
            a spoke port.
    """
    spoke, peers = get_channel_by_uuid(uuid)

    return create_channel_representation(spoke, peers.get(uuid, []))


def get_channel_by_uuid(uuid) -> Tuple[dict, List[dict]]:
    """Gets a channel (spoke) and its peers (hubs) from a UUID

    Args:
        uuid: The UUID of a spoke port

    Returns:
        A tuple containing a spoke port dict and a list of peer hub port dicts
    """
    neutron = get_neutron_client()

    try:
        spoke = neutron.show_port(uuid)["port"]
    except PortNotFoundClient:
        raise NotFound(f"Channel {uuid} not found.")

    # GetChannel is only allowed to retrieve spoke ports
    if not spoke_device_owner_pattern.match(get_channel_device_owner(spoke)):
        raise NotFound(f"Channel {uuid} not found.")

    # Retrieve potential peers by looking for hubs on the same project as the spoke
    channel_type = get_channel_type(spoke)
    hub_owner = f"channel:{channel_type}:hub"
    project_id = get_channel_project_id(spoke)
    hubs = neutron.list_ports(device_owner=hub_owner, project_id=project_id)["ports"]
    # Confirm that a hub is our peer by matching it to our public key
    peers = get_channel_peers_spokes([spoke], hubs)

    return spoke, peers
