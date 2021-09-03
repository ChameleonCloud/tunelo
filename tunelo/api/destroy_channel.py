from flask import Blueprint
from neutronclient.common.exceptions import PortNotFoundClient

from tunelo.api.get_channel import get_channel_by_uuid
from tunelo.api.hooks import channel_endpoint_blueprint
from tunelo.api.hooks import get_neutron_client
from tunelo.api.hooks import route
from tunelo.api.utils import get_binding_profile_attribute
from tunelo.api.utils import get_channel_uuid
from tunelo.common.exception import NotFound


@route("/channels/<uuid>", blueprint=channel_endpoint_blueprint, methods=["DELETE"])
def destroy_channel(uuid):
    """Destroys a channel by UUID

    Deletes a spoke port.
    Deletes the hub if this action would cause the hub to have zero peers

    Args:
        uuid: the UUID of the channel must be equivalent to the ``id`` field
        of a spoke port.
    """
    spoke, peers = get_channel_by_uuid(uuid)
    neutron = get_neutron_client()

    try:
        neutron.delete_port(uuid)
    except PortNotFoundClient:
        raise NotFound(f"Channel {uuid} not found.")

    # After deleting the spoke, we have to remove the spoke from its peer hub(s)
    for hub in peers:
        hub_peers = get_binding_profile_attribute(hub, "peers")
        hub_id = get_channel_uuid(hub)
        # If the hub has no peers left, it should be deleted
        if not hub_peers:
            neutron.delete_port(hub_id)
