from flask import Blueprint

from tunelo.api.get_channel import get_channel_by_uuid
from tunelo.api.hooks import get_neutron_client
from tunelo.api.hooks import route
from tunelo.api.utils import create_hub_peer_representation
from tunelo.api.utils import get_binding_profile_attribute
from tunelo.api.utils import get_channel_properties
from tunelo.api.utils import get_channel_uuid

bp = Blueprint("DestroyChannel", __name__)


@route("/DestroyChannel/<uuid>", bp, methods=["POST"])
def destroy_channel(uuid):
    """Destroys a channel by UUID

    Deletes a spoke port, and removes that port from the peer list of its corresponding
    hub. Deletes the hub if this action would cause the hub to have zero peers

    Args:
        uuid: the UUID of the channel must be equivalent to the ``id`` field
        of a spoke port.
    """
    spoke, peers = get_channel_by_uuid(uuid)

    neutron = get_neutron_client()
    spoke_as_peer = create_hub_peer_representation(spoke)
    neutron.delete_port(uuid)
    # After deleting the spoke, we have to remove the spoke from its peer hub(s)
    for hub in peers:
        hub_peers = get_binding_profile_attribute(hub, 'peers')
        hub_peers.remove(spoke_as_peer)
        hub_id = get_channel_uuid(hub)
        # If the hub has no peers left, it should be deleted
        if not hub_peers:
            neutron.delete_port(hub_id)
        # If the hub still has peers, we need to update its peer list
        else:
            neutron.update_port(hub_id, {
                'port': {'binding:profile': get_channel_properties(hub)}
            })
