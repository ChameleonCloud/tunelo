from collections import defaultdict
from functools import partial

from flask import make_response
from oslo_log import log

from tunelo.api.schema import VALID_CHANNEL_TYPES
from tunelo.api.schema import device_owner_pattern
from tunelo.api.schema import valid_hub_peer_pattern
from tunelo.common.exception import MalformedChannel

LOG = log.getLogger(__name__)


def make_error_response(message=None, status_code=None):
    return make_response(
        {
            "error": message,
        },
        status_code,
    )


def create_channel_representation(port, peers=None):
    """Creates a JSON (dict) representation of a channel as described by the
    Channel Service design spec.

    While this is a super-set of the peer representation of a channel, all of the fields
    for a channel are derived manually in this function to ensure that the order
    of keys in the objects returned by the API are always the same.

    Args:
        port: A dictionary which describes metadata of the port
            for which we are deriving a channel representation.
            This should be an un-modified reference to a dictionary
            returned by ``neutron_client.list_ports``
        peers (Optional): The peer channel(s) to which this channel is connected,
            if any.

    Returns: A ``dict`` containing the Channel's uuid, channel_type, peers, status,
    and properties.
    """
    return {
        "uuid": get_channel_uuid(port),
        "channel_type": get_channel_type(port),
        "peers": [create_spoke_peer_representation(peer) for peer in peers],
        "status": get_channel_status(port),
        "properties": get_channel_properties(port),
    }


def create_spoke_peer_representation(port):
    """Creates a simplified channel representation of a port for use in the ``'peers'``
    field of the channel representation. This is a subset of a channel description
    which provides a simplified view into a peer channel.

    Args:
        port: A dictionary which describes metadata of the port
            for which we are deriving a channel representation.
            This should be an un-modified reference to a dictionary
            returned by ``neutron_client.list_ports``

    Returns: A ``dict`` containing the peer's uuid, status, and properties.
    """
    return {
        "uuid": get_channel_uuid(port),
        "status": get_channel_status(port),
        "properties": get_channel_properties(port),
    }


def get_binding_profile_attribute(port, attr):
    """Retrieves a value from a channel's ``binding:profile`` dict

    Raises:
        MalformedChannel: If the channel's ``binding:profile`` dict has no ``attr``
    """
    profile = get_channel_properties(port)
    val = profile.get(attr)
    if not val:
        raise MalformedChannel(
            f"Port {port['id']} missing required binding:profile attribute {attr}."
        )
    return val


def create_hub_peer_representation(spoke):
    """Creates a peer representation in the form of pubkey|endpoint|allowed_ips.
    This is how peers are listed in the ``peers`` attribute of a hub port's
    ``binding:profile``.

    Args:
        spoke: The spoke port that will be represented
    """
    pubkey = get_spoke_channel_public_key(spoke)
    endpoint = get_spoke_channel_endpoint(spoke)
    allowed_ips = ",".join([ip["ip_address"] for ip in get_fixed_ips(spoke)])
    return f"{pubkey}|{endpoint}|{allowed_ips}"


def get_fixed_ips(spoke):
    return spoke["fixed_ips"]


def get_channel_properties(port):
    """Retreives a channel's binding:profile dict"""
    return port["binding:profile"]


def get_channel_type(port):
    """Resolves a channel's type as determined by its ``device_owner`` attribute
    as such:

    ``"channel:<channel_type>:(spoke|hub)"``

    Raises:
        MalformedChannel: If this channel has an invalid ``device_owner``
    """
    device_owner = get_channel_device_owner(port)
    valid_device_owner = device_owner_pattern.match(device_owner)
    if not valid_device_owner:
        raise MalformedChannel(
            f"Port {port['id']} has invalid device_owner: {device_owner}."
        )
    channel_type = valid_device_owner.group("channel_type")
    if channel_type not in VALID_CHANNEL_TYPES:
        raise MalformedChannel(f"Channel type '{channel_type}' is not supported.")
    return channel_type


def get_channel_network_id(port):
    return port["network_id"]


def get_channel_device_owner(port):
    return port["device_owner"]


get_spoke_channel_public_key = partial(get_binding_profile_attribute, attr="public_key")


def get_spoke_channel_endpoint(port):
    """Fetches the endpoint, if it exists. Else, returns an empty string"""
    if "endpoint" in get_channel_properties(port):
        return get_binding_profile_attribute(port, "endpoint")
    else:
        return ""


def get_channel_uuid(port):
    return port["id"]


def get_channel_endpoint(port):
    return port["endpoint"]


def get_channel_status(port):
    return port["status"]


def get_channel_project_id(port):
    return port["project_id"]


def get_channel_peers_spokes(spokes, hubs):
    """Gets a peers for a collection of spoke ports

    A peer for a spoke channel is, for now, defined as any hub channel which has
    a spoke's public key in its peers list.

    This function fetches peers for multiple spokes, which makes it more efficient
    for use in ListChannel.

    Args:
        spokes: An iterable of spoke port definitions, which are generated by
        ``neutron_client.get_ports()``
        hubs: An iterable of hub port definitions, which are generated by
        ``neutron_client.get_ports()``

    Raises:
        MalformedChannel: If a hub port has an invalid peer entry

    Returns:
        A dictionary, mapping spoke UUIDs to lists of hubs which have them as peers
    """
    if not hubs:
        return {get_channel_uuid(s): [] for s in spokes}
    if not spokes:
        return {}

    # Maps spoke public keys to hubs which have a peer with a given spoke public key
    hubs_by_peer_representation = defaultdict(list)

    # We determine a hub to be a peer if it has an entry with ``port``'s public key
    # in its own list of peers
    for hub in hubs:
        peers = get_channel_properties(hub).get("peers")
        if not peers:
            continue
        for peer in peers:
            # Hub ports have peer entries which represent spokes.
            # These entries look like "pubkey|endpoint|allowed_ips
            valid_peer = valid_hub_peer_pattern.match(peer)
            if not valid_peer:
                raise MalformedChannel(
                    f"Hub channel {get_channel_uuid(hub)} "
                    f"has invalid peer entry: {peer}"
                )
            hubs_by_peer_representation[peer].append(hub)

    return {
        get_channel_uuid(spoke): hubs_by_peer_representation.get(
            create_hub_peer_representation(spoke), []
        )
        for spoke in spokes
    }


def filter_ports_by_device_owner(filter_regex, port_list):
    return [p for p in port_list if filter_regex.match(get_channel_device_owner(p))]
