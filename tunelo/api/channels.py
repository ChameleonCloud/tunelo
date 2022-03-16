import random
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import List, Tuple

from flask import Blueprint
from neutronclient.common.exceptions import IpAddressAlreadyAllocatedClient
from neutronclient.common.exceptions import NotFound as NeutronNotFound
from neutronclient.common.exceptions import PortNotFoundClient
from oslo_utils import netutils, uuidutils

from tunelo.api import schema
from tunelo.api.hooks import get_neutron_client, route
from tunelo.api.schema import (
    hub_device_owner_pattern,
    spoke_device_owner_pattern,
)
from tunelo.api.utils import (
    create_channel_representation,
    filter_ports_by_device_owner,
    get_channel_device_owner,
    get_channel_peers_spokes,
    get_channel_project_id,
    get_channel_properties,
    get_channel_type,
    get_channel_uuid,
)
from tunelo.api.utils import create_hub_peer_representation
from tunelo.common.exception import (
    Conflict,
    Invalid,
    InvalidParameterValue,
    MalformedChannel,
    NotFound,
)
from tunelo.conf import CONF

bp = Blueprint("channels", __name__)

KEY_ID = "id"
KEY_NAME = "name"
KEY_PROJECT_ID = "project_id"
KEY_FIXED_IP = "fixed_ips"
KEY_IP_ADDRESS = "ip_address"
KEY_SUBNET = "subnet"
KEY_SUBNET_ID = "subnet_id"
KEY_SUBNET_RANGE = "subnet-range"
KEY_CIDR = "cidr"
KEY_NETWORK = "network"
KEY_NETWORK_ID = "network_id"
KEY_HOST = "host"
KEY_HOST_ID = "binding:host_id"
KEY_CHANNEL_ADDRESS = "channel_address"
KEY_CHANNEL_TYPE = "channel_type"
KEY_PROPERTIES = "properties"
KEY_DEVICE_OWNER = "device_owner"
KEY_BINDING_PROFILE = "binding:profile"


def _is_cidr(val):
    return netutils.is_valid_cidr(val) or netutils.is_valid_ipv6_cidr(val)


@route("/channels", blueprint=bp, methods=["GET"])
def list_channels():
    """Implements API function ListChannels

    All Neutron ports are pulled down and then channel spokes and hubs are derived
    locally. Peer hubs for each spoke are mapped, and then a list of
    channel representations is returned for all of the spokes
    """
    ports = get_neutron_client().list_ports()
    spokes = filter_ports_by_device_owner(spoke_device_owner_pattern, ports["ports"])
    hubs = filter_ports_by_device_owner(hub_device_owner_pattern, ports["ports"])

    spoke_peers = get_channel_peers_spokes(spokes, hubs)

    return {
        "channels": [
            create_channel_representation(spoke, spoke_peers[get_channel_uuid(spoke)])
            for spoke in spokes
        ]
    }


@route("/channels/<uuid>", blueprint=bp, methods=["GET"])
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


def get_channel_by_uuid(uuid) -> "Tuple[dict, dict[str, List[dict]]]":
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


@route(
    "/channels",
    blueprint=bp,
    json_body="channel_definition",
    methods=["POST"],
)
@schema.validate(channel_definition=schema.CREATE_CHANNEL_SCHEMA)
def create_channel(channel_definition=None):
    """Implements API function CreateChannel

    Follows a number of branching paths to create a new channel. The high level overview
    is as follows:

        1. Resolve the subnet
            a. If the subnet is a UUID, fetch it from OpenStack
            b. If the subnet is in CIDR notation:
                I. Attempt to find an existing subnet under the project that uses
                   the provided subnet address space
                II. If there is not existing subnet that fits, create a new one using
                    the provided CIDR
            c. If the subnet is not provided:
                I. Attempt to find an existing subnet under the project that will fit
                   the provided channel address
                II. If the channel address is not provided, provision a new subnet
                    from any fitting subnet pool.
        2. Ensure that, if a channel address is provided, it fits into the resolved
        subnet.
        3. Resolve an appropriate hub port for the channel
            a. Find a port with channel owner ``channel:<type>:hub`` that uses the same
               subnet that was resolved in step 1.
            b. If no such port exists, we create one.
        4. Create a spoke port using the provided channel information.
        5. Return a channel representation of the new spoke port
    """
    # Since schema is validated ahead of time, we are free to make unchecked assumptions
    # about the format of the data in the payload
    channel_type = channel_definition[KEY_CHANNEL_TYPE]
    if channel_type not in schema.VALID_CHANNEL_TYPES:
        raise InvalidParameterValue(f"Unknown channel type {channel_type}")

    properties = channel_definition[KEY_PROPERTIES]

    name = channel_definition.get(KEY_NAME)
    project_id = channel_definition[KEY_PROJECT_ID]
    subnet = channel_definition.get(KEY_SUBNET)
    channel_address = channel_definition.get(KEY_CHANNEL_ADDRESS)

    subnet_meta = get_or_create_subnet(subnet, channel_address, project_id)
    subnet_cidr = subnet_meta[KEY_CIDR]
    if (subnet and channel_address) and (
        ip_address(channel_address) not in ip_network(subnet_cidr)
    ):
        raise InvalidParameterValue(
            f"channel_address {channel_address} does not fit in subnet {subnet_cidr}"
        )

    spoke = create_spoke(
        project_id, name, subnet_meta, channel_type, channel_address, properties
    )

    # The current channel representation returned does not include the new spoke
    # in the hub's list of peers, so we shove the new spoke spoke as s new peer
    # into new hub to avoid an additional network round-trip.
    hub = resolve_hub(subnet_meta, project_id, name, channel_type)
    hub_peers = hub["binding:profile"].setdefault("peers", [])
    hub_peers.append(create_hub_peer_representation(spoke))

    return create_channel_representation(spoke, [hub])


@route("/channels/<uuid>", blueprint=bp, methods=["DELETE"])
@schema.validate(uuid=schema.uuid)
def destroy_channel(uuid):
    """Destroys a channel by UUID

    Deletes a spoke port.
    Deletes the hub if this action would cause the hub to have zero peers

    Args:
        uuid: the UUID of the channel must be equivalent to the ``id`` field
        of a spoke port.
    """
    _, peers = get_channel_by_uuid(uuid)
    neutron = get_neutron_client()

    try:
        neutron.delete_port(uuid)
    except PortNotFoundClient:
        raise NotFound(f"Channel {uuid} not found.")

    for peer in peers.values():
        peer_peers = peer["binding:profile"]["peers"]
        # If removing the last peer from our peer, our peer is now an orphan and can
        # also be cleaned up.
        # TODO(jason): this should probably be optional behavior in the future.
        if len(peer_peers) == 1:
            neutron.delete_port(get_channel_uuid(peer))


@route(
    "/channels/<uuid>",
    blueprint=bp,
    json_body="patch",
    methods=["PATCH", "PUT"],
)
@schema.validate(uuid=schema.uuid, patch=schema.UPDATE_CHANNEL_SCHEMA)
def update_channel(uuid, patch=None):
    """Implements the UpdateChannel API function"""
    spoke, peers = get_channel_by_uuid(uuid)

    channel_type = get_channel_type(spoke)
    if channel_type not in schema.VALID_CHANNEL_TYPES:
        raise MalformedChannel(
            f"Channel {uuid} has unknown channel type {channel_type}."
        )

    # Because properties are nested, and we don't want to fully overwrite,
    # we update the fields manually rather than using dict.update() on the whole port
    update_dict = {}
    name = patch.get("name")
    properties = patch.get("properties")
    if properties:
        channel_properties = get_channel_properties(spoke)
        channel_properties.update(properties)
        update_dict["binding:profile"] = channel_properties
    if name:
        update_dict["name"] = name

    get_neutron_client().update_port(uuid, body={"port": update_dict})

    spoke, peers = get_channel_by_uuid(uuid)
    return create_channel_representation(spoke, peers[uuid])


def get_or_create_subnet(subnet, channel_address, project_id):
    neutron = get_neutron_client()

    def _resolve_subnets(subnet_ref):
        if _is_cidr(subnet):
            return neutron.list_subnets(cidr=subnet, project_id=project_id)["subnets"]

        try:
            if uuidutils.is_uuid_like(subnet_ref):
                matching_subnets = [neutron.show_subnet(subnet_ref)["subnet"]]
            else:
                matching_subnets = neutron.list_subnets(
                    name=subnet_ref, project_id=project_id
                )["subnets"]

            if matching_subnets and matching_subnets[0][KEY_PROJECT_ID] != project_id:
                raise InvalidParameterValue(
                    f"Subnet {subnet_ref} is not associated with project {project_id}"
                )
            return matching_subnets
        except NeutronNotFound:
            raise NotFound(f"Subnet {subnet_ref} not found.")

    if not subnet and channel_address:
        # If a subnet is not provided, we try to find one for the channel address
        matching_subnets = neutron.list_subnets(project_id=project_id)["subnets"]
        try:
            channel_ip = ip_address(channel_address)
        except (ValueError, TypeError):
            raise InvalidParameterValue(
                f"Channel address {channel_address} is not a valid IP address."
            )
        matching_subnets = [
            sub
            for sub in matching_subnets["subnets"]
            if channel_ip in ip_network(sub[KEY_CIDR])
        ]
    elif subnet:
        matching_subnets = _resolve_subnets(subnet)
    else:
        matching_subnets = []

    if not matching_subnets:
        if CONF.default_subnet:
            subnet_meta = _resolve_subnets(CONF.default_subnet)[0]
        else:
            # If no subnet matching our criteria exists, we have to create a new one
            # on a valid network
            subnet_meta = new_subnet(project_id, subnet, channel_address)
    else:
        subnet_meta = random.choice(matching_subnets)

    return subnet_meta


def new_subnet(project_id, cidr, channel_address):
    """Creates a new subnet based on either a provided CIDR notation
    or by trying to fit a provided channel address
    """
    neutron = get_neutron_client()
    networks = neutron.list_networks(project_id=project_id, is_default=True)["networks"]
    if len(networks) == 0:
        raise Invalid("Could not find valid network in project to create new subnet.")
    network = networks[0]
    if cidr:
        ip_version = 4 if type(ip_network(cidr)) is IPv4Network else 6
        subnet_meta = neutron.create_subnet(
            {
                "subnet": {
                    KEY_CIDR: cidr,
                    "ip_version": ip_version,
                    "network_id": network[KEY_ID],
                }
            }
        )
    else:
        if channel_address:
            # If a channel address is provided, we try to get a subnet that will fit it
            ip = ip_address(channel_address)
            if type(ip) is IPv4Address:
                ip_version = 4
                # Default subnet mask we will use for ipv4 is 255.255.255.0
                new_cidr = ".".join(str(ip).split(".")[:-1]) + ".0/24"
            else:
                ip_version = 6
                # Default subnet for IPv6 will use a 64 byte prefix
                new_cidr = ":".join(str(ip).split(":")[:-4]) + "::0/64"
            create_subnet_body = {
                "subnet": {
                    "network_id": network[KEY_ID],
                    "ip_version": ip_version,
                    "cidr": new_cidr,
                }
            }
        else:
            # If no CIDR or channel address is provided, we will grab a random subnet
            # from a subnet pool
            subnet_pools = neutron.list_subnetpools(
                project_id=project_id, is_default=True
            )["subnetpools"]
            if len(subnet_pools) == 0:
                raise Invalid(
                    f"Could not find valid subnet pool for project {project_id} "
                    f"to provision new subnet."
                )
            create_subnet_body = {
                "subnet": {"network_id": network[KEY_ID], "subnetpool": subnet_pools[0]}
            }
        subnet_meta = neutron.create_subnet(create_subnet_body)

    return subnet_meta["subnet"]


def resolve_host(channel_type):
    neutron = get_neutron_client()
    agents = neutron.list_agents(binary=f"neutron-{channel_type}-agent")
    if len(agents["agents"]) == 0:
        raise NotFound(f"Could not find any hosts running {channel_type} agent.")
    return random.choice(agents["agents"])[KEY_HOST]


def resolve_hub(subnet_meta, project_id, name, channel_type):
    """
    TODO test channel creation for existing hub, non-existing hubs, and multiple hubs
    """
    neutron = get_neutron_client()
    subnet_id = subnet_meta[KEY_ID]
    ports = neutron.list_ports(project_id=project_id)
    hubs = filter_ports_by_device_owner(hub_device_owner_pattern, ports["ports"])
    hubs_in_subnet = [
        hub
        for hub in hubs
        if any(fip[KEY_SUBNET_ID] == subnet_id for fip in hub[KEY_FIXED_IP])
    ]

    if len(hubs_in_subnet) > 0:
        # If there are any existing hubs in the subnet, latch onto a random one
        return random.choice(hubs_in_subnet)

    hub_creation_request = {
        KEY_PROJECT_ID: project_id,
        KEY_FIXED_IP: [{KEY_SUBNET_ID: subnet_id}],
        KEY_NETWORK_ID: subnet_meta[KEY_NETWORK_ID],
        KEY_HOST_ID: resolve_host(channel_type),
        KEY_DEVICE_OWNER: f"channel:{channel_type}:hub",
        KEY_BINDING_PROFILE: {},
    }
    if name:
        hub_creation_request[KEY_NAME] = name

    new_hub = neutron.create_port({"port": hub_creation_request})

    return new_hub["port"]


def create_spoke(
    project_id, name, subnet_meta, channel_type, channel_address, properties
):
    """Creates a new spoke port using the provided channel information"""
    subnet_id = subnet_meta[KEY_ID]
    # If there are no hubs to attach to, we have to create a new one
    if not channel_address:
        # If channel address is not provided, neutron will find us an available IP
        fixed_ip = [{KEY_SUBNET_ID: subnet_id}]
    else:
        fixed_ip = [{KEY_SUBNET_ID: subnet_id, KEY_IP_ADDRESS: channel_address}]

    spoke_creation_request = {
        KEY_PROJECT_ID: project_id,
        KEY_FIXED_IP: fixed_ip,
        KEY_NETWORK_ID: subnet_meta[KEY_NETWORK_ID],
        KEY_DEVICE_OWNER: f"channel:{channel_type}:spoke",
        KEY_BINDING_PROFILE: properties,
    }
    if name:
        spoke_creation_request[KEY_NAME] = name

    try:
        spoke = get_neutron_client().create_port({"port": spoke_creation_request})
    except IpAddressAlreadyAllocatedClient as exc:
        raise Conflict(exc.message.split("\n")[0] + ".")

    return spoke["port"]
