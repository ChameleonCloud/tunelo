from ipaddress import IPv4Address
from ipaddress import IPv4Network
from ipaddress import ip_address
from ipaddress import ip_network

from flask import Blueprint
from flask import request
from neutronclient.common.exceptions import IpAddressAlreadyAllocatedClient
from neutronclient.common.exceptions import NotFound as NeutronNotFound

from tunelo.api.hooks import get_neutron_client
from tunelo.api.hooks import route
from tunelo.api.schema import CREATE_CHANNEL_SCHEMA
from tunelo.api.schema import VALID_CHANNEL_TYPES
from tunelo.api.schema import hub_device_owner_pattern
from tunelo.api.schema import validate_uuid
from tunelo.api.utils import create_channel_representation
from tunelo.api.utils import filter_ports_by_device_owner
from tunelo.common.exception import Conflict
from tunelo.common.exception import Invalid
from tunelo.common.exception import InvalidParameterValue
from tunelo.common.exception import NotFound

bp = Blueprint("CreateChannel", __name__)

KEY_ID = 'id'
KEY_NAME = 'name'
KEY_PROJECT_ID = 'project_id'
KEY_FIXED_IP = 'fixed_ips'
KEY_IP_ADDRESS = 'ip_address'
KEY_SUBNET = 'subnet'
KEY_SUBNET_ID = 'subnet_id'
KEY_SUBNET_RANGE = 'subnet-range'
KEY_CIDR = 'cidr'
KEY_NETWORK = 'network'
KEY_NETWORK_ID = 'network_id'
KEY_HOST = 'host'
KEY_HOST_ID = 'binding:host_id'
KEY_CHANNEL_ADDRESS = 'channel_address'
KEY_CHANNEL_TYPE = 'channel_type'
KEY_PROPERTIES = 'properties'
KEY_DEVICE_OWNER = 'device_owner'
KEY_BINDING_PROFILE = 'binding:profile'

neutron = get_neutron_client()


@route("/CreateChannel", bp, methods=["POST"])
def create_channel():
    """Implements API function CreateChannel

    Follows a number of branching paths to create a new channel. The high level overview
    is as follows:

        1. Validate the format of a user-provided channel description using the schema
        helpers
        2.

    """
    if len(request.get_data()) == 0:
        raise Invalid(
            "CreateChannel requires a channel description in the request body.")
    channel_definition = request.get_json()
    CREATE_CHANNEL_SCHEMA.validate_schema(channel_definition)

    # Schema is validated, so we are free to make unchecked assumptions
    # about the format of the data in the payload
    channel_type = channel_definition[KEY_CHANNEL_TYPE]
    if channel_type not in VALID_CHANNEL_TYPES:
        raise InvalidParameterValue(f"Unknown channel type {channel_type}")

    # Externally validate the properties schema since this is the only code path that
    # can look up the proper schema via channel_type
    properties = channel_definition[KEY_PROPERTIES]
    properties_schema = VALID_CHANNEL_TYPES[channel_type]
    properties_schema.validate_schema(properties)

    name = channel_definition.get(KEY_NAME)
    project_id = channel_definition[KEY_PROJECT_ID]
    subnet = channel_definition.get(KEY_SUBNET)
    channel_address = channel_definition.get(KEY_CHANNEL_ADDRESS)

    subnet_meta = resolve_subnet(subnet, channel_address, project_id)
    subnet_cidr = subnet_meta[KEY_CIDR]
    if (subnet and channel_address) and (
            ip_address(channel_address) not in ip_network(subnet_cidr)):
        raise InvalidParameterValue(
            f"channel_address {channel_address} does not fit in subnet {subnet_cidr}")

    hub = resolve_hub(subnet_meta, project_id, name, channel_type)

    spoke = create_spoke(project_id, name, subnet_meta, channel_type, channel_address,
                         properties)

    # TODO the current channel representation returned does not include the new spoke
    # in the hub's list of peers
    # TODO shove spoke as new peer into new hub to avoid additional network round-trip
    return create_channel_representation(spoke, [hub])


def resolve_subnet(subnet, channel_address, project_id):
    """

    """
    # First, determine if the provided subnet is a UUID or an IP address
    subnet_is_uuid = validate_uuid(subnet)
    if subnet_is_uuid:
        # If the subnet is a UUID, we fetch that subnet and make sure it's valid
        try:
            matching_subnets = neutron.show_subnet(subnet)
            # Change key 'subnet' to 'subnets' to be consistent with other code paths
            matching_subnets['subnets'] = [matching_subnets.pop('subnet')]
            if matching_subnets['subnets'][0][KEY_PROJECT_ID] != project_id:
                raise InvalidParameterValue(
                    f"Subnet {subnet} is not associated with project {project_id}")
        except NeutronNotFound:
            raise NotFound(f"Subnet {subnet} not found.")
    elif not subnet:
        # If a subnet is not provided, we try to find one for the channel address
        matching_subnets = neutron.list_subnets(project_id=project_id)
        if channel_address:
            # If channel address is provided, we narrow the search further to a subnet
            # which can hold the channel address
            channel_ip = ip_address(channel_address)
            matching_subnets['subnets'] = [sub for sub in matching_subnets['subnets'] if
                                           channel_ip in ip_network(sub[KEY_CIDR])]
    else:
        # If the subnet is in CIDR, find a matching subnet for the project
        matching_subnets = neutron.list_subnets(cidr=subnet, project_id=project_id)

    if len(matching_subnets['subnets']) == 0:
        # If no subnet matching our criteria exists, we have to create a new one
        # on a valid network
        subnet_meta = new_subnet(project_id, subnet, channel_address)
    else:
        subnet_meta = matching_subnets['subnets'][0]

    return subnet_meta


def new_subnet(project_id, cidr, channel_address):
    """

    """
    networks = neutron.list_networks(project_id=project_id, is_default=True)['networks']
    if len(networks) == 0:
        raise Invalid(
            "Could not find valid network in project to create new subnet.")
    network = networks[0]
    if cidr:
        ip_version = 4 if type(ip_network(cidr)) is IPv4Network else 6
        subnet_meta = neutron.create_subnet({
            'subnets': [{
                KEY_CIDR: cidr,
                'ip_version': ip_version,
                'network_id': network[KEY_ID]
            }],
        })
    else:
        if channel_address:
            # If a channel address is provided, we try to get a subnet that will fit it
            ip = ip_address(channel_address)
            if type(ip) is IPv4Address:
                ip_version = 4
                # Default subnet mask we will use for ipv4 is 255.255.255.0
                new_cidr = '.'.join(str(ip).split('.')[:-1]) + '.0/24'
            else:
                ip_version = 6
                # Default subnet for IPv6 will use a 64 byte prefix
                new_cidr = ':'.join(str(ip).split(':')[:-4]) + '::0/64'
            create_subnet_body = {
                'subnets': [{
                    'network_id': network[KEY_ID],
                    'ip_version': ip_version,
                    'cidr': new_cidr,
                }]
            }
        else:
            # If no CIDR or channel address is provided, we will grab a random subnet
            # from a subnet pool
            subnet_pools = \
                neutron.list_subnetpools(project_id=project_id, is_default=True)[
                    'subnetpools']
            if len(subnet_pools) == 0:
                raise Invalid(
                    f'Could not find valid subnet pool for project {project_id} '
                    f'to provision new subnet.')
            create_subnet_body = {
                'subnets': [
                    {'network_id': network[KEY_ID], 'subnetpool': subnet_pools[0]}
                ]
            }
        subnet_meta = neutron.create_subnet(create_subnet_body)

    return subnet_meta['subnets'][0]


def resolve_host(channel_type):
    """

    """
    agents = neutron.list_agents(binary=f"neutron-{channel_type}-agent")
    if len(agents['agents']) == 0:
        raise NotFound(f"Could not find any hosts running {channel_type} agent.")
    return agents['agents'][0][KEY_HOST]


def resolve_hub(subnet_meta, project_id, name, channel_type):
    """
    TODO test channel creation for existing hub, non-existing hubs, and multiple hubs
    """
    subnet_id = subnet_meta[KEY_ID]
    ports = neutron.list_ports(project_id=project_id)
    hubs = filter_ports_by_device_owner(hub_device_owner_pattern, ports['ports'])
    hubs_in_subnet = list(filter(
        lambda hub: any(
            fip[KEY_SUBNET_ID] == subnet_id for fip in hub[KEY_FIXED_IP]),
        hubs))

    if len(hubs_in_subnet) > 0:
        # If there are any existing hubs in the subnet, latch onto the first one
        return hubs_in_subnet[0]

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

    return new_hub['port']


def create_spoke(project_id, name, subnet_meta, channel_type, channel_address,
                 properties):
    """

    """
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
        spoke = neutron.create_port({'port': spoke_creation_request})
    except IpAddressAlreadyAllocatedClient as exc:
        raise Conflict(exc.message.split('\n')[0] + '.')

    return spoke['port']
