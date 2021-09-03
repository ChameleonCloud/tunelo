from tunelo.api import schema
from tunelo.api.get_channel import get_channel_by_uuid
from tunelo.api.hooks import channel_endpoint_blueprint
from tunelo.api.hooks import get_neutron_client
from tunelo.api.hooks import route
from tunelo.api.utils import create_channel_representation
from tunelo.api.utils import get_channel_properties
from tunelo.api.utils import get_channel_type
from tunelo.common.exception import MalformedChannel


@route(
    "/channels/<uuid>",
    blueprint=channel_endpoint_blueprint,
    json_body="patch",
    methods=["PATCH", "PUT"],
)
@schema.validate(uuid=schema.uuid, patch=schema.UPDATE_CHANNEL_SCHEMA)
def update_channel(uuid, patch=None):
    """ """
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

    neutron = get_neutron_client()
    neutron.update_port(uuid, body={"port": update_dict})

    spoke, peers = get_channel_by_uuid(uuid)
    return create_channel_representation(spoke, peers[uuid])
