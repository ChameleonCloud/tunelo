import binascii
import re
from base64 import b64decode
from ipaddress import ip_address
from ipaddress import ip_network
from uuid import UUID

from tunelo.common.exception import Invalid
from tunelo.common.exception import InvalidParameterValue
from tunelo.common.exception import MissingParameterValue

spoke_device_owner_pattern = re.compile(r"channel:(?P<channel_type>.*):spoke")
hub_device_owner_pattern = re.compile(r"channel:(?P<channel_type>.*):hub")
device_owner_pattern = re.compile(r"channel:(?P<channel_type>.*):(spoke|hub)")
valid_hub_peer_pattern = re.compile(
    r"(?P<public_key>.+)\|(?P<endpoint>.*)\|(?P<allowed_ips>.+)"
)


class SchemaItem(object):
    """A data class representing a single schema item which holds onto
    the minimum amount of information required to validate a parameter.

    Accepts a validation function, which returns a boolean, to validate a single
    input, and optional error message, which can provide more context about an invalid
    parameter, and and optional flag, which states whether or not a parameter is
    optional.
    """

    def __init__(self, validate, error_message="Invalid value", optional=False):
        self.validate = validate
        self.error_message = error_message
        self.optional = optional


class SchemaValidator(object):
    """A class meant for quickly validating only the format of a payload of a POST
    request. This is to ensure that:

        1. The API can return useful, informative error messages to the user about any
        mistakes they've made in their request.
        2. We are able to extract the most useful error information when the data is
        forwarded to OpenStack.

    A ``SchemaValidator`` should only ensure that a payload _could_ be valid. Any other
    checks should be provided by OpenStack itself.

    For example: If an item in a payload is intended to reserve an IP address, the
    ``SchemaValidator`` should ensure that the value for that parameter is a valid IP
    address. It should NOT ensure that the IP address is available and can be bound on
    the relevant network. That should be handled by OpenStack.

    A strict schema is one that doesn't allow any unknown (extra) parameters to be
    included in the payload. Optional parameters may still not be provided.
    """

    def __init__(self, strict=True, **schema):
        self.strict = strict
        self.schema_map = schema

    def validate_schema(self, payload):
        """Goes through every parameter in the payload and validates it against each
        associated schema item.

        Args:
            payload: The raw body of a POST request in JSON (dict) format.

        Raises:
            UnknownParameter:
                If an unknown parameter is provided and this schema is strict
            MissingParameterValue:
                If a non-optional parameter is not provided in the payload
            InvalidParameterValue:
                If a parameter fails validation
            Invalid:
                If an invalid payload is provided
        """
        if not payload or len(payload) == 0:
            raise Invalid("No channel data provided in request body.")

        # This union represents all recognized params combined with all provided params
        for param in set(payload.keys()).union(self.schema_map.keys()):
            # Reject any unknown parameters provided if the schema is strict
            if self.strict and param not in self.schema_map:
                raise Invalid(f"Unknown parameter {param}")
            schema_item = self.schema_map.get(param, _schema_always_valid)
            value = payload.get(param)
            if value is None:
                # Error if any required parameters are not provided
                if not schema_item.optional:
                    raise MissingParameterValue(f"Missing required value: {param}")
            # Only validate a parameter if it is provided
            elif not schema_item.validate(value):
                raise InvalidParameterValue(
                    f"{param} — {schema_item.error_message} ({value})"
                )


def _schema_always_valid(_):
    return True


def validate_uuid(uuid):
    try:
        UUID(uuid)
    except (ValueError, TypeError):
        return False
    return True


def validate_cidr(cidr):
    try:
        ip_network(cidr)
    except (ValueError, TypeError):
        return False
    return True


def validate_ip(ip):
    try:
        ip_address(ip)
    except ValueError:
        return False
    return True


def validate_public_key(public_key):
    try:
        key_bytes = b64decode(public_key, validate=True)
        if len(key_bytes) != 32:
            return False
    except binascii.Error:
        return False
    return True


VALID_CHANNEL_TYPES = {
    "wireguard": SchemaValidator(
        strict=False,
        # The endpoint on which the spoke port will listen
        endpoint=SchemaItem(
            validate_ip, optional=True, error_message="Invalid IP address."
        ),
        # The public key for the spoke port
        public_key=SchemaItem(
            validate_public_key,
            error_message="Must be a 32-bit value " "encoded in base64 format.",
        ),
    )
}

CREATE_CHANNEL_SCHEMA = SchemaValidator(
    # The name of the channel (optional)
    name=SchemaItem(_schema_always_valid, optional=True),
    # The project ID for the channel
    project_id=SchemaItem(validate_uuid, error_message="Invalid UUID."),
    # The subnet on which the channel will operate (UUID or CIDR) (optional)
    subnet=SchemaItem(
        lambda subnet: validate_uuid(subnet) or validate_cidr(subnet),
        optional=True,
        error_message="Subnet must be either a Neutron subnet UUID, "
        "or a subnet in valid CIDR notation.",
    ),
    # Local address on subnet where the channel will be located (optional)
    channel_address=SchemaItem(
        validate_ip, optional=True, error_message="Invalid IP address."
    ),
    # Channel type, must be a string from the set of VALID_CHANNEL_TYPES
    channel_type=SchemaItem(_schema_always_valid),
    # Channel properties, which must be appropriate according to channel_type
    properties=SchemaItem(
        lambda properties: type(properties) is dict,
        error_message="Properties must be valid JSON.",
    ),
)
