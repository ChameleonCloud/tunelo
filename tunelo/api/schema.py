import inspect
import re
from functools import partial
from functools import wraps
from typing import Optional

import jsonschema
from oslo_utils import uuidutils

from tunelo.common.exception import Invalid
from tunelo.common.exception import InvalidParameterValue
from tunelo.common.exception import MissingParameterValue

spoke_device_owner_pattern = re.compile(r"channel:(?P<channel_type>.*):spoke")
hub_device_owner_pattern = re.compile(r"channel:(?P<channel_type>.*):hub")
device_owner_pattern = re.compile(r"channel:(?P<channel_type>.*):(spoke|hub)")
valid_hub_peer_pattern = re.compile(
    r"(?P<public_key>.+)\|(?P<endpoint>.*)\|(?P<allowed_ips>.+)"
)

# Some JSON schema helpers
STRING = {"type": "string"}
IP_ADDRESS = {
    "anyOf": [
        {"type": "string", "format": "ipv4"},
        {"type": "string", "format": "ipv6"},
    ]
}
PUBLIC_KEY = {
    "type": "string",
    "contentEncoding": "base64",
}
UUID = {
    "type": "string",
    # TODO until version >= 4 of jsonschema is released, uuid format does NO validation
    "format": "uuid",
}
# Presently, JSON-Schema does not validate CIDR types, so this has to be validated
# manually. A subnet should be validated as CIDR | UUID.
SUBNET = STRING


def uuid(name, value) -> "Optional[str]":
    """Validate that the value is a UUID

    Args:
        name (str): Name of the argument
        value (any): A UUID string value

    Returns:
        The value, or None if value is None

    Raises:
        InvalidParameterValue: if the value is not a valid UUID
    """
    if value is None:
        return
    if not uuidutils.is_uuid_like(value):
        raise InvalidParameterValue(f"Expected UUID for {name}: {value}")
    return value


def _validate_schema(name, value, schema_dict):
    if not value:
        title = schema_dict.get("title")
        if title in ("CreateChannel", "UpdateChannel"):
            raise Invalid(f"No channel information provided for {title}.")
        else:
            return
    try:
        jsonschema.validate(
            value,
            schema_dict,
            # TODO jsonschema version >= 4: Use a newer draft version
            cls=jsonschema.Draft7Validator,
            format_checker=jsonschema.draft7_format_checker,
        )
    except jsonschema.exceptions.ValidationError as e:
        # The error message includes the whole schema which can be very
        # large and unhelpful, so truncate it to be brief and useful
        details = str(e).split("\n")[:3]
        error_msg = f"SchemaObject error for {name}: {details[0]}"
        schema_loc = re.sub("^(.*in schema)", "", details[-1])
        # SUPER hacky bracket-to-dot-notation thing
        schema_loc = schema_loc.replace("']", "").replace("['", ".")
        error_msg += f" (in '{schema_loc[:-1]}')"  # Strip trailing ':'
        raise InvalidParameterValue(error_msg)
    return value


def schema(schema_dict):
    """Return a validator function which validates the value with jsonschema

    Args:
        schema_dict (dict): JSON schema to validate with.

    Returns:
        A validator function, which takes name and value arguments.

    Raises:
        jsonschema.SchemaError: if the schema is not valid.
    """
    jsonschema.Draft7Validator.check_schema(schema_dict)

    return partial(_validate_schema, schema_dict=schema_dict)


def _inspect(function):
    sig = inspect.signature(function)
    params = []

    for param in sig.parameters.values():
        if param.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD:
            params.append(param)
        else:
            raise Invalid(f"Unsupported parameter kind {param.name} {param.kind}")
    return params


def validate(*args, **kwargs):
    """Decorator which validates and transforms function arguments"""
    if args:
        raise ValueError("Validators must be specifed by argument name")
    if not kwargs:
        raise ValueError("No validators specified")
    validators = kwargs

    def inner_function(function):
        params = _inspect(function)

        @wraps(function)
        def inner_check_args(*args, **kwargs):
            args = list(args)
            kwargs_next = {}

            # ensure each named argument belongs to a param
            kwarg_keys = set(kwargs)
            param_names = set(p.name for p in params)
            extra_args = kwarg_keys - param_names
            if extra_args:
                raise InvalidParameterValue(
                    "Unexpected arguments: %s" % ", ".join(extra_args)
                )

            args_len = len(args)

            for i, param in enumerate(params):
                val_function = validators.get(param.name)
                if not val_function:
                    continue

                if i < args_len:
                    # validate positional argument
                    args[i] = val_function(param.name, args[i])
                elif param.name in kwargs:
                    # validate keyword argument
                    kwargs_next[param.name] = val_function(
                        param.name, kwargs.pop(param.name)
                    )
                elif param.default == inspect.Parameter.empty:
                    # no argument was provided, and there is no default
                    # in the parameter, so this is a mandatory argument
                    raise MissingParameterValue(
                        f"Missing mandatory parameter: {param.name}"
                    )

            return function(*args, **kwargs_next)

        return inner_check_args

    return inner_function


VALID_CHANNEL_TYPES = {"wireguard"}


CREATE_CHANNEL_SCHEMA = schema(
    {
        "title": "CreateChannel",
        "type": "object",
        "properties": {
            # The name of the channel (optional)
            "name": STRING,
            # The project ID for the channel
            "project_id": UUID,
            # The subnet on which the channel will operate (UUID or CIDR) (optional)
            "subnet": SUBNET,
            # Local address on subnet where the channel will be located (optional)
            "channel_address": IP_ADDRESS,
            # Channel type, must be a string from the set of VALID_CHANNEL_TYPES
            "channel_type": STRING,
            # Channel properties, which must be appropriate according to channel_type
            "properties": {
                "type": "object",
                "properties": {
                    # The endpoint on which the spoke port will listen (optional)
                    "endpoint": IP_ADDRESS,
                    # The public key for the spoke port
                    "public_key": PUBLIC_KEY,
                },
                "required": ["public_key"],
            },
        },
        "required": ["project_id", "channel_type", "properties"],
        "additionalProperties": False,
    }
)

UPDATE_CHANNEL_SCHEMA = schema(
    {
        "type": "object",
        "title": "UpdateChannel",
        "properties": {
            "name": STRING,
            "properties": {
                "type": "object",
                "properties": {"endpoint": IP_ADDRESS, "public_key": PUBLIC_KEY},
            },
        },
        "additionalProperties": False,
    }
)
