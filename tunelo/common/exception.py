import collections
from http import client as http_client
import json

from oslo_log import log

from tunelo.conf import CONF

LOG = log.getLogger(__name__)


def _ensure_exception_kwargs_serializable(exc_class_name, kwargs):
    """Ensure that kwargs are serializable

    Ensure that all kwargs passed to exception constructor can be passed over
    RPC, by trying to convert them to JSON, or, as a last resort, to string.
    If it is not possible, unserializable kwargs will be removed, letting the
    receiver to handle the exception string as it is configured to.

    Args:
        exc_class_name (str): a TuneloException class name.
        kwargs (dict): Keyword arguments passed to the exception constructor.

    Returns:
        A dictionary of serializable keyword arguments.
    """
    serializers = [
        (json.dumps, ("when converting to JSON")),
        (str, ("when converting to string")),
    ]
    exceptions = collections.defaultdict(list)
    serializable_kwargs = {}
    for k, v in kwargs.items():
        for serializer, msg in serializers:
            try:
                serializable_kwargs[k] = serializer(v)
                exceptions.pop(k, None)
                break
            except Exception as e:
                exceptions[k].append(
                    "(%(serializer_type)s) %(e_type)s: %(e_contents)s"
                    % {
                        "serializer_type": msg,
                        "e_contents": e,
                        "e_type": e.__class__.__name__,
                    }
                )
    if exceptions:
        LOG.error(
            "One or more arguments passed to the %(exc_class)s "
            "constructor as kwargs can not be serialized. The "
            "serialized arguments: %(serialized)s. These "
            "unserialized kwargs were dropped because of the "
            "exceptions encountered during their "
            "serialization:\n%(errors)s",
            dict(
                errors=";\n".join(
                    "%s: %s" % (k, "; ".join(v)) for k, v in exceptions.items()
                ),
                exc_class=exc_class_name,
                serialized=serializable_kwargs,
            ),
        )
        # We might be able to actually put the following keys' values into
        # format string, but there is no guarantee, drop it just in case.
        for k in exceptions:
            del kwargs[k]
    return serializable_kwargs


class TuneloException(Exception):
    """Base Tunelo Exception

    To correctly use this class, inherit from it and define a '_msg_fmt'
    property. That message will get printf'd with the keyword arguments provided
    to the constructor.
    """

    _msg_fmt = "An unknown exception occurred."
    code = http_client.INTERNAL_SERVER_ERROR
    safe = False

    def __init__(self, message=None, **kwargs):

        self.kwargs = _ensure_exception_kwargs_serializable(
            self.__class__.__name__, kwargs
        )

        if "code" not in self.kwargs:
            try:
                self.kwargs["code"] = self.code
            except AttributeError:
                pass
        else:
            self.code = int(kwargs["code"])

        if not message:
            try:
                message = self._msg_fmt % kwargs

            except Exception as e:
                # kwargs doesn't match a variable in self._msg_fmt
                # log the issue and the kwargs
                prs = ", ".join("%s: %s" % pair for pair in kwargs.items())
                LOG.exception(
                    "Exception in string format operation " "(arguments %s)", prs
                )
                if CONF.fatal_exception_format_errors:
                    raise e
                else:
                    # at least get the core self._msg_fmt out if something
                    # happened
                    message = self._msg_fmt

        super(TuneloException, self).__init__(message)

    def __str__(self):
        return str(self.args[0])


class Invalid(TuneloException):
    _msg_fmt = "Unacceptable parameters."
    code = http_client.BAD_REQUEST


class NotFound(TuneloException):
    _msg_fmt = "Resource could not be found."
    code = http_client.NOT_FOUND


class CatalogNotFound(TuneloException):
    _msg_fmt = (
        "Service type %(service_type)s with endpoint type "
        "%(endpoint_type)s not found in keystone service catalog."
    )


class KeystoneUnauthorized(TuneloException):
    _msg_fmt = "Not authorized in Keystone."


class KeystoneFailure(TuneloException):
    """Unhandled Keystone failure wrapper."""
    pass


class Conflict(TuneloException):
    _msg_fmt = "Conflict."
    code = http_client.CONFLICT


class ConfigInvalid(TuneloException):
    _msg_fmt = "Invalid configuration."


class TemporaryFailure(TuneloException):
    _msg_fmt = "Resource temporarily unavailable, please retry."
    code = http_client.SERVICE_UNAVAILABLE


class InvalidParameterValue(Invalid):
    _msg_fmt = "%(msg)s"


class MissingParameterValue(Invalid):
    _msg_fmt = "Missing %(msg)s"


class MalformedChannel(TuneloException):
    _msg_fmt = "Malformed channel (%(msg)s)"
    code = http_client.NOT_ACCEPTABLE
