from flask import make_response
from oslo_log import log


LOG = log.getLogger(__name__)


def make_error_response(message=None, status_code=None):
    return make_response(
        {
            "error": message,
        },
        status_code,
    )
