import traceback
from functools import wraps

from flask import Blueprint, request
from keystoneauth1 import session as ks_session
from keystonemiddleware.auth_token import AuthProtocol
from keystonemiddleware.auth_token._request import _AuthTokenRequest
from neutronclient.v2_0 import client as neutron_client
from oslo_log import log
from oslo_policy.policy import PolicyNotAuthorized
from webob import exc as webob_exc
from werkzeug import exceptions as werkzeug_exc

from tunelo.api.utils import make_error_response
from tunelo.common import context as tunelo_context
from tunelo.common import exception, keystone
from tunelo.conf import CONF

LOG = log.getLogger(__name__)

_NEUTRON_CLIENT = None

channel_endpoint_blueprint = Blueprint("channels", __name__)


class AuthTokenFlaskMiddleware(object):
    """Wrap the keystonemiddleware.auth_token middleware for Flask.

    The auth_token middleware is designed to work for a more standard WSGI
    application using middleware components. Flask has some different design
    choices around how middleware are handled. This class just wraps up the
    middleware exposed by auth_token such that Flask can use it.
    """

    def __init__(self):
        self.keystonemiddleware = AuthProtocol(
            None,
            {
                "oslo_config_config": CONF,
            },
        )
        self.public_paths = [""]

    def before_request(self):
        if request.path.rstrip("/") in self.public_paths:
            return

        # When the middleware is invoked, it should mutate request.environ
        # and add 'keystone.auth_token' and 'keystone.auth_plugin' attributes.
        auth_token_request = _AuthTokenRequest(
            request.environ,
            # The request _should_ really only need headers for the middleware
            # to do its job.
            # NOTE: we have to cast to a dict structure because `headers` is
            # wrapped in a Flask/werkzeug data structure, and webob doesn't
            # properly interpret it as headers to be set in this form.
            headers=dict(request.headers),
        )
        try:
            res = self.keystonemiddleware.process_request(auth_token_request)
            if res:
                return res
        except webob_exc.HTTPError as exc:
            return make_error_response(
                "The request you have made requires authentication", exc.status_code
            )


class ContextMiddleware(object):
    def before_request(self):
        request.context = tunelo_context.RequestContext.from_environ(request.environ)

    def after_request(self, res):
        context: "tunelo_context.RequestContext" = getattr(request, "context", None)

        if context:
            request_id = context.request_id
        else:
            # If a prior middleware short-circuited before this middleware, context
            # is not set. This can happen e.g. on unauthenticated requests.
            # Just generate a new request ID in this case.
            request_id = tunelo_context.generate_request_id()

        res.headers["OpenStack-Request-Id"] = request_id
        return res


def get_neutron_client():
    """Returns an authenticated Neutron client.

    The client is created only the first time this function is called.
    """
    global _NEUTRON_CLIENT
    if not _NEUTRON_CLIENT:
        auth = keystone.get_auth("neutron")
        session = ks_session.Session(auth=auth)
        _NEUTRON_CLIENT = neutron_client.Client(session=session, raise_errors=False)
    return _NEUTRON_CLIENT


def route(rule, blueprint: "Blueprint" = None, json_body=None, **options):
    """Decorator which exposes a function as a Flask handler and handles errors.

    This is essentially a combination of Flask's default ``route`` decorator
    and some exception handling for common error cases, such as "not found"
    or "not authorized" errors. It handles translating those errors to
    downstream HTTP response codes gracefully.

    Args:
        rule (str): The routing rule to expose this handler on.
        blueprint (Blueprint): The Flask blueprint to hang the route on.
        json_body (str): When set to the name of a handler argument, the request
            body will be parsed as JSON and passed to the handler as this
            named keyword argument. Defaults to None, meaning request body is
            not parsed automatically and passed to the handler.
        **options: Additional options passed to the Flask ``route`` decorator.

    Returns:
        A decorated handler function, which is registered on the Flask
            blueprint and will translate known exceptions to HTTP status codes.
    """

    def inner_function(function):
        @wraps(function)
        def inner_check_args(*args, **kwargs):
            try:
                if json_body:
                    kwargs[json_body] = request.json
                res = function(*args, **kwargs)
                # Convert None to 200 with empty contents
                return res or ("", 200)
            except exception.Invalid as exc:
                return make_error_response(str(exc), 400)
            except PolicyNotAuthorized as exc:
                return make_error_response(str(exc), 403)
            except exception.NotFound as exc:
                return make_error_response(str(exc), 404)
            except exception.Conflict as exc:
                return make_error_response(str(exc), 409)
            except exception.MalformedChannel as exc:
                return make_error_response(str(exc), 500)
            except werkzeug_exc.HTTPException as exc:
                # Let Flask handle these with default behavior
                raise
            except Exception as exc:
                # FIXME: why won't this log for tests and we have to print()?
                traceback.print_exc()
                LOG.exception(f"Unhandled error on {rule}: {exc}")
                return make_error_response("An unknown error occurred.", 500)

        return blueprint.route(rule, **options)(inner_check_args)

    return inner_function
