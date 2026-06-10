import itertools
import sys

from oslo_config import cfg
from oslo_policy import policy

from tunelo import PROJECT_NAME

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tunelo.common.context import RequestContext

CONF = cfg.CONF
_ENFORCER = None

SYSTEM_ADMIN = "role:admin"
SYSTEM_ADMIN_OR_PROJECT_MEMBER = "role:admin or project_id:%(project_id)s"

channel_rules = [
    policy.DocumentedRuleDefault(
        name="channel:get",
        check_str=SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        description="Retrieve channel details",
        operations=[
            {"path": "/channels", "method": "GET"},
            {"path": "/channels/{channel_uuid}", "method": "GET"},
        ],
    ),
    policy.DocumentedRuleDefault(
        name="channel:create",
        check_str=SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        description="Create a channel",
        operations=[{"path": "/channels", "method": "POST"}],
    ),
    policy.DocumentedRuleDefault(
        name="channel:update",
        check_str=SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        description="Update a channel",
        operations=[
            {"path": "/channels/{channel_uuid}", "method": "PATCH"},
            {"path": "/channels/{channel_uuid}", "method": "PUT"},
        ],
    ),
    policy.DocumentedRuleDefault(
        name="channel:delete",
        check_str=SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        description="Delete a channel",
        operations=[{"path": "/channels/{channel_uuid}", "method": "DELETE"}],
    ),
]


def list_policies():
    return itertools.chain(
        channel_rules,
    )


def get_enforcer():
    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = policy.Enforcer(CONF)
        _ENFORCER.register_defaults(list_policies())
    return _ENFORCER


def get_oslo_policy_enforcer():
    # This method is for use by oslopolicy CLI scripts. Those scripts need the
    # 'output-file' and 'namespace' options, but having those in sys.argv means
    # loading the tunelo config options will fail as those are not expected to
    # be present. So we pass in an arg list with those stripped out.

    conf_args = []
    # Start at 1 because cfg.CONF expects the equivalent of sys.argv[1:]
    i = 1
    while i < len(sys.argv):
        if sys.argv[i].strip("-") in ["namespace", "output-file"]:
            i += 2
            continue
        conf_args.append(sys.argv[i])
        i += 1

    cfg.CONF(conf_args, project=PROJECT_NAME)

    return get_enforcer()


def authorize(rule, context: "RequestContext", target: "dict" = None):
    """Check if the request is authorized according to a given rule.

    Args:
        rule (str): The policy rule.
        context (RequestContext): The request context.
        target (dict): The target domain object, if any.

    Raises:
        PolicyNotAuthorized: If the rule is not satisfied.
    """
    return get_enforcer().authorize(
        rule, target or {}, context.to_policy_values(), do_raise=True
    )
