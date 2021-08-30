from oslo_config import cfg

from tunelo.common import auth
from tunelo.conf import api
from tunelo.conf import default
from tunelo.conf import neutron

CONF = cfg.CONF

CONF.register_opts(default.opts)
CONF.register_opts(api.opts, group=api.GROUP)
auth.register_auth_opts(CONF, neutron.GROUP)
