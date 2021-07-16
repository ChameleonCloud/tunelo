from oslo_config import cfg

from tunelo.conf import api
from tunelo.conf import default

CONF = cfg.CONF

CONF.register_opts(default.opts)
CONF.register_opts(api.opts, group=api.GROUP)
