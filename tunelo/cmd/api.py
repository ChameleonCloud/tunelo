"""The Tunelo Service API."""

import sys
import threading
import time

from oslo_config import cfg
from oslo_log import log
from oslo_reports import guru_meditation_report as gmr
from oslo_reports import opts as gmr_opts

from tunelo.api.channels import bootstrap_default_hub
from tunelo.common import service as tunelo_service
from tunelo.common import wsgi
from tunelo import version

CONF = cfg.CONF

LOG = log.getLogger(__name__)

# How long to wait between retries when the default subnet isn't reachable yet
# (e.g. neutron not responding, or post_networking hasn't created the subnet
# yet because it runs after kolla service deploys complete).
_BOOTSTRAP_HUB_RETRY_SECONDS = 30


def _bootstrap_default_hub_loop():
    if not CONF.default_subnet:
        return
    while True:
        try:
            bootstrap_default_hub()
            LOG.info(
                "Default wireguard hub is ready on subnet %s",
                CONF.default_subnet,
            )
            return
        except Exception:
            LOG.exception(
                "Failed to bootstrap default hub on subnet %s; retrying in %ss",
                CONF.default_subnet,
                _BOOTSTRAP_HUB_RETRY_SECONDS,
            )
        time.sleep(_BOOTSTRAP_HUB_RETRY_SECONDS)


def main():
    # Parse config file and command line options, then start logging
    tunelo_service.prepare_service(sys.argv)
    gmr_opts.set_defaults(CONF)
    gmr.TextGuruMeditation.setup_autorun(version)

    # Build and start the WSGI app
    launcher = tunelo_service.process_launcher()
    server = wsgi.WSGIService("tunelo_api", CONF.api.enable_ssl_api)
    launcher.launch_service(server, workers=server.workers)

    # Ensure a hub port is created.
    threading.Thread(
        target=_bootstrap_default_hub_loop,
        name="tunelo-bootstrap-default-hub",
        daemon=True,
    ).start()

    launcher.wait()


if __name__ == "__main__":
    sys.exit(main())
