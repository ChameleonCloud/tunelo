"""The Doni Service API."""

import sys

from oslo_config import cfg
from oslo_log import log
from oslo_reports import guru_meditation_report as gmr
from oslo_reports import opts as gmr_opts

from tunelo.common import service as tunelo_service
from tunelo.common import wsgi
from tunelo import version

CONF = cfg.CONF

LOG = log.getLogger(__name__)


def main():
    # Parse config file and command line options, then start logging
    tunelo_service.prepare_service(sys.argv)
    gmr_opts.set_defaults(CONF)
    gmr.TextGuruMeditation.setup_autorun(version)

    # Build and start the WSGI app
    launcher = tunelo_service.process_launcher()
    server = wsgi.WSGIService("tunelo_api", CONF.api.enable_ssl_api)
    launcher.launch_service(server, workers=server.workers)
    launcher.wait()


if __name__ == "__main__":
    sys.exit(main())
