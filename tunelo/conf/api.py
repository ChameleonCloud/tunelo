from oslo_config import cfg

GROUP = "api"

opts = [
    cfg.HostAddressOpt(
        "host_ip",
        default="0.0.0.0",
        help=("The IP address or hostname on which doni-api " "listens."),
    ),
    cfg.PortOpt("port", default=8001, help=("The TCP port on which doni-api listens.")),
    cfg.IntOpt(
        "max_limit",
        default=1000,
        mutable=True,
        help=(
            "The maximum number of items returned in a single "
            "response from a collection resource."
        ),
    ),
    cfg.StrOpt(
        "public_endpoint",
        mutable=True,
        help=(
            "Public URL to use when building the links to the API "
            'resources (for example, "https://doni.rocks:8001").'
            " If None the links will be built using the request's "
            "host URL. If the API is operating behind a proxy, you "
            "will want to change this to represent the proxy's URL. "
            "Defaults to None. "
            "Ignored when proxy headers parsing is enabled via "
            "[oslo_middleware]enable_proxy_headers_parsing option."
        ),
    ),
    cfg.IntOpt(
        "api_workers",
        help=(
            "Number of workers for OpenStack doni API service. "
            "The default is equal to the number of CPUs available, "
            "but not more than 4. One worker is used if the CPU "
            "number cannot be detected."
        ),
    ),
    cfg.BoolOpt(
        "enable_ssl_api",
        default=False,
        help=(
            "Enable the integrated stand-alone API to service "
            "requests via HTTPS instead of HTTP. If there is a "
            "front-end service performing HTTPS offloading from "
            "the service, this option should be False; note, you "
            "will want to enable proxy headers parsing with "
            "[oslo_middleware]enable_proxy_headers_parsing "
            "option or configure [api]public_endpoint option "
            "to set URLs in responses to the SSL terminated one."
        ),
    ),
]
