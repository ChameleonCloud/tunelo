from flask import Blueprint

bp = Blueprint("root", __name__)


@bp.route("/")
def info():
    return {
        "name": "OpenStack Tunelo API",
        "description": (
            "Tunelo is an OpenStack project for provisioning encrypted "
            "communications tunnels on-demand."
        ),
        "default_version": "1.0",
        "versions": ["1.0"],
    }
