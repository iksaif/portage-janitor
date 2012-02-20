import portage

from portage.dbapi import porttree
from gentoolkit.eclean.search import (port_settings)


def get_package_uris(package):
    cpv = package.cpv
    metadata = {
        "EAPI"    : port_settings["EAPI"],
        "SRC_URI" : package.environment("SRC_URI", False),
    }
    use = frozenset(port_settings["PORTAGE_USE"].split())

    alist = porttree._parse_uri_map(cpv, metadata, use=use)
    aalist = porttree._parse_uri_map(cpv, metadata)

    if "mirror" in portage.settings.features:
        uris = aalist
    else:
        uris = alist

    return uris
