#!/usr/bin/python

"""Copyright 2011 Gentoo Foundation
Distributed under the terms of the GNU General Public License v2
"""

from __future__ import print_function

import re
import sys

from gentoolkit.query import Query
from gentoolkit.package import Package
from gentoolkit.helpers import get_cpvs
import gentoolkit.pprinter as pp

_pypi_package_name_re = re.compile("(http://pypi.python.org/packages/source|mirror://pypi)/\w/([^/]*)/.+")

def pmsg(package, msg):
    print (pp.cpv(str(package)) + ": " + msg)

def bad_src_uri(package, uri):
    pass

# TODO: patch the file
def missing_remote_id(package, package_name, remote):
    msg = 'missing remote id: <upstream><remote-id type="%s">%s</remote-id></upstream>' % (remote, package_name)
    pmsg(package, msg)

def find_remote_id(package, remote):
    for upstream in package.metadata.upstream():
        for remoteid in upstream.upstream_remoteids():
            if remoteid[1] == remote:
                return remoteid
    return None

def pypi_package_name(package, uri):
    match = _pypi_package_name_re.match(uri)
    if not match:
        sys.stderr.write(pp.warn("Can't find pypi package in '%s'" % uri))
        return

    package_name = match.group(2)
    # FIXME check using pypi API
    return package_name

def pypi_src_uri(package, uri):
    package_name = pypi_package_name(package, uri)
    if not package_name:
        return

    uri = uri.replace('http://pypi.python.org/packages/source/', 'mirror://pypi/')
    pmsg(package, 'SRC_URI should be %s' % uri)
    pypi_remote_id(package, uri)


def cpan_remote_id(package, uri):
    package_name = package.name # FIXME, guess package name from URI
    remoteid = find_remote_id(package, 'cpan')
    if not remoteid:
        missing_remote_id(package, package_name, 'cpan')

def pypi_remote_id(package, uri):
    package_name = pypi_package_name(package, uri)
    if not package_name:
        return

    remoteid = find_remote_id(package, 'pypi')
    if not remoteid:
        missing_remote_id(package, package_name, 'pypi')

# TODO: handle these remote-id freshmeat|sourceforge|sourceforge-jp|cpan|vim|google-code|ctan|pypi|rubyforge|cran
# TODO: fix other upstream elements ? maintainer|changelog|doc|bugs-to|remote-id

URI_RULES = (
    (r'http://pypi.python.org/packages/source/.*', pypi_src_uri),
    (r'mirror://pypi/.*', pypi_remote_id),
    (r'mirror://cpan/authors/.*', cpan_remote_id),
# TODO: more rules
#    ('mirror://rubygem/.*', rubygem_remote_id),
)

def uri_rules(package, uri):
    for rule in URI_RULES:
        if re.match(rule[0], uri):
            rule[1](package, uri)

def upstream_remote_id_package(package):
    #for upstream in package.metadata.upstream():
    #    print (upstream)
    #    for remoteid in upstream.upstream_remoteids():
    #        print (remoteid)

    for uri in [package.environment('SRC_URI')]: # FIXME handle multiple URIs
        uri_rules(package, uri)

def upstream_remote_id(query):
    matches = Query(query).find(
        include_masked=True,
        in_installed=False
    )

    if not matches:
        sys.stderr.write(pp.warn("No package matching '%s'" % pp.pkgquery(query)))
        return

    matches = sorted(matches)

    for package in matches:
        upstream_remote_id_package(package)

def main():
    if len(sys.argv) == 2 and sys.argv[1] in ['--help', '-h']:
        print ("Usage: ")
        print (" %s --all" % sys.argv[0])
        print (" %s [pkg [pkg2 [...]]]" % sys.argv[0])
        print (" eix --only-names -C dev-perl | %s" % sys.argv[0])
    elif len(sys.argv) == 2 and sys.argv[1] == ['--all', '-a']:
        for package in get_cpvs():
            upstream_remote_id_package(Package(package))
    elif len(sys.argv) > 1:
        for query in sys.argv[1:]:
            upstream_remote_id(query)
    else:
        for package in sys.stdin.readlines():
            upstream_remote_id(package.replace('\n', ''))

if __name__ == '__main__':
    main()
