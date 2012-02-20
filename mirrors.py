#!/usr/bin/python

"""Copyright 2011 Gentoo Foundation
Distributed under the terms of the GNU General Public License v2
"""

from __future__ import print_function

import re
import sys
import portage

from gentoolkit.query import Query
from gentoolkit.package import Package
from gentoolkit.helpers import get_cpvs
import gentoolkit.pprinter as pp

import helpers
from pytrie import SortedStringTrie as trie

mirrors = trie()
generate_diff = False

def pmsg(package, msg):
    print (pp.cpv(str(package)) + ": " + msg)

def ediff(package, uri, prefix, mirror):
    from difflib import unified_diff

    ebuild = package.ebuild_path()
    before = open(ebuild).read()
    after = before.replace(prefix, mirror)

    n = ebuild.find(package.category)
    if n != -1:
        ebuild = ebuild[n:]

    diff = unified_diff(before.splitlines(1), after.splitlines(1),
                        fromfile='a/' + ebuild, tofile='b/' + ebuild)

    for line in diff:
        sys.stdout.write(line)

def bad_src_uri(package, uri, prefix, mirror):
    mirror = 'mirror://' + mirror
    if prefix.endswith('/'):
        mirror += '/'

    if not generate_diff:
        uri = uri.replace(prefix, mirror)
        pmsg(package, 'SRC_URI should be %s' % uri)
    else:
        ediff(package, uri, prefix, mirror)

def build_mirrors():
    global mirrors

    tmp = {}
    for k, v in portage.settings.thirdpartymirrors().iteritems():
        for mirror in v:
            tmp[mirror] = k
    mirrors = trie(tmp)

def check_uri(package, uri):
    global mirrors

    try:
        item = mirrors.longest_prefix_item(uri)
    except KeyError:
        return

    bad_src_uri(package, uri, item[0], item[1])

def upstream_remote_id_package(package):
    for filename, uris in helpers.get_package_uris(package).iteritems():
        for uri in uris:
            check_uri(package, uri)

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
    # FIXME: use a real argument parser
    if len(sys.argv) == 2 and sys.argv[1] in ['--help', '-h']:
        print ("Usage: ")
        print (" %s [--diff] --all" % sys.argv[0])
        print (" %s [--diff] [pkg [pkg2 [...]]]" % sys.argv[0])
        print (" eix --only-names -C dev-perl | %s" % sys.argv[0])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] in ['--diff', '-d']:
        global generate_diff
        sys.argv.pop(1)
        generate_diff = True

    build_mirrors()

    if len(sys.argv) == 2 and sys.argv[1] in ['--all', '-a']:
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
