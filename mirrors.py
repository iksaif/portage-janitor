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
count_prefixes = False

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

def add_package_prefix(package, count):
    for filename, uris in helpers.get_package_uris(package).iteritems():
        for uri in uris:
            if not uri or '://' not in uri:
                continue
            if uri in count:
                count[uri].update([package])
            else:
                count[uri] = set([package])

def end_prefix_count(count):
    import operator

    result = {}

    def split(uri):
        parts = uri.split('/')

        scheme, blank = parts.pop(0), parts.pop(0)
        parts[0] = '%s//%s' % (scheme, parts[0])

        parts.pop() # Skip file

        prefix = parts.pop(0)
        yield prefix

        while parts:
            prefix += '/' + parts.pop(0)
            yield prefix

    for uri in count.keys():
        for part in split(uri):
            if part in result:
                result[part].update(count[uri])
            else:
                result[part] = set(count[uri])

    sorted_uris = sorted(result.iteritems(), key=lambda x: len(x[1]), reverse=True)

    i, limit = 0, 50
    for uri, count in sorted_uris:
        if uri.startswith('mirror://'):
            continue
        print ('%s\t%s' % (len(count), uri))
        i += 1
        if i >= limit:
            break

def check_package(package):
    for filename, uris in helpers.get_package_uris(package).iteritems():
        for uri in uris:
            check_uri(package, uri)

def check_query(query, action):
    matches = Query(query).find(
        include_masked=True,
        in_installed=False
    )

    if not matches:
        sys.stderr.write(pp.warn("No package matching '%s'" % pp.pkgquery(query)))
        return

    matches = sorted(matches)

    for package in matches:
        action(package)

def main():
    import argparse
    global generate_diff

    count = {}

    parser = argparse.ArgumentParser(description='Cleanups SRC_URI using mirrors://')
    parser.add_argument('packages', metavar='N', type=str, nargs='*',
                        help='packages to check')
    parser.add_argument('-a', '--all', action='store_true',
                        help='check all packages')
    parser.add_argument('-d', '--diff', action='store_true',
                        help='generate ebuild diff (default: print package name and message)')
    parser.add_argument('-c', '--count', action='store_true',
                        help='generate a list of widely used URI prefix that should use a mirror:// instead')

    args = parser.parse_args()

    generate_diff = args.diff

    if not args.count:
        build_mirrors()
        action = check_package
    else:
        action = lambda x: add_package_prefix(x, count)

    if args.all:
        for package in get_cpvs():
            action(Package(package))
    elif args.packages:
        for query in args.packages:
            check_query(query, action)
    else:
        for package in sys.stdin.readlines():
            check_query(package.replace('\n', ''), action)

    if args.count:
        end_prefix_count(count)


if __name__ == '__main__':
    main()
