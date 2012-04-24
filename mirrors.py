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

_mirrors = trie()
_generate_diff = False
_thirdpartymirrors = []

def pmsg(package, msg):
    print (pp.cpv(str(package)) + ": " + msg)

def generate_diff(package, bad_uris):
    from difflib import unified_diff

    ebuild = package.ebuild_path()
    before = open(ebuild).read()
    after = before

    for old, new in bad_uris:
        after = after.replace(old, new)

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

    if not _generate_diff:
        uri = uri.replace(prefix, mirror)
        pmsg(package, 'SRC_URI should be %s' % uri)

    return (prefix, mirror)

def build_mirrors():
    from portage.util import stack_dictlist, grabdict

    global _mirrors

    tmp = {}
    thirdpartymirrors = {}

    if not _thirdpartymirrors:
        thirdpartymirrors = portage.settings.thirdpartymirrors()
    else:
        thirdparty_lists = [grabdict(x) for x in _thirdpartymirrors]
        thirdpartymirrors = portage.util.stack_dictlist(thirdparty_lists, incremental=True)

    for prefix, mirrors in thirdpartymirrors.iteritems():
        for mirror in mirrors:
            tmp[mirror] = prefix

    _mirrors = trie(tmp)

def check_uri(package, uri):
    global _mirrors

    try:
        item = _mirrors.longest_prefix_item(uri)
    except KeyError:
        return None

    return bad_src_uri(package, uri, item[0], item[1])

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
    bad_uris = []

    for filename, uris in helpers.get_package_uris(package).iteritems():
        for uri in uris:
            ret = check_uri(package, uri)
            if ret and ret not in bad_uris:
                bad_uris.append(ret)

    if _generate_diff and bad_uris:
        generate_diff(package, bad_uris)

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
    global _generate_diff, _thirdpartymirrors

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
    parser.add_argument('-m', '--thirdpartymirrors', action='append',
                        help='use this thirdpartymirrors file')

    args = parser.parse_args()

    _generate_diff = args.diff
    _thirdpartymirrors = args.thirdpartymirrors

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
