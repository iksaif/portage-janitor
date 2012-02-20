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

import helpers

generate_diff = False
patched_metadata = {}

_pypi_package_name_re = re.compile("mirror://pypi/\w/([^/]*)/.+")
_rubygems_package_name_re = re.compile("mirror://rubygems/(.*)\.gem")
_rubyforge_package_name_re = re.compile("mirror://rubyforge/([^/]*)/.*")
_googlecode_package_name_re = re.compile("http://(.*)\.googlecode.com/.*")
_php_package_name_re = re.compile("http://(.*).php.net/get/(.*)-(.*).tgz")

def pmsg(package, msg):
    print (pp.cpv(str(package)) + ": " + msg)


def mdiff(package, package_name, remote):
    global patched_metadata
    from difflib import unified_diff
    from xml.dom.minidom import parse, parseString, Document

    metadata = package.package_path() + '/metadata.xml'

    if metadata in patched_metadata:
        return
    patched_metadata[metadata] = True

    before = open(metadata).read()
    after = parse(metadata)

    remoteid = after.createElement('remote-id')
    remoteid.setAttribute('type', remote)
    remoteid.appendChild(after.createTextNode(package_name))
    #doc = parseString(doc.toprettyxml())



    upstream = after.getElementsByTagName('upstream')
    if not upstream:
        upstream = after.createElement('upstream')
        after.getElementsByTagName('pkgmetadata')[0].appendChild(upstream)
    else:
        upstream = upstream[0]

    upstream.appendChild(remoteid)
    after = after.toxml(encoding='UTF-8')

    # Fix indent style
    if '\n  <' in before:
        indent = 2
    elif '\n    <' in before:
        indent = 4
    else:
        indent = 8
    indent = indent * ' '

    after = after.replace('<upstream><remote-id', '%s<upstream>\n%s<remote-id' % (indent, indent * 2))
    after = after.replace('</remote-id></upstream></', '</remote-id>\n%s</upstream>\n</' % indent)

    if not after.endswith('\n') and before.endswith('\n'):
        after += '\n'

    after = after.replace('?><!DOCTYPE', '?>\n<!DOCTYPE')
    after = after.replace('\'><pkgmetadata>', '\'>\n<pkgmetadata>')
    after = after.replace("  SYSTEM 'http://www.gentoo.org/dtd/metadata.dtd'",
                          ' SYSTEM "http://www.gentoo.org/dtd/metadata.dtd"')

    n = metadata.find(package.category)
    if n != -1:
        metadata = metadata[n:]

    diff = unified_diff(before.splitlines(1), after.splitlines(1),
                        fromfile='a/' + metadata, tofile='b/' + metadata)

    for line in diff:
        sys.stdout.write(line)

def missing_remote_id(package, package_name, remote):
    if not generate_diff:
        msg = 'missing remote id: <upstream><remote-id type="%s">%s</remote-id></upstream>' % (remote, package_name)
        pmsg(package, msg)
    else:
        mdiff(package, package_name, remote)

def find_remote_id(package, remote):
    for upstream in package.metadata.upstream():
        for remoteid in upstream.upstream_remoteids():
            if remoteid[1] == remote:
                return remoteid
    return None

## Rubygems
def rubygems_package_name(package, uri):
    match = _rubygems_package_name_re.match(uri)
    if not match:
        sys.stderr.write(pp.warn("Can't find rubygems package in '%s'" % uri))
        return

    package_name = match.group(1)
    # FIXME check using rubygems API
    return package_name

## Rubyforge
def rubyforge_package_name(package, uri):
    match = _rubyforge_package_name_re.match(uri)
    if not match:
        sys.stderr.write(pp.warn("Can't find rubyforge package in '%s'" % uri))
        return

    package_name = match.group(1)
    # FIXME check using rubyforge API
    return package_name

## Google code
def google_package_name(package, uri):
    match = _googlecode_package_name_re.search(uri)

    if match:
        return match.group(1)
    else:
        return None

## CPAN
def cpan_package_name(package, uri):
    return package.name # FIXME: guess package name from URI

## PHP: Pear/Pecl
def php_package_name(package, uri):
    match = _php_package_name_re.search(uri)

    if match:
        channel = match.group(1)
        pkg = match.group(2)
    else:
        cat, pkg = package.split("/")

    return pkg, channel

def php_remote_id(package, uri):
    package_name, channel = php_package_name(package, uri)
    if not package_name:
        return

    remoteid = find_remote_id(package, channel)
    if not remoteid:
        missing_remote_id(package, package_name, channel)

## Pypi
def pypi_package_name(package, uri):
    match = _pypi_package_name_re.match(uri)
    if not match:
        sys.stderr.write(pp.warn("Can't find pypi package in '%s'" % uri))
        return

    package_name = match.group(1)
    # FIXME check using pypi API
    return package_name

def remote_id(package, uri, rule):
    regexp, remote, pname = rule

    package_name = pname(package, uri)
    if not package_name:
        return

    remoteid = find_remote_id(package, remote)
    if not remoteid:
        missing_remote_id(package, package_name, remote)

URI_RULES = (
    # pypi
    (r'mirror://pypi/.*', 'pypi', pypi_package_name),
    # cpan
    (r'mirror://cpan/authors/.*', 'cpan', cpan_package_name),
    # google-code
    (r'http://.*\.googlecode.com/.*', 'google-code', google_package_name),
    # rubyforge
    (r'mirror://rubyforge/.*', 'rubyforge', rubyforge_package_name),
    # rubygems
    (r'mirror://rubygems/.*.gem', 'rubygems', rubygems_package_name),
    # pear / pecl
    (r'http://(pecl|pear).php.net/get/.*-.*.tgz', php_remote_id, None),
    # FIXME
    # ctan (using HOMEPAGE ?)
    # cran
    # sourceforge
    # sourceforge-jp
    # vim
)

def uri_rules(package, uri):
    for rule in URI_RULES:
        if re.match(rule[0], uri):
            if type(rule[1]) == callable:
                rule[1](package, uri, rule)
            else:
                remote_id(package, uri, rule)

def upstream_remote_id_package(package):
    for filename, uris in helpers.get_package_uris(package).iteritems():
        for uri in uris:
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
        print (" %s [--diff] --all" % sys.argv[0])
        print (" %s [--diff] [pkg [pkg2 [...]]]" % sys.argv[0])
        print (" eix --only-names -C dev-perl | %s" % sys.argv[0])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] in ['--diff', '-d']:
        global generate_diff
        sys.argv.pop(1)
        generate_diff = True

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
