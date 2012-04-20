#!/usr/bin/python

"""Copyright 2011 Gentoo Foundation
Distributed under the terms of the GNU General Public License v2
"""

from __future__ import print_function

import re
import sys
import os

import portage

from gentoolkit.query import Query
from gentoolkit.package import Package
from gentoolkit.helpers import get_cpvs
import gentoolkit.pprinter as pp

from difflib import unified_diff
from xml.dom.minidom import parse, parseString, Document

import copy
import helpers
import urllib2
import json

_generate_diff = False
_patched_metadata = {}
_accepted_types = []
_only_latest = False

_pypi_package_name_re = [
    re.compile("mirror://pypi/\w/([^/]*)/.+"),
    re.compile("http://pypi\.python\.org/pypi/([^/]*).*")
]

_rubygems_package_name_re = [
    re.compile("mirror://rubygems/(.*)\.gem"),
    re.compile("http://rubygems\.org/gems/([^/]*).*")
]

_rubyforge_package_name_re = [
    re.compile("mirror://rubyforge/([^/]*)/.*"),
    re.compile('http://rubyforge\.org/projects/([^/]*).*')
]

_googlecode_package_name_re = [
    re.compile("http://(.*)\.googlecode.com/.*"),
    re.compile("http://code\.google\.com/p/([^/]*).*")
]

_php_package_name_re = [
    re.compile("http://(.*).php.net/get/(.*)-(.*).tgz"),
    re.compile("http://(.*).php.net/package/([^/]*).*"),
    re.compile("http://(.*).php.net/([^/]*)"),
]

_cpan_package_name_re = [
    re.compile("mirror://cpan/authors/.*/([^/.]*).*"),
]

_ctan_package_name_re = [
    re.compile("http://www.ctan.org/pkg/([^/]*).*"),
    re.compile("http://www.ctan.org/tex-archive/macros/latex/contrib/([^/]*).*")
]

_cran_package_name_re = [
    re.compile("http://cran\.r-project\.org/web/packages/([^/]*).*"),
    re.compile("http://(.*)\.r-project\.org/.*"),
]

_sourceforge_package_name_re = [
    (re.compile("https?://(.*)\.(sf|sourceforge)\.net"), 1),
    (re.compile("https?://(.*\.)?(sf|sourceforge)\.net/projects/([^/]*).*"), 3),
]

_bitbucket_package_name_re = [
    (re.compile(r'https?://(www\.)?bitbucket.org/[^/]*/([^/]*).*'), 2),
]

_gitorious_package_name_re = [
    (re.compile(r'https?://(www\.)?gitorious.org/([^/]*).*'), 2),
]

_github_package_name_re = [
    (re.compile(r'https?://github.com/(downloads/)?[^/]*/([^/]*).*'), 2),
]

def download_data(url):
    try:
        return urllib2.urlopen(url).read()
    except Exception as err:
        print (err)
        return False

def re_find_package_name(package, regexps, uri):
    if not isinstance(regexps, (list, tuple)):
        regexps = ( (regexps, 1), )

    match = None
    group = -1

    for regexp in regexps:
        if isinstance(regexp, (list, tuple)):
            regexp, group = regexp
        else:
            group = 1
        match = regexp.match(uri)
        if match:
            break

    if not match:
        sys.stderr.write(pp.warn("Can't find package name in '%s'" % uri))
        return None

    package_name = match.group(group)

    # Try to strip version, if present
    if '-%s' % package.version in package_name:
        package_name.replace('-%s' % package.version, '')
    cpv = 'fake/' + package_name
    cpv = portage.pkgsplit(cpv)
    if cpv:
        package_name = cpv[0].replace('fake/', '', 1)
    return package_name

def pmsg(package, msg):
    print (pp.cpv(str(package)) + ": " + msg)

def guess_indent_values(before):
    rindent = -1
    indent = -1
    tab = False

    def guess_for_tags(tags):
        for tag in tags:
            for i in [0, 2, 4, 6, 8, 12, 16]:
                if '\n%s<%s' % (' ' * i, tag) in before:
                    return i, False
            for i in [0, 1, 2]:
                if '\n%s<%s' % ('\t' * i, tag) in before:
                    return i, True
        return -1, False

    rindent, tab = guess_for_tags(['herd', 'maintainer', 'longdescription', 'use', 'upstream'])
    if rindent == -1:
        rindent = 2
    rindent_str = ('\t' if tab else ' ') * rindent
    indent, tab = guess_for_tags(['remote-id', 'name', 'email'])
    if indent == -1:
        indent = rindent * 2 if rindent else 4
    indent_str = ('\t' if tab else ' ') * indent
    return rindent_str, indent_str

def is_locked(key, val):
    return key in _patched_metadata and val in _patched_metadata[key]

def lock(key, val):
    global _patched_metadata

    if key not in  _patched_metadata:
        _patched_metadata[key] = []
    _patched_metadata[key].append(val)


def mdiff(package, package_name, remote):
    metadata = package.package_path() + '/metadata.xml'

    if is_locked(metadata, remote):
        return
    lock(metadata, remote)

    before = open(metadata).read()
    before = before.decode('utf8')
    after = copy.deepcopy(before)

    # Find root-indent and child-indent values
    rindent, indent = guess_indent_values(before)

    remote_tag = '%s<remote-id type="%s">%s</remote-id>' % (indent, remote, package_name)

    if '<upstream>' in after:
        after = after.replace('<upstream>', '<upstream>\n%s' % remote_tag, 1)
    else:
        rep = '%s<upstream>\n%s\n%s</upstream>\n</pkgmetadata>' % (rindent, remote_tag, rindent)
        after = after.replace('</pkgmetadata>', rep, 1)

    # Generate clean a/category/package/metadata.xml path
    n = metadata.find(package.category)
    if n != -1:
        metadata = metadata[n:]

    diff = unified_diff(before.splitlines(1), after.splitlines(1),
                        fromfile='a/' + metadata, tofile='b/' + metadata)

    for line in diff:
        sys.stdout.write(line.encode('utf8'))

def missing_remote_id(package, package_name, remote):
    # Ignore types not defined in dtd
    if _accepted_types and remote not in _accepted_types:
        return

    if not _generate_diff:
        if is_locked(package.cp, remote):
            return
        lock(package.cp, remote)
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
    # FIXME check using rubygems API
    return re_find_package_name(package, _rubygems_package_name_re, uri)

## Rubyforge
def rubyforge_package_name(package, uri):
    # FIXME check using rubyforge API
    return re_find_package_name(package, _rubyforge_package_name_re, uri)

## Google code
def google_package_name(package, uri):
    return re_find_package_name(package, _googlecode_package_name_re, uri)

## CPAN
def cpan_package_name(package, uri):
    package_name = re_find_package_name(package, _cpan_package_name_re, uri)
    if not package_name:
        package_name = package.name
    cpan_module = None

    tries = [ package_name ]
    if '-' in package_name:
        tries.append(package_name.replace('-', '::'))

    for module in tries:
        data = download_data('http://search.cpan.org/api/module/%s' % module)
        try:
            data = json.loads(data)
        except:
            continue
        if 'distvname' in data and data['distvname'].startswith(package_name):
            cpan_module = module
            break

    return package_name, cpan_module

def cpan_remote_id(package, uri, rulte):
    package_name, cpan_module = cpan_package_name(package, uri)
    if not package_name:
        return

    if not find_remote_id(package, 'cpan'):
        missing_remote_id(package, package_name, 'cpan')

    # CPAN module is optional
    if cpan_module and not find_remote_id(package, 'cpan-module'):
        missing_remote_id(package, cpan_module, 'cpan-module')

## PHP: Pear/Pecl
def php_package_name(package, uri):
    match = None
    for regexp in _php_package_name_re:
        match = regexp.search(uri)
        if match:
            break

    if not match:
        sys.stderr.write(pp.warn("Can't find package name in '%s'" % uri))
        return None, None

    channel = match.group(1)
    pkg = match.group(2)
    return pkg, channel

def php_remote_id(package, uri, rule):
    package_name, channel = php_package_name(package, uri)
    if not package_name:
        return

    remoteid = find_remote_id(package, channel)
    if not remoteid:
        missing_remote_id(package, package_name, channel)

## Pypi
def pypi_package_name(package, uri):
    # FIXME check using pypi API
    return re_find_package_name(package, _pypi_package_name_re, uri)

## CTAN
def ctan_package_name(package, uri):
    return re_find_package_name(package, _ctan_package_name_re, uri)

## CRAN
def cran_package_name(package, uri):
    return re_find_package_name(package, _cran_package_name_re, uri)

## Sourceforge
def sourceforge_package_name(package, uri):
    return re_find_package_name(package, _sourceforge_package_name_re, uri)

## Github
def github_package_name(package, uri):
    return re_find_package_name(package, _github_package_name_re, uri)

## Gitorious
def gitorious_package_name(package, uri):
    return re_find_package_name(package, _gitorious_package_name_re, uri)

## Bitbucket
def bitbucket_package_name(package, uri):
    return re_find_package_name(package, _bitbucket_package_name_re, uri)

def remote_id(package, uri, rule):
    regexp, remote, pname = rule

    if not pname:
        package_name = None
    else:
        package_name = pname(package, uri)
    if not package_name:
        return

    remoteid = find_remote_id(package, remote)
    if not remoteid:
        missing_remote_id(package, package_name, remote)

URI_RULES = (
    # pypi
    (r'mirror://pypi/.*', 'pypi', pypi_package_name),
    (r'http://pypi\.python\.org/pypi/.*', 'pypi', pypi_package_name),
    # cpan
    #(r'mirror://cpan/authors/.*', 'cpan', cpan_package_name),
    (r'mirror://cpan/authors/.*',  cpan_remote_id, ''),
    # google-code
    (r'http://.*\.googlecode\.com/.*', 'google-code', google_package_name),
    (r'http://code\.google\.com/p/.*', 'google-code', google_package_name),
    # rubyforge
    (r'mirror://rubyforge/.*', 'rubyforge', rubyforge_package_name),
    (r'http://rubyforge\.org/projects/.*', 'rubyforge', rubyforge_package_name),
    # rubygems
    (r'mirror://rubygems/.*.gem', 'rubygems', rubygems_package_name),
    (r'http://rubygems\.org/gems/.*', 'rubygems', rubygems_package_name),
    # pear / pecl
    (r'http://(pecl|pear)\.php\.net/get/.*\-.*\.tgz', php_remote_id, None),
    (r'http://(pecl|pear)\.php\.net/.*', php_remote_id, None),
    # ctan
    (r'http://www.ctan.org/pkg/.*', 'ctan', ctan_package_name),
    (r'http://www.ctan.org/tex-archive/macros/latex/contrib/.*', 'ctan', ctan_package_name),
    # cran
    (r'http://(?!www)(.*)\.r-project\.org/.*', 'cran', cran_package_name),
    # sourceforge
    (r'.*\.(sf|sourceforge)\.net', 'sourceforge', sourceforge_package_name),
    (r'.*(sf|sourceforge)\.net/projects/.*', 'sourceforge', sourceforge_package_name),
    # bitbucket
    (r'https?://(www\.)?bitbucket.org/.*/.*', 'bitbucket', bitbucket_package_name),
    # gitorious
    (r'https?://(www\.)?gitorious.org/.*', 'gitorious', gitorious_package_name),
    # github
    (r'https?://github.com/(downloads/)?.*/.*', 'github', github_package_name),
    # FIXME
    # sourceforge-jp
    # vim
)

def uri_rules(package, uri):
    for rule in URI_RULES:
        if re.match(rule[0], uri):
            if hasattr(rule[1], '__call__'):
                rule[1](package, uri, rule)
            else:
                remote_id(package, uri, rule)

def upstream_remote_id_package(package):
    if not package.ebuild_path():
        return

    for filename, uris in helpers.get_package_uris(package).iteritems():
        for uri in uris:
            uri_rules(package, uri)
    for homepage in package.environment('HOMEPAGE').split():
        uri_rules(package, homepage)

def upstream_remote_id(query):
    matches = Query(query).find(
        include_masked=True,
        in_installed=False
    )

    if not matches:
        sys.stderr.write(pp.warn("No package matching '%s'" % pp.pkgquery(query)))
        return

    matches = sorted(matches)
    matches.reverse()
    if _only_latest:
        matches = matches[:1]
    for package in matches:
        upstream_remote_id_package(package)

def types_from_dtd():
    from xml.parsers.xmlproc import dtdparser,xmldtd,utils
    from portage import settings

    parser = dtdparser.DTDParser()
    dtd = xmldtd.CompleteDTD(parser)

    parser.set_error_handler(utils.ErrorPrinter(parser))
    parser.set_dtd_consumer(dtd)
    parser.parse_resource(os.path.join(settings["PORTDIR"], 'metadata/dtd/metadata.dtd'))

    elem = dtd.get_elem('remote-id')
    attr = elem.get_attr('type')
    return attr.get_type()

def main():
    # FIXME: Use a real parser !

    if len(sys.argv) == 2 and sys.argv[1] in ['--help', '-h']:
        print ("Usage: ")
        print (" %s [--diff] --all" % sys.argv[0])
        print (" %s [--diff] [pkg [pkg2 [...]]]" % sys.argv[0])
        print (" eix --only-names -C dev-perl | %s" % sys.argv[0])
        sys.exit(0)

    if '--vanilla' in sys.argv:
        global _accepted_types
        sys.argv.remove('--vanilla')
        _accepted_types = types_from_dtd()
    if '--latest' in sys.argv:
        global _only_latest
        sys.argv.remove('--latest')
        _only_latest = True

    if len(sys.argv) >= 2 and sys.argv[1] in ['--diff', '-d']:
        global _generate_diff
        sys.argv.pop(1)
        _generate_diff = True

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
