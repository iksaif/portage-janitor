#!/bin/sh

run() {
    local cmd=$@

    echo "$cmd"
    eix --only-names -x | ${cmd} > portage.diff
    categories=$(diffstat -p1 -l portage.diff | cut -d/ -f 1 | sort -u)
    for category in ${categories}; do
	echo ${category}
	difffilter -a -e "${category}/" -x -e '' < portage.diff > ${category}.diff

	mkdir ${category} -p
	packages=$(diffstat -p1 -l ${category}.diff | cut -d/ -f1-2)

	for package in ${packages}; do
	    echo ${package}
	    difffilter -a -e "${package}/" -x -e '' < ${category}.diff > ${package}.diff
	done
    done
}

run_in_dir() {
    local output=$1
    shift

    rm -rf output/${output}
    mkdir -p output/${output}
    (cd output/${output} && run $@)
}

PATH=$(pwd):$PATH
PWD=$(pwd)

run_in_dir remoteids remoteids.py --diff --check

run_in_dir mirrors mirrors.py --diff
run_in_dir mirrors-fix mirrors.py --diff -m ${PWD}/thirdpartymirrors-fix
run_in_dir mirrors-extended mirrors.py --diff -m ${PWD}/thirdpartymirrors-extended -m ${PWD}/thirdpartymirrors-fix-extended
run_in_dir mirrors-full mirrors.py --diff -m ${PWD}/thirdpartymirrors-extended -m ${PWD}/thirdpartymirrors-fix-extended -m ${PWD}/thirdpartymirrors-fix -m /usr/portage/profiles/thirdpartymirrors

