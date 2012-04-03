#! /bin/env bash

readonly prog=`basename $0 .sh`
readonly progdir=`cd \`dirname $0\` >/dev/null && pwd`
readonly program=$progdir/`basename $0`
readonly progpid=$$
dying=false

die() {
    $dying && exit 1
    dying=true
    echo "$prog fatal error:  $*"
    kill -TERM $progpid
    sleep 1
    kill -KILL $progpid
    exit 1
} >&2
trap 'die "dying on command failure"' 0

init() {
    set -e
    dirlist=(PYTHONSRC PYTHONBLD CRASHSRC)
    namelist=(python python crash)

    local ix=0
    for f in $dirlist
    do  eval ${f}_ix=$ix
        ix=`expr $ix + 1`
    done

    check_dirs

    nl='
'   ht='	'
}

check_dirs() {
    local dftfmt='The %s build directory has been defaulted to the source.\n'
    local nodirfmt='Please specify the %s source directory.\n'

    for f in ${dirlist[*]}
    do
        eval ix=\${${f}_ix}
        eval d=\${${f}DIR}
        test -d "$d" && continue
        case "$f" in
        *BLD )
            eval ${f}DIR=\${${f%BLD}SRCDIR}
            printf "$dftfmt" ${namelist[$ix]}
            ;;

        *SRC )
            printf "$nodirfmt" ${namelist[$ix]}
            while test ! -d "$d"
            do
                read -p 'dir> ' d || \
                    die "no ${namelist[$ix]} directory specified"
                test -d "$d" || \
                    echo "that is not a directory"
            done
            eval ${f}DIR=$d
            ;;
        esac
    done
}

validate() {
    local txt=`exec 2>/dev/null
        file ${CRASHSRCDIR}/crash | fgrep 'executable'`
    test -z "$txt" && \
        die "crash has not been built in ${CRASHSRCDIR}"
    txt=`sed -n 's/^m4_define(PYTHON_VERSION, *\([0-9.]*\).*/\1/p` \
        ${PYTHONSRCDIR}/configure.??`
    test -z "$txt" && \
        die "python sources are not in ${PYTHONSRCDIR}"
    case "$txt" in
    2.[6-9]* | 3.* )
        : ;;
    * )
        die "unknown python version:  $txt"
        ;;
    esac

    txt=`exec 2>/dev/null
        file ${PYTHONBLDDIR}/Modules/main.o | fgrep relocatable`
    test -z "$txt" && \
        die "python has not been built in ${PYTHONBLDDIR} or" \
            "${nl}it was not built as a relocatable object"
}

build_ext() {
    cd ${progdir}/Extension
    test -f crash.mk || \
        ./configure -c ${CRASHBLDDIR} -p ${PYTHONBLDDIR}
    make
    make install
}

init
validate
build_ext
trap '' 0
exit 0
