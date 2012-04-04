#!/bin/bash

# Build Python as needed for PyKdump. If called without any options in Python src
# directory, it builds everything there.

# If called with an additional argument, it build Python in that directory


# Get file from SF GIT via HTTP-browser, using the 'master' branch
# Usage: getgitfile path outfile

getgitfile() {
  url="http://pykdump.git.sourceforge.net/git/gitweb.cgi?p=pykdump/pykdump;a=blob_plain;f=$1;hb=refs/heads/master"
  if ! wget -q "$url" -O $2
  then
     echo "Cannot retrieve $1 using HTTP"
     exit 2
  fi
}


getslocal() {
  # Get Python version
  if test ! -f "$CONFIGURE"
  then
    echo "Cannot find 'configure' file"
    exit 1
  fi

  PYVERS=`grep PACKAGE_VERSION= $CONFIGURE | sed -e "s/PACKAGE_VERSION=//;s/'//g" `

  setuploc="Setup.local-${PYVERS}"
  getgitfile Extension/$setuploc Modules/Setup.local
}

PYDIR=$PWD

buildarch () {
  local bdir 
  bdir="$1"
  echo "------Building for $bdir ------"
  # Test whether this directory already exists
  if [ ! -d $bdir ];then
    mkdir -p $bdir
  fi
  # Check whether this directory exists
  if [ ! -d $bdir ];then
      echo "Cannot create directory $bdir"
      exit 3
  fi
  cd $bdir
  CONFIGURE="$PYDIR/configure"
  $CONFIGURE CFLAGS=-fPIC
  getslocal 
  make
  #strip -d libpython${PYVERS}.a
  cd $PYDIR
}

Usage() {
  cat <<_ACEOF
'buildPython.sh' lets you build Python as needed by PyKdump.
After unpacking Python sources, go its top directory and call
this script like that:

Usage: $0  [-a] [-b builddir]

Configuration:
  -a                    Builds both 32-bit and 64-bit versions
                        of Python in X86 and X86_64 subdirectories
  -h, --help              display this help and exit
  -b                    Use a separate directory for your build.

_ACEOF
}


build_dir='.'

while getopts "b:ha" opt
do
    case $opt in
      b)
        build_dir="$OPTARG"
        ;;
      a)
        a3264=1
        ;;
      h)
        Usage;exit 0
        ;;
      esac
done
      
#echo "build_dir=$build_dir"
#echo "a3264=$a3264"

if test "${a3264+set}" != set; then
    buildarch "$build_dir"
else
    # Build in X86 and X86_64 subdirectories
    buildarch "`dirname $build_dir/a`/X86_64"
    CC='gcc -m32' buildarch "`dirname $build_dir/a`/X86"
    exit 0
fi    

