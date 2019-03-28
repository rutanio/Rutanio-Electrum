#!/bin/bash

NAME_ROOT=exos-electrum
PYTHON_VERSION=3.6.6

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
cd `dirname $0`
set -e

mkdir -p $WINEPREFIX/drive_c/exos-electrum

pushd ../..
cp -r electrum* .git* icons* pubkeys* setup* run_electrum LICENCE Info.plist $WINEPREFIX/drive_c/exos-electrum/
cp --parents contrib/requirements/* $WINEPREFIX/drive_c/exos-electrum/
popd

pushd $WINEPREFIX/drive_c/exos-electrum

# Load electrum-exo-icons and electrum-exo-locale for this release
git submodule init
git submodule update

VERSION=`git describe --tags || printf 'custom'`
echo "Last commit: $VERSION"

pushd ./contrib/deterministic-build/exos-electrum-locale
if ! which msgfmt > /dev/null 2>&1; then
    echo "Please install gettext"
    exit 1
fi
for i in ./locale/*; do
    dir=$WINEPREFIX/drive_c/exos-electrum/electrum/$i/LC_MESSAGES
    mkdir -p $dir
    msgfmt --output-file=$dir/electrum.mo $i/electrum.po || true
done
popd

find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

# Install frozen dependencies
$PYTHON -m pip install -r ../deterministic-build/requirements.txt

$PYTHON -m pip install -r ../deterministic-build/requirements-hw.txt

pushd $WINEPREFIX/drive_c/exos-electrum
$PYTHON setup.py install
popd

rm -rf dist/

# build standalone and portable versions
wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm --ascii --clean --name $NAME_ROOT-$VERSION -w deterministic.spec

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script itself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

cd dist
mv exos-electrum.exe $NAME_ROOT-$VERSION-setup.exe
cd ..

echo "Done."
md5sum dist/exos-electrum*exe
