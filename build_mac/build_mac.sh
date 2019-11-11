#!/bin/bash


# notes: on a fresh machine, you will need to install xcode and use it to generate certs
# on 10.10+ you will need to reboot to recovery mode (command-R at boot), open terminal, csrutil disable, reboot
# then chflags -R norestricted /System/Library/Frameworks/Python.framework/
# then pip install paramiko==1.17.2

THISDIR=`pwd`
BUILDDIR=/tmp/easyvnc-build
PYINSTALLER=/Library/Frameworks/Python.framework/Versions/3.*/bin/pyinstaller

# read in the version of this build
. ../version.py
echo "Building version $VERSION"

echo "Clearing out $BUILDDIR"
rm -rf "$BUILDDIR"
mkdir -p "$BUILDDIR"

cd "$THISDIR/.."
pwd 

$PYINSTALLER --workpath $BUILDDIR/easyvnc --distpath $BUILDDIR/dist/ build_mac/EasyVNC.spec
ln -s /Applications $BUILDDIR/dist/Applications
rm -rf $BUILDDIR/dist/EasyVNC

codesign --force --deep -s L4U79Z7Z9S $BUILDDIR/dist/EasyVNC.app/Contents/MacOS/EasyVNC
hdiutil create $BUILDDIR/EasyVNC-$VERSION.dmg -srcfolder $BUILDDIR/dist/ -volname "EasyVNC" -ov -verbose -format UDZO



