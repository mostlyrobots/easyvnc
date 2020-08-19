#!/bin/bash -x


# notes: on a fresh machine, you will need to install xcode and use it to generate certs
# on 10.10+ you will need to reboot to recovery mode (command-R at boot), open terminal, csrutil disable, reboot
# then chflags -R norestricted /System/Library/Frameworks/Python.framework/
# then pip install paramiko==1.17.2

THISDIR=`pwd`
BUILDDIR=/tmp/easyvnc-build
CERTNAME="Developer ID Application: Lucas Coady (L4U79Z7Z9S)"
AC_USERNAME="lucas@uchicago.edu"
BUNDLEID="edu.uchicago.sscs.easyvnc.dmg"

#PYINSTALLER=/Library/Frameworks/Python.framework/Versions/3.*/bin/pyinstaller
PYINSTALLER=/usr/local/bin/pyinstaller

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

codesign --timestamp --force --deep -s "${CERTNAME}" $BUILDDIR/dist/EasyVNC.app/Contents/MacOS/EasyVNC

if [ $? -gt 0 ] ; then 
   exit 1
fi

hdiutil create $BUILDDIR/EasyVNC-$VERSION.dmg -srcfolder $BUILDDIR/dist/ -volname "EasyVNC" -ov -verbose -format UDZO

xcrun altool \
  --notarize-app \
  --primary-bundle-id ${BUNDLEID} \
  --username "${AC_USERNAME}" \
  --password "@keychain:AC_PASSWORD" \
  --asc-provider LucasCoady78264057 \
  --file $BUILDDIR/EasyVNC-$VERSION.dmg

mv $BUILDDIR/EasyVNC-$VERSION.dmg ~/Desktop
echo Done.

# xcrun altool -u "lucas@uchicago.edu" --password @keychain:AC_PASSWORD   --notarization-info
# xcrun stapler staple ~/Desktop/EasyVNC-*.dmg