#!/bin/bash


# notes: on a fresh machine, you will need to install xcode and use it to generate certs
# on 10.10+ you will need to reboot to recovery mode (command-R at boot), open terminal, csrutil disable, reboot
# then chflags -R norestricted /System/Library/Frameworks/Python.framework/
# then pip install paramiko==1.17.2

rm -rf dist
python macsetup.py py2app
cp -rp mac_bin/vncviewer.app dist/EasyVNC.app/Contents/Resources
ln -s /Applications dist/Applications
mkdir -p baked
codesign --force --deep -s L4U79Z7Z9S dist/EasyVNC.app/Contents/MacOS/EasyVNC
hdiutil create ./baked/EasyVNC.dmg -srcfolder ./dist/ -volname "EasyVNC" -ov -verbose -format UDZO
#rm -rf dist


