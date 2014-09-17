#!/bin/bash

rm -rf dist
python macsetup.py py2app
cp -rp mac_bin/vncviewer.app dist/EasyVNC.app/Contents/Resources
ln -s /Applications dist/Applications
mkdir -p baked
codesign --force --deep -s L4U79Z7Z9S dist/EasyVNC.app/Contents/MacOS/EasyVNC
hdiutil create ./baked/EasyVNC.dmg -srcfolder ./dist/ -volname "EasyVNC" -ov -verbose -format UDZO
#rm -rf dist


