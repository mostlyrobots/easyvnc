#!/bin/bash

rm -rf dist
python macsetup.py py2app
cp -rp mac_bin/vncviewer.app dist/EasyVNC.app/Contents/Resources
ln -s /Applications dist/Applications
hdiutil create ./dist/EasyVNC.dmg -srcfolder ./dist/ -ov
rm -rf baked
mkdir -p baked
mv dist/EasyVNC.dmg baked
rm -rf dist


