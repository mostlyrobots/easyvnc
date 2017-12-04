rmdir /s /q dist
c:\python27\python winsetup.py py2exe
xcopy win_bin\*.* dist

echo now zip up dist
echo return here and make self extracting archive with setup.bat

