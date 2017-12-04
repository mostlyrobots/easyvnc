
cd C:\Users\lcoady\Google Drive\Career\Work\easyvnc\build_win

SET EASYVNCBUILD=%TEMP%\easyvnc-build

for /f "delims== tokens=1,2" %%G in (..\version.py) do set %%G=%%~H

echo Compiling version %VERSION%
pause

if exist %EASYVNCBUILD% rmdir /s /q %EASYVNCBUILD%
if exist %HOMEPATH%\Desktop\EasyVNC-%VERSION%.zip del %HOMEPATH%\Desktop\EasyVNC-%VERSION%.zip
if exist %HOMEPATH%\Desktop\EasyVNC-%VERSION%.exe del %HOMEPATH%\Desktop\EasyVNC-%VERSION%.exe

C:\Python35\Scripts\pyinstaller.exe ^
 --workpath %EASYVNCBUILD%\EasyVNC ^
 --distpath %EASYVNCBUILD%\dist ^
 EasyVNC.spec
 
REM "C:\Program Files\WinZIP\WZZIP.EXE" -a -rp %HOMEPATH%\Desktop\EasyVNC-%VERSION%.zip %EASYVNCBUILD%\dist\EasyVNC.exe 