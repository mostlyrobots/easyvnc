

cd X:\easyvnc\build_win
X:

SET PYTHONDIR=C:\Users\lcoady\AppData\Local\Programs\Python\Python38
SET EASYVNCBUILD=%TEMP%\easyvnc-build

for /f "delims== tokens=1,2" %%G in (..\version.py) do set %%G=%%~H

echo Compiling version %VERSION%
pause

if not exist vncviewer.exe (
  curl -L -o vncviewer.exe "https://bintray.com/tigervnc/stable/download_file?file_path=vncviewer64-1.10.1.exe"
)


if exist %EASYVNCBUILD% rmdir /s /q %EASYVNCBUILD%
if exist  %HOMEDRIVE%%HOMEPATH%\Desktop\EasyVNC-%VERSION%.zip del %HOMEDRIVE%%HOMEPATH%\Desktop\EasyVNC-%VERSION%.zip
if exist %HOMEDRIVE%%HOMEPATH%\Desktop\EasyVNC-%VERSION%.exe del %HOMEDRIVE%%HOMEPATH%\Desktop\EasyVNC-%VERSION%.exe

%PYTHONDIR%\Scripts\pyinstaller.exe ^
 --workpath %EASYVNCBUILD%\EasyVNC ^
 --distpath %EASYVNCBUILD%\dist ^
 EasyVNC.spec

%systemroot%\system32\xcopy.exe skel\*.* "%EASYVNCBUILD%\dist" /E /Y /I

"C:\Program Files\WinZIP\WZZIP.EXE" -a -rp %HOMEDRIVE%%HOMEPATH%\Desktop\EasyVNC-%VERSION%.zip %EASYVNCBUILD%\dist

"C:\Program Files (x86)\WinZip Self-Extractor\WINZIPSE.EXE" %HOMEDRIVE%%HOMEPATH%\Desktop\EasyVNC-%VERSION%.zip -setup -t dialog.txt -st "EasyVNC Installer" -c .\setup.bat
