
echo Remove files from C:\Program Files\EasyVNC, if they exist..
if exist "c:\Program Files\EasyVNC" rmdir /s /q "C:\Program Files\EasyVNC"

echo Creating directories..
mkdir "C:\Program Files\EasyVNC\"

echo Installing EasyVNC to C:\Program Files..
%systemroot%\system32\xcopy.exe "dist" "C:\Program Files\EasyVNC" /E /Y /I

%systemroot%\system32\xcopy.exe "dist\EasyVNC.lnk" "%HOMEDRIVE%%HOMEPATH%\Desktop\"  /Y

.\dist\vcredist_x86.exe /Q
