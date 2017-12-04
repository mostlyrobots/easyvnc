# -*- mode: python -*-

block_cipher = None

# add this to pathex and change escapes "C:\python35\lib\site-packages\pyqt5\qt\bin"

a = Analysis(['..\\EasyVNC.py'],
             pathex=['C:\\program files(x86)\\Windows Kits\\10\\Redist\\ucrt\\DLLs\\x64', 'C:\\Users\\lcoady\\Google Drive\\Career\\Work\\easyvnc\\build_win'],
             binaries=[],
             datas=[('C:\\Users\\lcoady\\Google Drive\\Career\\Work\\easyvnc\\build_win\\vncviewer.exe', 'vncviewer.exe')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='EasyVNC',
          debug=False,
          strip=False,
          upx=True,
          console=False , icon='..\\icons\\EasyVNC.ico')
