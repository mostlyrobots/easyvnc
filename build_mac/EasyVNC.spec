# -*- mode: python -*-

block_cipher = None


a = Analysis(['../EasyVNC.py'],
             pathex=['/Volumes/lcoady/easyvnc'],
             binaries=[],
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
          exclude_binaries=True,
          name='EasyVNC',
          debug=False,
          strip=False,
          upx=True,
          console=False )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='EasyVNC')
app = BUNDLE(coll,
	name='EasyVNC.app',
	icon='../icons/EasyVNC.icns',
	bundle_identifier=None,
	info_plist={ 'NSHighResolutionCapable': 'True' })

