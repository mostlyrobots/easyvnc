
from distutils.core import setup
import py2exe

setup(
	windows = [
		{
			"script": 'EasyVNC.py',
			"icon_resources": [(1, "icons\EasyVNC.ico")]
		}
	],
)

