import pytest

from config import Password, Config

def test_vnchex():
	assert Password('password').vnchex == 'dbd83cfd727a1458'
	assert Password('password1').vnchex == 'dbd83cfd727a1458'
	assert Password('passwor').vnchex == 'd1cc5f0a77989279'
