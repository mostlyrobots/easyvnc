import pytest

from config import Password, Config

def test_vnchex():
	assert Password('password').get_vnchex() == 'dbd83cfd727a1458'
	assert Password('password1').get_vnchex() == 'dbd83cfd727a1458'
	assert Password('passwor').get_vnchex() == 'd1cc5f0a77989279'
