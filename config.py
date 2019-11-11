import base64
import sys
from binascii import hexlify

import d3des

#this command will be executed on the remote host to start the Xvnc server session
REMOTE_VNCCOMMAND = """
	vncactive() {
		VNCPID=$(pgrep -U $USER Xvnc* | tr ' ' ',')
		if [ "$VNCPID" != "" ]; then
			VNCACTIVE=$(ps -p $VNCPID -o args | grep : | cut -d: -f2 | cut -d' ' -f1)
		fi
	};
	
	remove_locks() {
		find /tmp/.X* -user $USER -exec rm '{}' \;
	};
	
	vnckill() {
		vncactive
		kill $VNCPID
	}
	
	vncmkpass() {
		PASS=$(openssl rand -base64 9 | tr '/' ',')
		echo $PASS | /usr/local/tigervnc/vncpasswd -f > ~/.vnc/passwd 
	}
	
	run_vnc() {
		mkdir -p ~/.vnc
		PATH=/usr/local/tigervnc:$PATH;	export PATH
		
		vncmkpass
		
		vncactive
		case ${#VNCACTIVE[@]} in 
			0)
				#not running
				remove_locks
				vncserver -rfbauth ~/.vnc/passwd -xstartup /usr/local/tigervnc/xstartup -geometry 1024x768  &>/dev/null
				sleep 2 # give the process time to warm up
				vncactive
			;;
		esac 

		echo ${VNCACTIVE[0]}
		echo 0
		echo $PASS
	};
	run_vnc
	"""

class Password(str):
	"""Extended str() class for handling obfuscated VNC passwords. Accepts plaintext str()."""
	passwordfile = None
	
	def obfuscate(self, password):
		"""Obfuscate a plaintext password in VNC format"""
		
		# pad password up to 8 chars, truncate anything over 8
		passpadd = (password + '\x00'*8)[:8]
		
		# load the vnckey from library and change encoding to ascii
		strkey = ''.join([ chr(x) for x in d3des.vnckey ])
		ekey = d3des.deskey(bytearray(strkey, encoding="ascii"), False)
		
		# encrypt the passpadd section from above
		ctext = d3des.desfunc(bytearray(passpadd, encoding="ascii"), ekey)
		
		# if the password was longer than 8 chars, then recurse, this will chunk the 
		# password into 8 character obfuscated sections. versions older than 5 will ignore 8+
		# this method is used by RealVNC but most other implementations truncate at 8
		
		#if len(password) > 8:
		#	ctext += self.obfuscate(password[8:])
		return ctext
		
	def get_vnchex(self):
		"""return the hexencoded obfuscated vnc password"""
		return hexlify(self.obfuscate(self)).decode()
	
class Config():
	"""Master App config"""
	passwordfile = None
	
	def __init__(self):
		# the host and port we are going to connect to
		self.remote_host = str()
		self.remote_port = 22

		self.homedir = os.path.expanduser("~")
		self.scriptdir = self.get_scriptdir()
		self.password = Password()
		
		# these are all possible host options for the dropdown in the GUI
		self.hosts = ("acropolis.uchicago.edu", "athens.uchicago.edu", "cronus.uchicago.edu", "css.uchicago.edu", "rhodes.uchicago.edu")
		
		if os.name == 'nt':
			# windows is the os
			self.username = os.environ.get('USERNAME')
			self.configfile = self.homedir + '\\mvnc.cfg'
		else:
			# otherwise presume macos
			self.username = os.environ.get('LOGNAME')
			self.configfile = self.homedir + '/.mvnc.cfg'

		self.load() 

	def get_vnccommand(self, vnc_port):
		if os.name == 'nt':
			self.passwordfile = tempfile.NamedTemporaryFile(delete=False)
			self.passwordfile.write(self.password.obfuscate(self))
			self.passwordfile.close()
			self.vnccommand = [ self.scriptdir + '\\vncviewer.exe'] + ['-PasswordFile', self.passwordfile.name, 'localhost:%s' % (vnc_port) ]

		else:
			self.vnccommand = ['/System/Library/CoreServices/Applications/Screen Sharing.app/Contents/MacOS/Screen Sharing']
		return self.vnccommand

	def cleanup_passwordfile(self):
		if self.passwordfile:
			return os.remove(self.passwordfile.name)
	
	def get_scriptdir(self):
		"""Return the full path of the directory this script is being executed from"""
		# Determine if application is a script file or frozen exe
		if getattr(sys, 'frozen', False):
			application_path = sys._MEIPASS
		else:
			application_path = os.path.dirname(os.path.abspath(__file__))
		return application_path

	def get_fqdn_remote_host(self):
		return self.remote_host

	def load(self):
		"""Load options from configfile on disk"""
		try:
			file = open(self.configfile)
			for line in file:
				(key, value) = line.split('=')
				if key == 'username':
					self.username=value.strip()
				elif key == 'remote_host':
					remote_host=value.strip()
					if remote_host in self.hosts:
						# reject remote_host entries that are options
						self.remote_host = remote_host
		except IOError:
			return

	def save(self):
		"""Save options to configfile."""
		file = open(self.configfile, 'w+')
		file.write('username=%s\nremote_host=%s' % (self.username, self.remote_host))
