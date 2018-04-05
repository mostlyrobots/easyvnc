#! /usr/bin/env pythonw
# -*- coding: utf-8 -*-

# local version number
from version import VERSION

import base64
from binascii import hexlify
import os
import select
import socket
import sys
import time
import traceback

import socketserver
import _thread as thread
import subprocess

from binascii import hexlify

from tkinter import *
from tkinter.ttk import *
from tkinter import messagebox as tkMessageBox

# non-standard libraries 
import paramiko
import d3des

class Config():
	def __init__(self):
		self.remote_host = str()
		self.homedir = os.path.expanduser("~")
		self.scriptdir = self.get_scriptdir()
		self.remote_port = 22
		
		vncargs = ['-config', '-']
		
		if os.name == 'nt':
			# windows is the os
			self.vnccommand = [ self.scriptdir + '\\vncviewer.exe\\vncviewer.exe'] + vncargs
			self.username = os.environ.get('USERNAME')
			self.configfile = self.homedir + '\\mvnc.cfg'
		else:
			# otherwise presume macos
			self.vnccommand = [ self.scriptdir + '/vncviewer.app/Contents/MacOS/vncviewer'] + vncargs
			self.username = os.environ.get('LOGNAME')
			self.configfile = self.homedir + '/.mvnc.cfg'
		
		# these are all possible host options for the dropdown in the GUI
		self.hosts = ("acropolis", "athensx", "cronusx", "css", "rhodesx")

		self.load()

	def get_vncconfig(self, vnc_port):
		vncconfig='Host=127.0.0.1:%s\nUsername=%s\n Password=%s\nverifyid=0\nautoreconnect=1\nclientcuttext=1\nencryption=preferoff\nshared=0\nuserlocalcursor=1\nsecuritynotificationtimeout=0\nservercuttext=1\nsharefiles=1\nwarnunencrypted=0\n'
		return vncconfig % (vnc_port, self.username, self.get_vncpassword()) 

	def get_scriptdir(self):
		# determine if application is a script file or frozen exe
		if getattr(sys, 'frozen', False):
			application_path = sys._MEIPASS
		else:
			application_path = os.path.dirname(os.path.abspath(__file__))
		return application_path

	def vnc_obfuscate(self, password):
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
		if len(password) > 8:
			ctext += self.vnc_obfuscate(password[8:])
		return ctext

	def get_vncpassword(self):
		"""return the hexencoded obfuscated vnc password"""
		return hexlify(self.vnc_obfuscate(self.password)).decode()
	
	def get_fqdn_remote_host(self):
		return self.remote_host + ".uchicago.edu"

	def load(self):
		"""Load options from configfile on disk"""
		try:
			file = open(self.configfile)
			for line in file:
				(key, value) = line.split('=')
				if key == 'username':
					self.username=value.strip()
				elif key == 'remote_host':
					self.remote_host=value.strip()
		except IOError:
			return

	def save(self):
		"""Save options to configfile."""
		file = open(self.configfile, 'w+')
		file.write('username=%s\nremote_host=%s' % (self.username, self.remote_host))	

# instantiate config and declare it global
global config
config = Config()


def verbose(s):
	"""Wrapper function to print debug statements"""
	#print(s, file=sys.stderr)
	pass



class MainUI(Frame):
	"""Main Tkinter GUI"""
	
	def __init__(self, parent):
		# initialize root frame and holders for values
		Frame.__init__(self, parent)
		self.remote_host = StringVar()
		self.username = StringVar()
		self.password = StringVar()
		self.parent = parent

		# fill in the forms with config data
		
		self.remote_host.set(config.remote_host)
		self.username.set(config.username)

		# describe the interface
		self.parent.title("Connect to Server")
		self.style = Style()
		self.style.theme_use("default")

		frame = Frame(self, relief='flat', borderwidth=10)

		Label(frame, text='VNC Host:').grid(row=0, sticky=W)
		hostOption = OptionMenu(frame, self.remote_host, "", *config.hosts)
		hostOption.grid(row=0, column=1, pady=10, padx=5)

		Label(frame, text='Username:').grid(row=1, sticky=W)
		usernameEntry = Entry(frame, textvariable=self.username, width=16)
		usernameEntry.grid(row=1, column=1, padx=5)

		Label(frame, text='Password:').grid(row=2, sticky=W)
		passwordEntry = Entry(frame, textvariable=self.password, width=16, show='•')
		passwordEntry.grid(row=2, column=1)
		passwordEntry.bind('<Return>', connect)

		frame.pack(fill=BOTH, expand=1)
		self.pack(fill=BOTH, expand=1)
		
		revisionLabel = Label(self, text="r. " + str(VERSION))
		revisionLabel.pack(side=LEFT, padx=5, pady=5)

		closeButton = Button(self, text="Quit", command=master.quit)
		closeButton.pack(side=RIGHT, padx=5, pady=5)
		
		connectButton = Button(self, text="Connect", command=connect)
		connectButton.pack(side=RIGHT)
 
def forward_tunnel(local_port, remote_host, remote_port, transport):
	"""Start a tunnel using the supplied transport object"""

	# This class defines the socket handler that will attach to the remote system
	# it is in the context of the forward_tunnel in order to get the remote transport details
	# This is because Handler is not instantiated until the ThreadingTCPServer starts
	class Handler(socketserver.BaseRequestHandler):
		def handle(self):
			# try to open a paramiko ssh channel to host the forwarded packets and catch exceptions
			try:
				chan = transport.open_channel('direct-tcpip', (remote_host, remote_port), self.request.getpeername())
			except Exception as e:
				verbose('Incoming request to %s:%d failed: %s' % (remote_host, remote_port, repr(e)))
				return
			if chan is None:
				verbose('Incoming request to %s:%d was rejected by the SSH server.' % (remote_host, remote_port))
				return
			verbose('Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(), chan.getpeername(), (remote_host, remote_port)))
	
			# The tunnel is established, start send and receive buffer loop
			while True:
				r, w, x = select.select([self.request, chan], [], [])
				if self.request in r:
					data = self.request.recv(1024)
					if len(data) == 0:
						break
					chan.send(data)
				if chan in r:
					data = chan.recv(1024)
					if len(data) == 0:
						break
					self.request.send(data)
			# exit of loop indicates that the connection is closed down
			# close down request and exit app
			chan.close()
			self.request.close()
			verbose('Tunnel closed ')
			master.quit()

	# Start the Threading TCP server using the above defined Handler. This is actually
	# the process that will forward packets between our side and the server
	forwardserver = socketserver.ThreadingTCPServer(('127.0.0.1', local_port), Handler)
	forwardserver.daemon_threads = True
	forwardserver.allow_reuse_address = True
	forwardserver.serve_forever()

def connect(event=None):
	if app.password.get() == "" or app.username.get() == '' or app.remote_host.get() == '':
		tkMessageBox.showwarning("Incomplete Form", "You must supply a server name, username, and password.")
		return

	# save the form data into the config
	config.username = app.username.get()
	config.password = app.password.get()
	config.remote_host = app.remote_host.get()
	config.save()

	verbose("%s@%s:%s" % (config.username, config.get_fqdn_remote_host(), config.remote_port))

	# this command will be executed on the remote host to start the Xvnc server session
	remote_vnccommand = """
vncactive() {
	 VNCACTIVE=($(ps -C Xvnc-core -o user,args | grep $USER | grep : | cut -d: -f2 | cut -d' ' -f1))
};
remove_locks() {
	find /tmp/.X* -user $USER -exec rm '{}' \;
};
run_vnc() {
	vncactive
	case ${#VNCACTIVE[@]} in 
		0)
			#not running
			remove_locks
			/usr/bin/.remotex -geometry 1024x768 -randr 1680x1050,1280x800,2048x1150,1920x1200,1152x864,1600x900,1366x768,1280x1024,1440x900,2560x1440,1024x768,1920x1080 &>/dev/null
			vncactive
		;;
	esac 

	echo ${VNCACTIVE[0]}
	echo 0
};
run_vnc
"""

	# attempt to connect TCP socket to remote host, catch exceptions and throw warnings if there are problems	
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((config.get_fqdn_remote_host(), config.remote_port))
	except Exception as e:
		if e.errno == 11001:
			tkMessageBox.showwarning("Connect Failed", "Could not connect because the remote_host (%s) would not resolve.\n  There may be a problem with your internet connection." % (remote_host))
		else:
			tkMessageBox.showwarning("Connect Failed", "SSH negotiation failed for %s: %s" % (config.get_fqdn_remote_host(), str(e)))
		return


	try:
		# start a new paramiko transport over TCP socket
		t = paramiko.Transport(sock)
		t.start_client()

		# authenticate 
		t.auth_password(config.username, config.password)
		
		# a new channel on the paramiko transport layer, ssh can have lots of channels 
		# may be interesting to add more channels, for remote shells and stuff
		chan = t.open_session()
		# fire up Xvnc on remote system and capture the output
		chan.exec_command(remote_vnccommand)
		stdin = chan.makefile('wb')
		stdout = chan.makefile('rb')
		stderr = chan.makefile_stderr('rb')
		# expecting an integer from the remote_vnccommand script, to tell us what port to use
		vnc_port = int(stdout.readline()) + 5900
		verbose('Discovered VNC on port %i' % (vnc_port))

		# get a clue to tell us if we are compatible with the remote
		# compare remote_verison to local and if the remote is newer throw a warning
		remote_version = int(stdout.readline())
		verbose('Remote version %i' %(remote_version))
		if remote_version > VERSION:
			tkMessageBox.showwarning("Update Available", "There is a newer version of EasyVNC available for download.  Please download and install a new copy from sw.src.uchicago.edu in order to ensure continued use.")

		# we are done with this control channel
		chan.close()

		# create a thread to forward packets to server
		thread.start_new_thread(forward_tunnel, (vnc_port, 'localhost', vnc_port, t, ))

		# start up the local vnc client
		vncprocess = subprocess.Popen(config.vnccommand, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		# pipe the vncconfig into the new vnc client process
		vncconfig = config.get_vncconfig(vnc_port)
		verbose('vncconfig: ' + vncconfig)		
		vncprocess.stdin.write(str.encode(vncconfig)  )
		vncprocess.stdin.close()
		
		# minimize the GUI
		master.withdraw()
	except ValueError:
			tkMessageBox.showwarning("Server Error", "%s did not respond as expected to the command \n %s\nContact server support and report this error." % (config.remote_host, remote_vnccommand))
			t.close()
			return
	except paramiko.AuthenticationException:
			tkMessageBox.showwarning("Connect Failed", "Authentication failed :(  You provided an incorrect username or password for %s" % (config.remote_host))
			t.close()
			return
	except Exception as e:
		tkMessageBox.showwarning("Unhandled Exception", "An application error has occured.\n Traceback: %s Dir:%s CMD: %s" % (traceback.format_exc(), config.scriptdir, config.vnccommand))
		sys.exit(1)


master = Tk()
master.geometry("300x200+300+300")
app = MainUI(master)
master.mainloop()  
