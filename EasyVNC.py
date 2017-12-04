#! /usr/bin/env pythonw
# -*- coding: utf-8 -*-


# This file represents the main user interface for the project.

from version import VERSION

import base64
from binascii import hexlify
import os
import select
import socket
import sys
import time
import traceback

import paramiko

import d3des

import socketserver
import _thread as thread
import subprocess

from binascii import hexlify

from tkinter import *
from tkinter.ttk import *
from tkinter import messagebox as tkMessageBox

class MainUI(Frame):

	def __init__(self, parent):
		Frame.__init__(self, parent)
		self.hostname = StringVar()
		self.username = StringVar()
		self.password = StringVar()
		self.parent = parent

		self.homedir = os.path.expanduser("~")
		if os.name == 'nt':
			self.vnccommand = ['vncviewer.exe']
			self.username.set(os.environ.get('USERNAME'))
			self.configfile = self.homedir + '\\mvnc.cfg'
		else:
			self.configfile = self.homedir + '/.mvnc.cfg'
			self.vnccommand = ['./vncviewer.app/Contents/MacOS/vncviewer']
			self.vnccommand = ['./mac_bin/vncviewer.app/Contents/MacOS/vncviewer']
			self.username.set(os.environ.get('LOGNAME'))
	
		self.load()
		
		self.initUI()

	def initUI(self):
		self.parent.title("Connect to Server")
		self.style = Style()
		self.style.theme_use("default")


		frame = Frame(self, relief='flat', borderwidth=10)

		Label(frame, text='VNC Host:').grid(row=0, sticky=W)
		hostOption = OptionMenu(frame, self.hostname, "", "acropolis", "athensx", "cronusx", "css", "rhodesx")
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

	def load(self):
		try:
			file = open(self.configfile)
			for line in file:
				(key, value) = line.split('=')
				if key == 'username':
					self.username.set(value.strip())
				elif key == 'hostname':
					self.hostname.set(value.strip())
		except IOError:
			return

	def save(self):
		file = open(self.configfile, 'w+')
		file.write('username=%s\nhostname=%s' % (self.username.get(), self.hostname.get()))

def verbose(s):
	print(s, file=sys.stderr)
	pass

def vnc_encode(password):
    passpadd = (password + '\x00'*8)[:8]
    strkey = ''.join([ chr(x) for x in d3des.vnckey ])
    ekey = d3des.deskey(bytearray(strkey, encoding="ascii"), False)
    ctext = d3des.desfunc(bytearray(passpadd, encoding="ascii"), ekey)
    if len(password) > 8:
    	ctext += vnc_encode(password[8:])
    return ctext




class ForwardServer (socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    
class Handler (socketserver.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel('direct-tcpip', (self.chain_host, self.chain_port), self.request.getpeername())
        except Exception as e:
            verbose('Incoming request to %s:%d failed: %s' % (self.chain_host, self.chain_port, repr(e)))
            return
        if chan is None:
            verbose('Incoming request to %s:%d was rejected by the SSH server.' % (self.chain_host, self.chain_port))
            return

        verbose('Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(), chan.getpeername(), (self.chain_host, self.chain_port)))
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
        chan.close()
        self.request.close()
        #master.update()
        #master.deiconify()
        verbose('Tunnel closed ')
        master.quit()

def forward_tunnel(local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (socketserver doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander (Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport
    ForwardServer(('', local_port), SubHander).serve_forever()


def connect(event=None):
	if app.password.get() == "" or app.username.get() == '' or app.hostname.get() == '':
		tkMessageBox.showwarning("Incomplete Form", "You must supply a server name, username, and password.")
		return
	
	app.save()
	username = app.username.get()
	password = app.password.get()
	vncpassword = hexlify(vnc_encode(password)).decode()
	hostname = app.hostname.get()
	if hostname == "corinthx": hostname = "rhodesx"
	hostname = app.hostname.get() + '.uchicago.edu'
	port = 22
	verbose("%s@%s:%s" % (username, hostname, port))

	vnccommand = app.vnccommand
	vncargs = ' -config -'
	#	vncargs = ' -config - -verifyid=0 -autoreconnect=1 -clientcuttext=1 -encryption=preferoff -shared=0 -uselocalcursor=1 -securitynotificationtimeout=0 -servercuttext=1 -sharefiles=1 -username=%s -warnunencrypted=0 localhost:' % (username)
	verbose(vnccommand[0] + vncargs)

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
	
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((hostname, port))
	except Exception as e:
		if e.errno == 11001:
			tkMessageBox.showwarning("Connect Failed", "Could not connect because the hostname (%s) would not resolve.\n  There may be a problem with your internet connection." % (hostname))
		else:
			tkMessageBox.showwarning("Connect Failed", "SSH negotiation failed for %s: %s" % (hostname, str(e)))
		return

	try:
	
		vncconfig='Host=127.0.0.1:%s\nUsername=%s\n Password=%s\nverifyid=0\nautoreconnect=1\nclientcuttext=1\nencryption=preferoff\nshared=0\nuserlocalcursor=1\nsecuritynotificationtimeout=0\nservercuttext=1\nsharefiles=1\nwarnunencrypted=0\n' 

		t = paramiko.Transport(sock)
		
		t.start_client()

		t.auth_password(username, password)
		
		chan = t.open_session()
		chan.exec_command(remote_vnccommand)
		stdin = chan.makefile('wb')
		stdout = chan.makefile('rb')
		stderr = chan.makefile_stderr('rb')
		vncport = int(stdout.readline())
		verbose('Discovered VNC on port %i' % (vncport))

		remoteversion = int(stdout.readline())
		verbose('Remote version %i' %(remoteversion))
		if remoteversion > VERSION:
			tkMessageBox.showwarning("Update Available", "There is a newer version of EasyVNC available for download.  Please download and install a new copy from sw.src.uchicago.edu in order to ensure continued use.")
		chan.close()
		#vncargs += str(vncport + 5900)
		thread.start_new_thread(forward_tunnel, (vncport + 5900, 'localhost', vncport + 5900, t, ))
		vnccommand += vncargs.split()
		vncprocess = subprocess.Popen(vnccommand, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		vncconfig = vncconfig % (vncport + 5900, username, vncpassword)
		verbose('vncconfig: ' + vncconfig)
		
		vncprocess.stdin.write(str.encode(vncconfig)  )
		vncprocess.stdin.close()
		master.withdraw()
	except ValueError:
			tkMessageBox.showwarning("Server Error", "%s did not respond as expected to the command \n %s\nContact server support and report this error." % (hostname, remote_vnccommand))
			t.close()
			return
	except paramiko.AuthenticationException:
			tkMessageBox.showwarning("Connect Failed", "Authentication failed :(  You provided an incorrect username or password for %s" % (hostname))
			t.close()
			return
	except Exception as e:
		tkMessageBox.showwarning("Unhandled Exception", "An application error has occured.\n Traceback: %s " % (traceback.format_exc()))
		sys.exit(1)


master = Tk()
master.geometry("300x200+300+300")
app = MainUI(master)
master.mainloop()  
