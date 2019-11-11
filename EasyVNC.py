#! /usr/bin/env pythonw
# -*- coding: utf-8 -*-

# local scirpt version number
import version


import os
import select
import socket
import sys
import time
import traceback
import io
import re

import socketserver
import _thread as thread
import subprocess


# QT5 libraries 
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

# non-standard libraries 
import paramiko


from config import Config, Password, REMOTE_VNCCOMMAND

if os.name is not 'nt': import applescript


# instantiate config and declare it global
global config
config = Config()

def excepthook(excType, excValue, tracebackobj):
	"""
	Global function to catch unhandled exceptions.

	@param excType exception type
	@param excValue exception value
	@param tracebackobj traceback object
	"""

	if str(excType) == """<class 'UserWarning'>""":
		msg = str(excValue)
	else:
		notice = \
			"""Hi. An unhandled exception was encountered. Please report the problem """\
			"""by copying this dialog to <%s>.\n""" % \
			("lucas@uchicago.edu")

		build_info = \
			"""Exception occured on version <%s> at %s.""" % (version.VERSION, time.strftime("%Y-%m-%d, %H:%M:%S"))

		tbinfofile = io.StringIO()
		traceback.print_tb(tracebackobj, None, tbinfofile)
		tbinfofile.seek(0)
		tbinfo = tbinfofile.read()
	
		separator = '~' * 85

		errmsg = '%s: \n%s' % (str(excType), str(excValue))

		sections = [notice, separator, build_info, separator, tbinfo, errmsg]
		msg = '\n'.join(sections)
	
	
	errorbox = QMessageBox()
	errorbox.setText(str(msg))
	errorbox.exec_()

class KQDialog(QDialog):
	def centerWindow(self):
		qr = self.frameGeometry()
		cp = QDesktopWidget().availableGeometry().center()
		qr.moveCenter(cp)
		self.move(qr.topLeft())
		
	def closeEvent(self, event):
		sys.exit()

class LoginUI(KQDialog):
	def __init__(self, mainwindow):
	
		self._mainwindow = mainwindow
		
		KQDialog.__init__(self)
		
		self.username = QLineEdit()
		self.password = QLineEdit()
		self.password.setEchoMode(QLineEdit.Password)
		self.remote_host = QComboBox()
		self.remote_host.addItems(config.hosts)
		
		self.resize(300,200)
		self.centerWindow()
		
		# fill in the forms with config data	
		if config.remote_host: self.remote_host.setCurrentIndex(config.hosts.index(config.remote_host))
		self.username.setText(config.username)
		
		# describe the interface
		self.setWindowTitle('EasyVNC Connect to Server')
		
		self.password.returnPressed.connect(self.connect)
		
		self.connectButton = QPushButton("Connect")
		self.connectButton.clicked.connect(self.connect)
		
		self.exitButton = QPushButton("Exit")
		self.exitButton.clicked.connect(sys.exit)

		self.rowA = QHBoxLayout()
		self.rowA.addWidget(QLabel("VNC Host:"))
		self.rowA.addWidget(self.remote_host)

		self.rowB = QHBoxLayout()
		self.rowB.addWidget(QLabel("Username:"))
		self.rowB.addWidget(self.username)
		
		self.rowC = QHBoxLayout()
		self.rowC.addWidget(QLabel("Password:"))
		self.rowC.addWidget(self.password)
		
		self.hbox = QHBoxLayout()
		self.hbox.addWidget(QLabel("v. " + str(version.VERSION)))
		self.hbox.addStretch(1)
		self.hbox.addWidget(self.connectButton)
		self.hbox.addWidget(self.exitButton)
		
		self.vbox = QVBoxLayout()
		self.vbox.addLayout(self.rowA)
		self.vbox.addLayout(self.rowB)
		self.vbox.addLayout(self.rowC)
		self.vbox.addStretch(1)
		self.vbox.addLayout(self.hbox)
		
		self.setLayout(self.vbox)

	def connect(self):

		if self.password.text() == "" or self.username.text() == '' or str(self.remote_host.currentText) == '':
			QMessageBox.warning(self, "Incomplete Form", "You must supply a server name, username, and password.")
			return

		# save the form data into the config
		config.username = self.username.text()
		config.password = Password(self.password.text())
		config.remote_host = str(self.remote_host.currentText())
		
		self._mainwindow.console.append("%s@%s:%s" % (config.username, config.get_fqdn_remote_host(), config.remote_port))

		self.done(0)


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
				mainwindow.console.append('Incoming request to %s:%d failed: %s' % (remote_host, remote_port, repr(e)))
				return
			if chan is None:
				mainwindow.console.append('Incoming request to %s:%d was rejected by the SSH server.' % (remote_host, remote_port))
				return
			mainwindow.console.append('Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(), chan.getpeername(), (remote_host, remote_port)))
	
			# The tunnel is established, start send and receive buffer loop
			while True:
				r, w, x = select.select([self.request, chan], [], [])
				if self.request in r:
					data = self.request.recv(1024)
					size = len(data)
					mainwindow.txrate.addBytes(size)
					if size == 0:
						break
					chan.send(data)
				if chan in r:
					data = chan.recv(1024)
					size = len(data)
					mainwindow.rxrate.addBytes(size)
					if size == 0:
						break
					self.request.send(data)
			# exit of loop indicates that the connection is closed down
			# close down request and exit app
			chan.close()
			self.request.close()
			mainwindow.console.append('Tunnel closed ')
			app.quit()

	# Start the Threading TCP server using the above defined Handler. This is actually
	# the process that will forward packets between our side and the server
	forwardserver = socketserver.ThreadingTCPServer(('127.0.0.1', local_port), Handler)
	forwardserver.daemon_threads = True
	forwardserver.allow_reuse_address = True
	forwardserver.serve_forever()

class RateBar(QProgressBar):
	def __init__(self):
		QProgressBar.__init__(self)
		self.setRange(1,100000)
		stylesheet = """QProgressBar { border: 1px solid rgb(35, 167, 41); border-radius: 5px; text-align: center; }  """
		stylesheet += """QProgressBar::chunk { background-color: rgb(40, 196, 50); width: 10px; margin: 1px; }  """
		self.setStyleSheet(stylesheet)
		self.setFormat("%v bps")
		self.bytes = 0
		
	def addBytes(self, size):
		self.bytes += size

	def updateRate(self):
		self.setValue((self.value() + self.bytes ) / 2 )
		self.bytes = 0

class MainWindow(KQDialog):
	"""This class is the main interface for EasyVNC"""

	def __init__(self):
		KQDialog.__init__(self)
		
		self.setWindowTitle("EasyVNC Status")
		self.resize(600,400)
		self.centerWindow()
				
		self.console = QTextEdit()
		self.console.setReadOnly(True)

		self.rxrate = RateBar()
		self.txrate = RateBar()
				
		self.connected = 0
		self.connected_for = QLabel()

		# Set up a timer that will fire every 1000ms to update the status box with info 
		# from the forward_tunnel
		self._status_update_timer = QTimer(self)
		self._status_update_timer.setSingleShot(False)
		self._status_update_timer.timeout.connect(self._status_update)
		self._status_update_timer.start(1000)
				
		mainlayout = QVBoxLayout()

		progress_lo = QVBoxLayout()
		tx_progress_lo = QHBoxLayout()
		tx_progress_lo.addWidget(QLabel("TX"))
		tx_progress_lo.addWidget(self.txrate)
		progress_lo.addLayout(tx_progress_lo)

		rx_progress_lo = QHBoxLayout()
		rx_progress_lo.addWidget(QLabel("RX"))
		rx_progress_lo.addWidget(self.rxrate)
		progress_lo.addLayout(rx_progress_lo)

		connected_for_lo = QHBoxLayout()
		connected_for_lo.addWidget(QLabel("Connected"))
		connected_for_lo.addWidget(self.connected_for)
		connected_for_lo.addStretch(1)
		
		top_lo = QHBoxLayout()
		top_lo.addLayout(connected_for_lo)
		top_lo.addLayout(progress_lo)
		
		mainlayout.addLayout(top_lo)
		mainlayout.addWidget(self.console)
		self.setLayout(mainlayout)
		
		while True:
			self.hide()

			loginui = LoginUI(self)
			loginui.exec_()
			loginui.hide()

			loginui = None
			
			self.show()

			result = self.connect()
			if result == 0: 
				break
	
	def _status_update(self):
		self.update()
		QApplication.processEvents()
		if self.connected:
			self.connected_for.setText(str(time.strftime('%H:%M:%S', time.gmtime(time.time() - self.connected))))
			self.rxrate.updateRate()
			self.txrate.updateRate()

	
	def connect(self):
		
		# attempt to connect TCP socket to remote host, catch exceptions and throw warnings if there are problems	
		try:
			self.console.append("Opening connection to "+ config.get_fqdn_remote_host() + ":" + str(config.remote_port))
			self.console.update()
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((config.get_fqdn_remote_host(), config.remote_port))
			self.console.append("Connected.")
			self.connected = time.time()
			self.update()
		except Exception as e:
			if e.errno == 11001:
				QMessageBox.warning(self, "Connect Failed", "Could not connect because the remote_host (%s) would not resolve.\n  There may be a problem with your internet connection." % (remote_host))
				return(1)
			else:
				QMessageBox.warning(self, "Connect Failed", "Could not connect to remote SSH daemon %s: %s" % (config.get_fqdn_remote_host(), str(e)))
				return(1)
			return

		try:
			# start a new paramiko transport over TCP socket
			t = paramiko.Transport(sock)
			t.start_client()

			# authenticate 
			self.console.append("Authenticating to remote host as "+ config.username)
			t.auth_password(config.username, config.password)
	
			# authentication was successful, save the config
			config.save()
	
			# a new channel on the paramiko transport layer, ssh can have lots of channels 
			# may be interesting to add more channels, for remote shells and stuff
			chan = t.open_session()
			# fire up Xvnc on remote system and capture the output
			chan.exec_command(REMOTE_VNCCOMMAND)
			stdin = chan.makefile('wb')
			stdout = chan.makefile('rb')
			stderr = chan.makefile_stderr('rb')
			
			# expecting an integer from the remote_vnccommand script, to tell us what port to use
			vnc_port = int(stdout.readline()) + 5900
			self.console.append('Discovered VNC on port %i' % (vnc_port))

			# get a hint to tell us if we are compatible with the remote
			# compare remote_verison to local and if the remote is newer throw a warning
			remote_version = int(stdout.readline())
			self.console.append('Remote version %i' %(remote_version))
			if remote_version > version.VERSION:
				QMessageBox.warning(self,"Update Available", "There is a newer version of EasyVNC available for download.  Please download and install a new copy from sw.src.uchicago.edu in order to ensure continued use.")

			# get the new password for the remote session
			config.password = Password(stdout.readline().decode('utf-8').strip())
			self.console.append('Generated new VNC server secret: %s' %(config.password))

			# we are done with this control channel
			chan.close()

			# create a thread to forward packets to server
			thread.start_new_thread(forward_tunnel, (vnc_port, 'localhost', vnc_port, t, ))
			# create a thread to run the vnc client process
			thread.start_new_thread(self.vncprocess, (vnc_port,))

			return(0)
			
		except ValueError:
			QMessageBox.warning(self, "Server Error", "%s did not respond as expected to the command \n %s\nContact server support and report this error." % (config.remote_host, REMOTE_VNCCOMMAND))
			t.close()
			return(1)
		except paramiko.AuthenticationException:
			QMessageBox.warning(self, "Connect Failed", "Authentication failed :(  You provided an incorrect username or password for %s" % (config.remote_host))
			t.close()
			return(1)
		except Exception as e:
			QMessageBox.warning(self, "Unhandled Exception", "An application error has occured.\n Traceback: %s Dir:%s CMD: %s" % (traceback.format_exc(), config.scriptdir, config.vnccommand))
			app.quit()		

	def vncprocess(self, vnc_port):
		"""Start a blocking vnc subprocess, once the vnc process exits terminate the script."""
		
		vnccommand = config.get_vnccommand(vnc_port)
		self.console.append('vnccommand: ' + ' '.join(vnccommand))
		
		# start up the local vnc client
		vncprocess = subprocess.Popen(vnccommand, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		
			
		if os.name is not 'nt':
			applescript.tell.app('Screen Sharing', 'open location "vnc://%s:%s@localhost:%s"' % (config.username, config.password, vnc_port))
		
			
		vncprocess.stdin.close()
		# block until vnc exits, callback
		vncprocess.wait()

		self.console.append("VNC has quit.")
		config.cleanup_passwordfile()
		sys.exit()



if __name__ == '__main__':
	app = QApplication(sys.argv)
	mainwindow = MainWindow()
	sys.exit(app.exec_())
