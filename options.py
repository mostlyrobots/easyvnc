class Options:

	def __init__(self):
				self.homedir = os.path.expanduser("~")
		if os.name == 'nt':
			if 'PROGRAMFILES(X86)' in os.environ:
				self.vnccommand = ['vncviewer_64.exe']
			else:
				self.vnccommand = ['vncviewer_32.exe']
			self.username.set(os.environ.get('USERNAME'))
			self.configfile = self.homedir + '\\mvnc.cfg'
		else:
			self.configfile = self.homedir + '/.mvnc.cfg'
			self.vnccommand = ['./vncviewer.app/Contents/MacOS/vncviewer']
			self.username.set(os.environ.get('LOGNAME'))
	
		self.load()

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
