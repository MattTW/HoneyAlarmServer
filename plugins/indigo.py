import requests
import ConfigParser
from basePlugin import BasePlugin
from requests.auth import HTTPDigestAuth

class IndigoPlugin(BasePlugin):
    def __init__(self, configfile):
        print("config file name is " + configfile)
        self._config = ConfigParser.ConfigParser()
        self._config.read(configfile)

        self._SERVER = self.read_config_var('indigo', 'server', 'localhost', 'str')
        self._PORT = self.read_config_var('indigo', 'port', 8176, 'int')
        self._USERNAME = self.read_config_var('indigo', 'user', 'user', 'str')
        self._PASSWORD = self.read_config_var('indigo', 'password', 'pass', 'str')

        self._urlbase = 'http://%s:%i/variables/' % (self._SERVER,self._PORT)
        self._auth = HTTPDigestAuth(self._USERNAME,self._PASSWORD)

    #Update Indigo variables based on alarm event
    def armedAway(self):
        r = requests.put(self._urlbase + 'alarmArmedAway', data={'value': str(True)}, auth=self._auth)

    def armedHome(self):
        r = requests.put(self._urlbase + 'alarmArmedHome', data={'value': str(True)}, auth=self._auth)


    def armedInstant(self):
        r = requests.put(self._urlbase + 'alarmArmedAway', data={'value': str(True)}, auth=self._auth)


    def disarmed(self):
        r = requests.put(self._urlbase + 'alarmArmedAway', data={'value': str(False)}, auth=self._auth)
        r = requests.put(self._urlbase + 'alarmArmedHome', data={'value': str(False)}, auth=self._auth)


    def alarmTriggered(self):
        r = requests.put(self._urlbase + 'alarmTriggered', data={'value': str(True)}, auth=self._auth)


    def alarmCleared(self):
        r = requests.put(self._urlbase + 'alarmTriggered', data={'value': str(False)}, auth=self._auth)
