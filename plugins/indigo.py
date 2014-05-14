import requests
import ConfigParser
from basePlugin import BasePlugin
from requests.auth import HTTPDigestAuth

class IndigoPlugin(BasePlugin):
    def __init__(self, configfile):
        print("config file name is " + configfile)
        self._config = ConfigParser.ConfigParser()
        self._config.read(configfile)

        self.SERVER = self.read_config_var('indigo', 'server', 'localhost', 'str')
        self.PORT = self.read_config_var('indigo', 'port', 8176, 'int')
        self.USERNAME = self.read_config_var('indigo', 'user', 'user', 'str')
        self.PASSWORD = self.read_config_var('indigo', 'password', 'pass', 'str')


    def armedAway(self):
      self.notifyIndigo(True)
      return

    def armedHome(self):
      return

    def armedInstant(self):
      return

    def disarmed(self):
      self.notifyIndigo(False)
      return

    def notifyIndigo(self, armedState):
      payload = {'value': str(armedState)}
      r = requests.put('http://' + self.SERVER + ':' + str(self.PORT) + '/variables/alarmArmed', data=payload, auth=HTTPDigestAuth(self.USERNAME,self.PASSWORD))
