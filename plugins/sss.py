import requests
import ConfigParser
from basePlugin import BasePlugin
from requests.auth import HTTPDigestAuth

class sssPlugin(BasePlugin):
    def __init__(self, configfile):
        print("config file name is " + configfile)
        self._config = ConfigParser.ConfigParser()
        self._config.read(configfile)

        self._SERVER = self.read_config_var('sss', 'server', 'localhost', 'str')
        self._PORT = self.read_config_var('sss', 'port', 5000, 'int')
        self._USERNAME = self.read_config_var('sss', 'user', 'user', 'str')
        self._PASSWORD = self.read_config_var('sss', 'password', 'pass', 'str')
        self._API_VERSION = self.read_config_var('sss','apiVersion','2','str')

        self._rootURL = 'http://%s:%i/webapi' % (self._SERVER, self._PORT)
        self._session = requests.Session();
        self.signonSS()
        self.notifySS(True)

    def alarmTriggered(self):
      self.notifySS(True)

    def alarmCleared(self):
      self.notifySS(False)

    def signonSS(self):
      loginParams = {'account' : self._USERNAME,
                     'passwd' : self._PASSWORD,
                     'api' : 'SYNO.API.Auth',
                     'method' : 'Login',
                     'version' : self._API_VERSION,
                     'session' : 'SurveillanceStation'}
      r = self._session.get(self._rootURL + "/auth.cgi", params = loginParams)
      self.checkResponse(r,'login')
      if not r.json()['success']:
        print("Unsuccessful login to Synology Surveillance Station.  url:'%s' status code: %s response:'%s'" % (r.url,r.status_code,r.json()))

    def notifySS(self, isInAlarm):
      params = {'api' : 'SYNO.SurveillanceStation.Camera',
                     'method' : 'List',
                     'version' : self._API_VERSION}
      r = self._session.get(self._rootURL + '/SurveillanceStation/camera.cgi',params = params)
      if not self.checkResponse(r,'List Cameras'): return


      cameras = r.json()['data']['cameras']
      for camera in cameras:
        recordAction = 'start' if isInAlarm else 'stop'
        params = {'api' : 'SYNO.SurveillanceStation.ExternalRecording',
                       'method' : 'Record',
                       'version' : self._API_VERSION,
                       'cameraId' : str(camera['id']),
                       'action' : recordAction}
        r = self._session.get(self._rootURL + '/SurveillanceStation/extrecord.cgi',params = params)
        self.checkResponse(r,'Record ' + recordAction)

    def checkResponse(self,response,action):
        if not response.json()['success']:
            print("Unsuccessful %s to Synology Surveillance Station.  url:'%s' status code: %s response:'%s'" % (action,response.url,response.status_code,response.json()))
            return False
        return True
