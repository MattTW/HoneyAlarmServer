import requests
import ConfigParser
import logging
from basePlugin import BasePlugin
from requests.auth import HTTPDigestAuth

class sssPlugin(BasePlugin):
    def __init__(self, configfile):
        #call ancestor for common setup
        super(sssPlugin, self).__init__(configfile)

        self._SERVER = self.read_config_var('sss', 'server', 'localhost', 'str')
        self._PORT = self.read_config_var('sss', 'port', 5000, 'int')
        self._USERNAME = self.read_config_var('sss', 'user', 'user', 'str')
        self._PASSWORD = self.read_config_var('sss', 'password', 'pass', 'str')
        self._API_VERSION = self.read_config_var('sss','apiversion','2','str')

        self._rootURL = 'http://%s:%i/webapi' % (self._SERVER, self._PORT)
        self._session = requests.Session();
        self.signonSS()

    def armedAway(self,user):
      self.cameraEnable(True)

    def armedHome(self,user):
      self.cameraEnable(False)

    def disarmedHome(self,user):
      self.cameraEnable(False)

    def disarmedAway(self,user):
      #only disable cameras when disarmed with non-guest code
      if not self.isGuest(user):
          self.cameraEnable(False)

    def alarmTriggered(self,alarmDescription, zone):
      self.cameraRecord(True)

    def alarmCleared(self,alarmDescription, zone):
      self.cameraRecord(False)

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
        logging.error("Unsuccessful login to Synology Surveillance Station.  url:'%s' status code: %s response:'%s'" % (r.url,r.status_code,r.json()))

    def cameraRecord(self, shouldRecord):
      for camera in self.listCameras():
        recordAction = 'start' if shouldRecord else 'stop'
        params = {'api' : 'SYNO.SurveillanceStation.ExternalRecording',
                       'method' : 'Record',
                       'version' : self._API_VERSION,
                       'cameraId' : str(camera['id']),
                       'action' : recordAction}
        r = self._session.get(self._rootURL + '/SurveillanceStation/extrecord.cgi',params = params)
        self.checkResponse(r,'Record ' + recordAction)

    def cameraEnable(self, shouldEnable):
      for camera in self.listCameras():
        enableAction = 'cameraEnable' if shouldEnable else 'cameraDisable'
        params = {     'idList' : str(camera['id']),
                       'action' : enableAction}
        #undocumented, just snooped synology's web ui
        r = self._session.get('http://%s:%i/webman/3rdparty/SurveillanceStation/cgi/camera.cgi' % (self._SERVER, self._PORT),params = params)
        self.checkResponse(r,'Enable ' + enableAction)

    def listCameras(self):
        params = {'api' : 'SYNO.SurveillanceStation.Camera',
                       'method' : 'List',
                       'version' : self._API_VERSION}
        r = self._session.get(self._rootURL + '/SurveillanceStation/camera.cgi',params = params)
        if not self.checkResponse(r,'List Cameras'): return
        return r.json()['data']['cameras']

    def checkResponse(self,response,action):
        if not response.json()['success']:
            logging.error("Unsuccessful %s to Synology Surveillance Station.  url:'%s' status code: %s response:'%s'" % (action,response.url,response.status_code,response.json()))
            return False
        return True
