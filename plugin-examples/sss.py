import requests
import logging
from basePlugin import BasePlugin


class sssPlugin(BasePlugin):
    def __init__(self, configfile):
        # call ancestor for common setup
        super(sssPlugin, self).__init__(configfile)

        self._SERVER = self.read_config_var('sss', 'server', 'localhost', 'str')
        self._PORT = self.read_config_var('sss', 'port', 5000, 'int')
        self._USERNAME = self.read_config_var('sss', 'user', 'user', 'str')
        self._PASSWORD = self.read_config_var('sss', 'password', 'pass', 'str')
        self._API_VERSION = self.read_config_var('sss', 'apiversion', '2', 'str')

        self._rootURL = 'http://%s:%i/webapi' % (self._SERVER, self._PORT)
        self._session = requests.Session()
        self._signedon = False

    def armedAway(self, user):
        self.cameraEnable(True)

    def armedHome(self, user):
        self.cameraEnable(False)

    def disarmedHome(self, user):
        self.cameraEnable(False)

    def disarmedAway(self, user):
        # only disable cameras when disarmed with non-guest code
        if not self.isGuest(user):
            self.cameraEnable(False)

    def alarmTriggered(self, alarmDescription, zone):
        self.cameraRecord(True)

    def alarmCleared(self, alarmDescription, zone):
        self.cameraRecord(False)

    def signonSS(self):
        loginParams = {'account': self._USERNAME,
                       'passwd': self._PASSWORD,
                       'api': 'SYNO.API.Auth',
                       'method': 'Login',
                       'version': self._API_VERSION,
                       'session': 'SurveillanceStation'}
        if self.getAndCheckResponse(self._rootURL + "/auth.cgi", params=loginParams, 'login'):
            self._signedon = True

    def cameraRecord(self, shouldRecord):
        for camera in self.listCameras():
            recordAction = 'start' if shouldRecord else 'stop'
            params = {'api': 'SYNO.SurveillanceStation.ExternalRecording',
                      'method': 'Record',
                      'version': self._API_VERSION,
                      'cameraId': str(camera['id']),
                      'action': recordAction}
            self.getAndCheckResponse(self._rootURL + '/SurveillanceStation/extrecord.cgi', params=params, 'Record ' + recordAction)

    def cameraEnable(self, shouldEnable):
        cameras = self.listCameras()
        if not cameras:
            logging.error("Could not retrieve list of cameras to enable!")
            return
        for camera in self.listCameras():
            enableAction = 'cameraEnable' if shouldEnable else 'cameraDisable'
            params = {'idList': str(camera['id']),
                      'action': enableAction}
            # undocumented, just snooped synology's web ui
            self.getAndCheckResponse('http://%s:%i/webman/3rdparty/SurveillanceStation/cgi/camera.cgi' % (self._SERVER, self._PORT), params=params, 'Enable ' + enableAction)

    def listCameras(self):
        params = {'api': 'SYNO.SurveillanceStation.Camera',
                  'method': 'List',
                  'version': self._API_VERSION}
        if not getAndCheckResponse(self._rootURL + '/SurveillanceStation/camera.cgi', params=params, 'List Cameras'): return False
        return r.json()['data']['cameras']

    def getAndCheckResponse(self, url, params, action):
        if not self._signedon and action != 'login': self.signonSS()
        try:
            response = self._session.get(url, params, timeout=3)
            if response.status_code != requests.codes.ok or if not response.json()['success']:
                logging.error("Unsuccessful %s to Synology Surveillance Station. url: '%s' status code was %i, response content was %s",
                              action, response.url, response.status_code, response.text)
                return False
        except requests.exceptions.RequestException as e:
            logging.error("Exception performing action %s to Synology Surveillance Station.  Error number was %i, error text is %s", action, e.errno, e.strerror)
            return False

        return True
