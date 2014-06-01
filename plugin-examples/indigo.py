import requests
from basePlugin import BasePlugin
from requests.auth import HTTPDigestAuth


class IndigoPlugin(BasePlugin):
    def __init__(self, configfile):
        # call ancestor for common setup
        super(IndigoPlugin, self).__init__(configfile)

        self._SERVER = self.read_config_var('indigo', 'server', 'localhost', 'str')
        self._PORT = self.read_config_var('indigo', 'port', 8176, 'int')
        self._USERNAME = self.read_config_var('indigo', 'user', 'user', 'str')
        self._PASSWORD = self.read_config_var('indigo', 'password', 'pass', 'str')

        self._urlbase = 'http://%s:%i/variables/' % (self._SERVER, self._PORT)
        self._session = requests.Session()

    # Update Indigo variables based on alarm event
    def armedAway(self, user):
        self._session.put(self._urlbase + 'alarmGuestMode', data={'value': str(self.isGuest(user))}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))
        self._session.put(self._urlbase + 'alarmArmedAway', data={'value': str(True)}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))

    def armedHome(self, user):
        self._session.put(self._urlbase + 'alarmGuestMode', data={'value': str(self.isGuest(user))}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))
        self._session.put(self._urlbase + 'alarmArmedHome', data={'value': str(True)}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))

    def disarmedAway(self, user):
        self._session.put(self._urlbase + 'alarmGuestMode', data={'value': str(self.isGuest(user))}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))
        self._session.put(self._urlbase + 'alarmArmedAway', data={'value': str(False)}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))

    def disarmedHome(self, user):
        self._session.put(self._urlbase + 'alarmGuestMode', data={'value': str(self.isGuest(user))}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))
        self._session.put(self._urlbase + 'alarmArmedHome', data={'value': str(False)}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))

    def alarmTriggered(self, alarmDescription, zone):
        self._session.put(self._urlbase + 'alarmTriggered', data={'value': str(True)}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))

    def alarmCleared(self, alarmDescription, zone):
        rself._session.put(self._urlbase + 'alarmTriggered', data={'value': str(False)}, auth=HTTPDigestAuth(self._USERNAME,self._PASSWORD))
