import requests
import logging
from basePlugin import BasePlugin


class PushoverPlugin(BasePlugin):
    def __init__(self, configfile):
        # call ancestor for common setup
        super(PushoverPlugin, self).__init__(configfile)

        self._SERVER = self.read_config_var('pushover', 'server', 'api.pushover.net', 'str')
        self._PORT = self.read_config_var('pushover', 'port', 443, 'int')
        self._APP_TOKEN = self.read_config_var('pushover', 'apptoken', 'not_provided', 'str')
        self._USER_KEY = self.read_config_var('pushover', 'userkey', 'not_provided', 'str')

        self._urlbase = 'https://%s:%i/1/messages.json' % (self._SERVER, self._PORT)
        self._payload = {'token': self._APP_TOKEN,
                         'user': self._USER_KEY}

    def armedAway(self, user):
        self._payload['message'] = "Security system armed away by " + user
        self.postAndCheckresponse()

    def armedHome(self, user):
        self._payload['message'] = "Security system armed home by " + user
        self.postAndCheckresponse()

    def disarmedAway(self, user):
        self._payload['message'] = "Security system disarmed from away status by " + user
        self.postAndCheckresponse()

    def disarmedHome(self, user):
        self._payload['message'] = "Security system disarmed from home status by " + user
        self.postAndCheckresponse()

    def alarmTriggered(self, alarmDescription, zone):
        self._payload['message'] = "Security Alarm triggered at %s. Description: %s" % (zone, alarmDescription)
        self._payload['priority'] = "2"
        self._payload['retry'] = "30"
        self._payload['expire'] = '86400'
        self._payload['sound'] = 'siren'
        # TODO utilize receipt in response to for acknowledgement callback
        # TODO utilize supplementary URL to open eyez-on portal quickly.
        self.postAndCheckresponse()

    def alarmCleared(self, alarmDescription, zone):
        self._payload['message'] = "Security Alarm cleared at %s. Description: %s" % (zone, alarmDescription)
        self.postAndCheckresponse()

    def envisalinkUnresponsive(self, condition):
        self._payload['message'] = "Envisalink became unresponse. %s" % condition
        self.postAndCheckresponse()

    def postAndCheckresponse(self):
        try:
            response = requests.post(self._urlbase, data=self._payload, timeout=3)
            if response.status_code != requests.codes.ok:
                logging.error("Problem sending a pushover notification, status code was %i, response content was %s" %
                              (response.status_code, response.text))
        except requests.exceptions.RequestException as e:
            logging.error("Error communicating with Pushover server.  Error number was %i, error text is %s", e.errno, e.strerror)
