import requests
import ConfigParser
import logging
from basePlugin import BasePlugin

class PushoverPlugin(BasePlugin):
    def __init__(self, configfile):
        #call ancestor for common setup
        super(PushoverPlugin, self).__init__(configfile)

        self._SERVER = self.read_config_var('pushover', 'server', 'api.pushover.net', 'str')
        self._PORT = self.read_config_var('pushover', 'port', 443, 'int')
        self._APP_TOKEN = self.read_config_var('pushover', 'apptoken', 'not_provided', 'str')
        self._USER_KEY = self.read_config_var('pushover', 'userkey', 'not_provided', 'str')

        self._urlbase = 'https://%s:%i/1/messages.json' % (self._SERVER,self._PORT)
        self._payload = { 'token' : self._APP_TOKEN,
                          'user' : self._USER_KEY
        }

    def armedAway(self,user):
        self._payload['message'] = "Security Alarm armed away by " + user
        r = requests.post(self._urlbase, data=self._payload)
        self.checkresponse(r)

    def armedHome(self,user):
        self._payload['message'] = "Security Alarm armed home by " + user
        r = requests.post(self._urlbase, data=self._payload)
        self.checkresponse(r)

    def disarmedAway(self,user):
        self._payload['message'] = "Security Alarm disarmed from away status by " + user
        r = requests.post(self._urlbase, data=self._payload)
        self.checkresponse(r)

    def disarmedHome(self,user):
        self._payload['message'] = "Security Alarm disarmed from home status by " + user
        r = requests.post(self._urlbase, data=self._payload)
        self.checkresponse(r)

    def alarmTriggered(self,zone):
        self._payload['message'] = "Security Alarm triggered at zone " + zone
        r = requests.post(self._urlbase, data=self._payload)
        self.checkresponse(r)

    def alarmCleared(self,zone):
        self._payload['message'] = "Security Alarm cleared at zone " + zone
        r = requests.post(self._urlbase, data=self._payload)
        self.checkresponse(r)

    def checkresponse(self,response):
        if response.status_code != requests.codes.ok:
            logging.error("Problem sending a pushover notification, status code was %i, response content was %s" % (response.status_code,response.text))
