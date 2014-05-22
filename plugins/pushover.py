import requests
import ConfigParser
from basePlugin import BasePlugin

class PushoverPlugin(BasePlugin):
    def __init__(self, configfile):
        self._config = ConfigParser.ConfigParser()
        self._config.read(configfile)

        self._SERVER = self.read_config_var('pushover', 'server', 'api.pushover.net', 'str')
        self._PORT = self.read_config_var('pushover', 'port', 443, 'int')
        self._APP_TOKEN = self.read_config_var('pushover', 'apptoken', 'not_provided', 'str')
        self._USER_KEY = self.read_config_var('pushover', 'userkey', 'not_provided', 'str')

        self._urlbase = 'https://%s:%i/1/messages.json' % (self._SERVER,self._PORT)
        self._payload = { 'token' : self._APP_TOKEN,
                          'user' : self._USER_KEY
        }

    #Update Indigo variables based on alarm event
    def armedAway(self,user):
        self._payload['message'] = "Security Alarm armed away by " + user
        r = requests.post(self._urlbase, data=self._payload)
        if r.status_code != requests.codes.ok:
            print("Problem sending a pushover notification, status code was %i, response content was %s" % (r.status_code,r.text))


    def armedHome(self,user):
        self._payload['message'] = "Security Alarm armed home by " + user
        r = requests.post(self._urlbase, data=self._payload)
        if r.status_code != requests.codes.ok:
            print("Problem sending a pushover notification, status code was %i, response content was %s" % (r.status_code,r.text))


    def disarmedAway(self,user):
        self._payload['message'] = "Security Alarm disarmed from away status by " + user
        r = requests.post(self._urlbase, data=self._payload)
        if r.status_code != requests.codes.ok:
            print("Problem sending a pushover notification, status code was %i, response content was %s" % (r.status_code,r.text))

    def disarmedHome(self,user):
        self._payload['message'] = "Security Alarm disarmed from home status by " + user
        r = requests.post(self._urlbase, data=self._payload)
        if r.status_code != requests.codes.ok:
            print("Problem sending a pushover notification, status code was %i, response content was %s" % (r.status_code,r.text))

    def alarmTriggered(self,zone):
        self._payload['message'] = "Security Alarm triggered at zone " + zone
        r = requests.post(self._urlbase, data=self._payload)
        if r.status_code != requests.codes.ok:
            print("Problem sending a pushover notification, status code was %i, response content was %s" % (r.status_code,r.text))

    def alarmCleared(self,zone):
        self._payload['message'] = "Security Alarm cleared at zone " + zone
        r = requests.post(self._urlbase, data=self._payload)
        if r.status_code != requests.codes.ok:
            print("Problem sending a pushover notification, status code was %i, response content was %s" % (r.status_code,r.text))
