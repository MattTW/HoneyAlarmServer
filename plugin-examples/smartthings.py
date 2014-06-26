import requests
import logging
from basePlugin import BasePlugin


class SmartthingsPlugin(BasePlugin):
    def __init__(self, configfile):
        # call ancestor for common setup
        super(SmartthingsPlugin, self).__init__(configfile)

        self._CALLBACKURL_BASE         = self.read_config_var('smartthings', 'callbackurl_base', 'not_provided', 'str')
        self._CALLBACKURL_APP_ID       = self.read_config_var('smartthings', 'callbackurl_app_id', 'not_provided', 'str')
        self._CALLBACKURL_ACCESS_TOKEN = self.read_config_var('smartthings', 'callbackurl_access_token', 'not_provided', 'str')
        self._CALLBACKURL_EVENT_CODES  = self.read_config_var('smartthings', 'callbackurl_event_codes', 'not_provided', 'str')

        #  URL example: ${callbackurl_base}/${callbackurl_app_id}/panel/${code}/${zoneorpartitionnumber}?access_token=${callbackurl_access_token}

        self._payload = {}

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

    def zoneStatus(self, zone, status):
        # Goofy for now but map open/closed to DSC event numbers 609 and 610 so we don't have to modify the Smartthings app for DSC
        if status == 'open':
          code = 609
        else:
          code = 610

        # Make the proper URL now
        self._urlbase = self._CALLBACKURL_BASE + "/" + self._CALLBACKURL_APP_ID + "/panel/" + str(code) + "/zone" + str(int(zone)) + "?access_token=" + self._CALLBACKURL_ACCESS_TOKEN
        logging.debug("URL: %s" % self._urlbase)
        self.postAndCheckresponse()

    def partitionStatus(self, partition, status):
        # Map HoneyAlarm states to DSC codes
        # NOTE: EXIT_ENTRY_DELAY is both exit and entry, currently maped to exit delay on DSC codes
        # how to fix that?
        dscCodes = { 'READY': 650,
            'NOT_READY': 651,
            'IN_ALARM': 654,
            'EXIT_ENTRY_DELAY': 656,
            'ARMED_STAY': 652,
            'ARMED_AWAY': 652,
            'ARMED_MAX': 652,
            'READY_BYPASS': 702
            }
        code = dscCodes[status]
        self._urlbase = self._config.CALLBACKURL_BASE + "/" + self._config.CALLBACKURL_APP_ID + "/panel/" + str(code) + "/partition" + str(partition) + "?access_token=" + self._config.CALLBACKURL_ACCESS_TOKEN
        logging.debug("URL: %s" % self._urlbase)
        self.postAndCheckresponse()

    def postAndCheckresponse(self):
        try:
            response = requests.get(self._urlbase, timeout=3)
            if response.status_code != requests.codes.ok:
                logging.error("Problem sending a smartthings notification, status code was %i, response content was %s" %
                              (response.status_code, response.text))
        except requests.exceptions.RequestException as e:
            logging.error("Error communicating with smartthings server.  Error number was %i, error text is %s", e.errno, e.strerror)

