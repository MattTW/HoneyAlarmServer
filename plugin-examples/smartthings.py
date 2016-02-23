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
        self._urlbase = ""
        # Tracking list for open zones
        self._openzones = []

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
          # Track open zones, only append if it's not already in our list
          if zone not in self._openzones:
            self._openzones.append(zone)
          code = 609
        else:
          # Track closed zones, remove from our list if it was there
          if zone in self._openzones:
            self._openzones.remove(zone)
          code = 610

        # Make the proper URL now
        self._urlbase = self._CALLBACKURL_BASE + "/" + self._CALLBACKURL_APP_ID + "/panel/" + str(code) + "/" + str(int(zone)) + "?access_token=" + self._CALLBACKURL_ACCESS_TOKEN
        logging.debug("URL: %s" % self._urlbase)
        self.postAndCheckresponse()

    def partitionStatus(self, partition, status):
        # Map HoneyAlarm states to DSC codes
        # NOTE: EXIT_ENTRY_DELAY is both exit and entry, currently maped to exit delay on DSC codes
        # how to fix that?

        # Better error checking..
        if partition == '' or status == '':
          logging.debug("Partition or status was empty, skipping this event. NOTE: This may be an error, if so we need to get a proper status for whatever even this is to fix it")
          return
        else:
          logging.debug("Status code was: %s", status)

        dscCodes = {
            'READY': 650,
            'NOT_READY': 651,
            'ALARM_IN_MEMORY': 654,
            'IN_ALARM': 654,
            'EXIT_ENTRY_DELAY': 656,
            'ARMED_STAY': 652,
            'ARMED_AWAY': 652,
            'ARMED_MAX': 652,
            'READY_BYPASS': 702
            }

        # Better error handling..
        try:
          dscCodes[status]
        except:
          logging.debug("Status code we received was not in the map, please add it and map to a proper number if you want to act on it")
          return

        # If system sent us the READY_BYPASS signal then all zones are closed so dump our list to close them all
        # this is mainly due to issues with the Ademco/Vista panels and the Envizalink TPI not always reporting close events.
        if status == 'READY_BYPASS' or status == 'READY':
          for zone in self._openzones:
            # Send close code 610 for each zone in the list
            self._urlbase = self._CALLBACKURL_BASE + "/" + self._CALLBACKURL_APP_ID + "/panel/610/" + str(int(zone)) + "?access_token=" + self._CALLBACKURL_ACCESS_TOKEN
            logging.debug("URL: %s" % self._urlbase)
            self.postAndCheckresponse()

          # Delete everything in the list now so we don't close them again unless they open again
          del self._openzones[:]

        # If we made it here we should be OK to lookup and send our notification to Smartthings
        code = dscCodes[status]
        self._urlbase = self._CALLBACKURL_BASE + "/" + self._CALLBACKURL_APP_ID + "/panel/" + str(code) + "/" + str(partition) + "?access_token=" + self._CALLBACKURL_ACCESS_TOKEN
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

