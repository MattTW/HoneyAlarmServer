#!/usr/bin/python
# Alarm Server
# Supporting Envisalink 2DS/3
# Original version for DSC Written by donnyk+envisalink@gmail.com,
# lightly improved by leaberry@gmail.com
# Honeywell version adapted by matt.weinecke@gmail.com
#
# This code is under the terms of the GPL v3 license.

import os
import sys
import json
import getopt
import logging
import re
import urlparse

from twisted.internet import reactor
from twisted.web.resource import Resource, NoResource
from twisted.web.server import Site
from twisted.web.static import File
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.task import LoopingCall
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.python import log

from envisalinkdefs import *
from plugins.basePlugin import BasePlugin
from baseConfig import BaseConfig
from datetime import datetime
from datetime import timedelta

ALARMSTATE = {'version': 0.2, 'arm': False, 'disarm': False, 'cancel': False}
MAXPARTITIONS = 16
MAXZONES = 128
MAXALARMUSERS = 47
shuttingdown = False


class AlarmServerConfig(BaseConfig):
    def __init__(self, configfile):
        # call ancestor for common setup
        super(self.__class__, self).__init__(configfile)

        self.LOGURLREQUESTS = self.read_config_var('alarmserver',
                                                   'logurlrequests',
                                                   True, 'bool')
        self.LISTENTYPE = self.read_config_var('alarmserver',
                                               'listentype',
                                               'tcp', 'str')
        self.LISTENPORT = self.read_config_var('alarmserver',
                                               'listenport',
                                               8111, 'int')
        self.CERTFILE = self.read_config_var('alarmserver',
                                             'certfile',
                                             'server.crt', 'str')
        self.KEYFILE = self.read_config_var('alarmserver',
                                            'keyfile',
                                            'server.key', 'str')
        self.MAXEVENTS = self.read_config_var('alarmserver',
                                              'maxevents',
                                              10, 'int')
        self.MAXALLEVENTS = self.read_config_var('alarmserver',
                                                 'maxallevents',
                                                 100, 'int')
        self.ENVISALINKVERSION = self.read_config_var('envisalink',
                                                      'version',
                                                      3, 'int')
        self.ENVISALINKHOST = self.read_config_var('envisalink',
                                                   'host',
                                                   'envisalink', 'str')
        self.ENVISALINKPORT = self.read_config_var('envisalink',
                                                   'port',
                                                   4025, 'int')
        self.ENVISALINKPASS = self.read_config_var('envisalink',
                                                   'pass',
                                                   'user', 'str')
        self.ENVISAPOLLINTERVAL = self.read_config_var('envisalink',
                                                       'pollinterval',
                                                       0, 'int')
        self.ENVISAZONEDUMPINTERVAL = self.read_config_var('envisalink',
                                                           'zonedumpinterval',
                                                           60, 'int')
        self.ENVISAKEYPADUPDATEINTERVAL = self.read_config_var('envisalink',
                                                           'keypadupdateinterval',
                                                           60, 'int')
        self.ENVISACOMMANDTIMEOUT = self.read_config_var('envisalink',
                                                         'commandtimeout',
                                                         30, 'int')
        self.ENVISAKPEVENTTIMEOUT = self.read_config_var('envisalink',
                                                         'kpeventtimeout',
                                                         45, 'int')
        self.ALARMCODE = self.read_config_var('envisalink',
                                              'alarmcode',
                                              1111, 'int')
        self.LOGFILE = self.read_config_var('alarmserver',
                                            'logfile',
                                            '', 'str')
        self.LOGLEVEL = self.read_config_var('alarmserver',
                                             'loglevel',
                                             'DEBUG', 'str')

        self.PARTITIONNAMES = {}
        for i in range(1, MAXPARTITIONS + 1):
            self.PARTITIONNAMES[i] = self.read_config_var('alarmserver',
                                                          'partition' + str(i),
                                                          False, 'str', True)

        self.ZONENAMES = {}
        for i in range(1, MAXZONES + 1):
            self.ZONENAMES[i] = self.read_config_var('alarmserver',
                                                     'zone' + str(i),
                                                     False, 'str', True)

        self.ALARMUSERNAMES = {}
        for i in range(1, MAXALARMUSERS + 1):
            self.ALARMUSERNAMES[i] = self.read_config_var('alarmserver',
                                                          'user' + str(i),
                                                          False, 'str', True)

    def initialize_alarmstate(self):
        ALARMSTATE['zone'] = {'lastevents': []}
        for zoneNumber in self.ZONENAMES.keys():
            zoneName = self.ZONENAMES[zoneNumber]
            if not zoneName: continue
            ALARMSTATE['zone'][zoneNumber] = {'name': zoneName, 'lastevents': [],
                                              'lastfault': 'Last Closed longer ago than I can remember',
                                              'status': {'open': False, 'fault': False, 'alarm': False, 'tamper': False}
                                              }

        ALARMSTATE['partition'] = {'lastevents': []}
        for pNumber in self.PARTITIONNAMES.keys():
            pName = self.PARTITIONNAMES[pNumber]
            if not pName: continue
            ALARMSTATE['partition'][pNumber] = {'name': pName, 'lastevents': [],
                                                'lastfault': 'Last Closed longer ago than I can remember',
                                                'status': {'alarm': False, 'alarm_in_memory': False, 'armed_away': False,
                                                           'ac_present': False, 'armed_bypass': False, 'chime': False,
                                                           'armed_zero_entry_delay': False, 'alarm_fire_zone': False,
                                                           'trouble': False, 'ready': False, 'fire': False,
                                                           'armed_stay': False, 'alpha': False, 'beep': False}}


class EnvisalinkClientFactory(ReconnectingClientFactory):

    def __init__(self, config):
        self._config = config

    def buildProtocol(self, addr):
        logging.debug("%s connection estblished to %s:%s", addr.type, addr.host, addr.port)
        logging.debug("resetting connection delay")
        self.resetDelay()
        self.envisalinkClient = EnvisalinkClient(self._config)
        # check on the state of the envisalink connection repeatedly
        self._currentLoopingCall = LoopingCall(self.envisalinkClient.check_alive)
        self._currentLoopingCall.start(1)
        return self.envisalinkClient

    def startedConnecting(self, connector):
        logging.debug("Started to connect to Envisalink...")

    def clientConnectionLost(self, connector, reason):
        if not shuttingdown:
            logging.debug('Lost connection to Envisalink.  Reason: %s', str(reason))
            if hasattr(self, "_currentLoopingCall"):
                try:
                    self._currentLoopingCall.stop()
                except:
                    logging.error("Error trying to stop looping call, ignoring...")
            ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        logging.debug('Connection failed to Envisalink. Reason: %s', str(reason))
        if hasattr(self, "_currentLoopingCall"):
            try:
                self._currentLoopingCall.stop()
            except:
                logging.error("Error trying to stop looping call, ignoring...")
        ReconnectingClientFactory.clientConnectionFailed(self, connector,
                                                         reason)


class EnvisalinkClient(LineOnlyReceiver):
    def __init__(self, config):
        # Are we logged in?
        self._loggedin = False

        self._has_partition_state_changed = False

        # Set config
        self._config = config

        # find plugins and load/config them
        self.plugins = []
        pluginClasses = BasePlugin.find_subclasses("./plugins/")
        for plugin in pluginClasses:
            plugincfg = "./plugins/" + plugin.__name__ + ".cfg"
            self.plugins.append(plugin(plugincfg))

        self._commandinprogress = False
        now = datetime.now()
        self._lastkeypadupdate = now
        self._lastpoll = now
        self._lastzonedump = now
        self._lastpartitionupdate = now
        self._lastcommand = now
        self._lastcommandresponse = now

    def logout(self):
        logging.debug("Ending Envisalink client connection...")
        self._loggedin = False
        if hasattr(self, 'transport'):
            self.transport.loseConnection()

    def send_data(self, data):
        logging.debug('TX > ' + data)
        self.sendLine(data)

    def check_alive(self):
        if self._loggedin:
            now = datetime.now()

            # if too much time has passed since command was sent without a
            # response, something is wrong
            delta = now - self._lastcommand
            if self._lastcommandresponse < self._lastcommand and delta > timedelta(seconds=self._config.ENVISACOMMANDTIMEOUT):
                message = "Timed out waiting for command response, resetting connection..."
                logging.error(message)
                for plugin in self.plugins:
                    plugin.envisalinkUnresponsive(message)
                self.logout()
                return

            # is it time to poll again?
            if self._config.ENVISAPOLLINTERVAL != 0:
                delta = now - self._lastpoll
                if delta > timedelta(seconds=self._config.ENVISAPOLLINTERVAL) and not self._commandinprogress:
                    self._lastpoll = now
                    self.send_command('00', '')

            # is it time to dump zone states again?
            delta = now - self._lastzonedump
            if delta > timedelta(seconds=self._config.ENVISAZONEDUMPINTERVAL) and not self._commandinprogress:
                self._lastzonedump = now
                self.dump_zone_timers()

            # if 10 seconds have passed and we haven't received a keypad update,
            # something is wrong
            delta = now - self._lastkeypadupdate
            if delta > timedelta(seconds=self._config.ENVISAKPEVENTTIMEOUT):
                # reset connection
                message = "No recent keypad updates from envisalink, resetting connection..."
                logging.error(message)
                for plugin in self.plugins:
                    plugin.envisalinkUnresponsive(message)
                self.logout()
                return


# application commands to the envisalink

    def send_command(self, code, data):
        if not self._loggedin:
            logging.error("Not connected to Envisalink - ignoring last command")
            return
        if self._commandinprogress:
            logging.error("Command already in progress - ignoring last command")
            return
        self._commandinprogress = True
        self._lastcommand = datetime.now()
        to_send = '^' + code + ',' + data + '$'
        self.send_data(to_send)

    def change_partition(self, partitionNumber):
        if partitionNumber < 1 or partitionNumber > 8:
            logging.error("Invalid Partition Number %i specified when trying to change partition, ignoring.", partitionNumber)
            return
        self.send_command('01', str(partitionNumber))

    def dump_zone_timers(self):
        self.send_command('02', '')

    def keypresses_to_default_partition(self, keypresses):
        self.send_data(keypresses)

    def keypresses_to_partition(self, partitionNumber, keypresses):
        for char in keypresses:
            to_send = '^03,' + str(partitionNumber) + ',' + char + '$'
            logging.debug('TX > ' + to_send)
            self.sendLine(to_send)

    # network communication callbacks

    def connectionMade(self):
        logging.info("Connected to %s:%i" % (self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))

    def connectionLost(self, reason):
        if not shuttingdown:
            logging.info("Disconnected from %s:%i, reason was %s" % (self._config.ENVISALINKHOST, self._config.ENVISALINKPORT, reason.getErrorMessage()))
            if self._loggedin:
                self.logout()

    def lineReceived(self, input):
        if input != '':

            logging.debug('----------------------------------------')
            logging.debug('RX < ' + input)
            if input[0] in ("%", "^"):
                # keep first sentinel char to tell difference between tpi and
                # Envisalink command responses.  Drop the trailing $ sentinel.
                inputList = input[0:-1].split(',', 5)
                code = inputList[0]
                data = ','.join(inputList[1:])
            else:
                # assume it is login info
                code = input
                data = ''

            try:
                handler = "handle_%s" % evl_ResponseTypes[code]['handler']
            except KeyError:
                logging.warning('No handler defined for ' + code + ', skipping...')
                return

            try:
                handlerFunc = getattr(self, handler)
            except AttributeError:
                raise RuntimeError("Handler function doesn't exist")

            handlerFunc(data)
            logging.debug('----------------------------------------')

    # Envisalink Response Handlers

    def handle_login(self, data):
        self.send_data(self._config.ENVISALINKPASS)

    def handle_login_success(self, data):
        self._loggedin = True
        logging.info('Password accepted, session created')

    def handle_login_failure(self, data):
        logging.error('Password is incorrect. Server is closing socket connection.')

    def handle_login_timeout(self, data):
        logging.error('Envisalink timed out waiting for password, whoops that should never happen. Server is closing socket connection')

    def handle_poll_response(self, code):
        self._lastpollresponse = datetime.now()
        self.handle_command_response(code)

    def handle_command_response(self, code):
        self._commandinprogress = False
        self._lastcommandresponse = datetime.now()
        responseString = evl_TPI_Response_Codes[code]
        logging.debug("Envisalink response: " + responseString)
        if code != '00':
            logging.error("error sending command to envisalink.  Response was: " + responseString)

    def handle_keypad_update(self, data):
        self._lastkeypadupdate = datetime.now()
        dataList = data.split(',')
        # make sure data is in format we expect, current TPI seems to send bad data every so ofen
        if len(dataList) != 5 or "%" in data:
            logging.error("Data format invalid from Envisalink, ignoring...")
            return

        partitionNumber = int(dataList[0])
        flags = IconLED_Flags()
        flags.asShort = int(dataList[1], 16)
        userOrZone = dataList[2]
        beep = evl_Virtual_Keypad_How_To_Beep.get(dataList[3], 'unknown')
        alpha = dataList[4]

        ALARMSTATE['partition'][partitionNumber]['status'].update({'alarm': bool(flags.alarm), 'alarm_in_memory': bool(flags.alarm_in_memory), 'armed_away': bool(flags.armed_away),
                                                                   'ac_present': bool(flags.ac_present), 'armed_bypass': bool(flags.bypass), 'chime': bool(flags.chime),
                                                                   'armed_zero_entry_delay': bool(flags.armed_zero_entry_delay), 'alarm_fire_zone': bool(flags.alarm_fire_zone),
                                                                   'trouble': bool(flags.system_trouble), 'ready': bool(flags.ready), 'fire': bool(flags.fire),
                                                                   'armed_stay': bool(flags.armed_stay),
                                                                   'alpha': alpha,
                                                                   'beep': beep,
                                                                   })

        # if we have never yet received a partition state changed event,  we
        # need to compute the armed state ourselves. Don't want to always do
        # it here because we can't also figure out if we are in entry/exit
        # delay from here
        if not self._has_partition_state_changed:
            armed = bool(flags.armed_away or flags.armed_zero_entry_delay or flags.armed_stay)
            ALARMSTATE.update({'arm': not armed, 'disarm': armed})
            ALARMSTATE['partition'][partitionNumber]['status'].update({'armed': armed})

        now = datetime.now()
        delta = now - self._lastpartitionupdate
        if delta > timedelta(seconds=self._config.ENVISAKEYPADUPDATEINTERVAL) and not self._commandinprogress:
            self._lastpartitionupdate = now
            dscCode = ''
            if flags.alarm or flags.alarm_fire_zone or flags.fire:
                dscCode = 'IN_ALARM'
            elif flags.system_trouble:
                dscCode = 'NOT_READY'
            elif flags.ready:
                dscCode = 'READY'
            elif flags.bypass:
                dscCode = 'READY_BYPASS'
            elif flags.armed_stay:
                dscCode = 'ARMED_STAY'
            elif flags.armed_away:
                dscCode = 'ARMED_AWAY'
            elif flags.armed_zero_entry_delay:
                dscCode = 'ARMED_MAX'

            for plugin in self.plugins:
                plugin.partitionStatus(partitionNumber, dscCode)

        #logging.debug(json.dumps(ALARMSTATE))

    def zoneHexString2Bitmask(self, aHexStringInt):
        bitfieldString = ''
        bigEndianHexString = ''
        # every four characters
        inputItems = re.findall('....', aHexStringInt)
        for inputItem in inputItems:
            # Swap the couples of every four bytes
            # (little endian to big endian)
            swappedBytes = []
            swappedBytes.insert(0, inputItem[0:2])
            swappedBytes.insert(0, inputItem[2:4])

            # add swapped set of four bytes to our return items,
            # converting from hex to int
            bigEndianHexString += ''.join(swappedBytes)

            # convert hex string to 64 bit bitstring
            bitfieldString = str(bin(int(bigEndianHexString, 16))[2:].zfill(64))

        # reverse every 16 bits so "lowest" zone is on the left
        zonefieldString = ''
        inputItems = re.findall('.' * 16, bitfieldString)
        for inputItem in inputItems:
            zonefieldString += inputItem[::-1]

        return zonefieldString

    def handle_zone_state_change(self, data):
        # Envisalink TPI is inconsistent at generating these
        fullZoneBitmask = ''
        if self._config.ENVISALINKVERSION == 4:
            #envisalink 4 returns 128 bits for zone bitmask, bin function used
            #conversion logic assumes 64 bit int so break it in two and combine the parts.
            fullZoneBitmask = self.zoneHexString2Bitmask(data[0:16])
            fullZoneBitmask += self.zoneHexString2Bitmask(data[16:])
        else:
            fullZoneBitmask = self.zoneHexString2Bitmask(data)

        for zoneNumber, zoneBit in enumerate(fullZoneBitmask, start=1):
            zoneName = self._config.ZONENAMES[zoneNumber]
            if zoneName:    # defined in config with name (i.e. we care about it?)
                ALARMSTATE['zone'][zoneNumber]['status'].update({'open': zoneBit == '1', 'fault': zoneBit == '1'})
                logging.debug("%s (zone %i) is %s", zoneName, zoneNumber, "Open/Faulted" if zoneBit == '1' else "Closed/Not Faulted")
                # Save zoneStatus
                if zoneBit == '1':
                    zoneStatus = "open"
                else:
                    zoneStatus = "closed"

                # Send to plugin
                for plugin in self.plugins:
                    plugin.zoneStatus(zoneNumber, zoneStatus)

    def handle_partition_state_change(self, data):
        self._has_partition_state_changed = True
        for currentIndex in range(0, 8):
            partitionStateCode = data[currentIndex * 2:(currentIndex * 2) + 2]
            partitionState = evl_Partition_Status_Codes[str(partitionStateCode)]
            if partitionState['name'] != 'NOT_USED':
                partitionNumber = currentIndex + 1
                previouslyArmed = ALARMSTATE['partition'][partitionNumber]['status'].get('armed', False)
                armed = partitionState['name'] in ('ARMED_STAY', 'ARMED_AWAY', 'ARMED_MAX')
                ALARMSTATE.update({'arm': not armed, 'disarm': armed, 'cancel': bool(partitionState['name'] == 'EXIT_ENTRY_DELAY')})
                ALARMSTATE['partition'][partitionNumber]['status'].update({'exit_delay': bool(partitionState['name'] == 'EXIT_ENTRY_DELAY' and not previouslyArmed),
                                                                           'entry_delay': bool(partitionState['name'] == 'EXIT_ENTRY_DELAY' and previouslyArmed),
                                                                           'armed': armed,
                                                                           'ready': bool(partitionState['name'] == 'READY' or partitionState['name'] == 'READY_BYPASS')})
                if partitionState['name'] == 'NOT_READY': ALARMSTATE['partition'][partitionNumber]['status'].update({'ready': False})

                logging.debug('Parition ' + str(partitionNumber) + ' is in state ' + partitionState['name'])
                logging.debug(json.dumps(ALARMSTATE))

                # Send to plugin
                for plugin in self.plugins:
                    plugin.partitionStatus(partitionNumber, partitionState['name'])

    def handle_realtime_cid_event(self, data):
        eventTypeInt = int(data[0])
        eventType = evl_CID_Qualifiers[eventTypeInt]
        cidEventInt = int(data[1:4])
        cidEvent = evl_CID_Events[cidEventInt]
        partition = data[4:6]
        zoneOrUser = int(data[6:9])

        logging.debug('Event Type is ' + eventType)
        logging.debug('CID Type is ' + cidEvent['type'])
        logging.debug('CID Description is ' + cidEvent['label'])
        logging.debug('Partition is ' + partition)
        logging.debug(cidEvent['type'] + ' value is ' + str(zoneOrUser))

        # notify plugins about if it is an event about arming or alarm
        if cidEvent['type'] == 'user':
            currentUser = self._config.ALARMUSERNAMES[int(zoneOrUser)]
            if not currentUser: currentUser = 'Unknown!'
            currentZone = 'N/A'
        if cidEvent['type'] == 'zone':
            currentZone = self._config.ZONENAMES[int(zoneOrUser)]
            if not currentZone: currentZone = 'Unknown!'
            currentUser = 'N/A'
        logging.debug('Mapped User is ' + currentUser + '. Mapped Zone is ' + currentZone)
        if cidEventInt == 401 and eventTypeInt == 3:  # armed away or instant/max
            for plugin in self.plugins:
                plugin.armedAway(currentUser)
        if cidEventInt == 441 and eventTypeInt == 3:  # armed home
            for plugin in self.plugins:
                plugin.armedHome(currentUser)
        if cidEventInt == 401 and eventTypeInt == 1:  # disarmed away
            for plugin in self.plugins:
                plugin.disarmedAway(currentUser)
        if cidEventInt == 441 and eventTypeInt == 1:  # disarmed away
            for plugin in self.plugins:
                plugin.disarmedHome(currentUser)
        if cidEventInt in range(100, 164) and eventTypeInt == 1:   # alarm triggered
            for plugin in self.plugins:
                plugin.alarmTriggered(cidEvent['label'], currentZone)
        if cidEventInt in range(100, 164) and eventTypeInt == 3:   # alarm in memory cleared
            for plugin in self.plugins:
                plugin.alarmCleared(cidEvent['label'], currentZone)
        if cidEventInt is 406 and eventTypeInt == 1:              # alarm cancelled by user
            for plugin in self.plugins:
                plugin.alarmCleared(cidEvent['label'], currentZone)

    # note that a request to dump zone timers generates both a standard command
    # response (handled elsewhere) as well as this event
    def handle_zone_timer_dump(self, zoneDump):
        zoneInfoArray = self.convertZoneDump(zoneDump)
        for zoneNumber, zoneInfo in enumerate(zoneInfoArray, start=1):
            zoneName = self._config.ZONENAMES[zoneNumber]
            if zoneName:
                ALARMSTATE['zone'][zoneNumber]['lastfault'] = zoneInfo['message']
                logging.debug("%s (zone %i) %s", zoneName, zoneNumber, zoneInfo['message'])
                for plugin in self.plugins:
                    plugin.zoneStatus(zoneNumber, zoneInfo['status'])


    # convert a zone dump into something humans can make sense of
    def convertZoneDump(self, theString):

        returnItems = []

        # every four characters
        inputItems = re.findall('....', theString)
        for inputItem in inputItems:
            # Swap the couples of every four bytes (little endian to big endian)
            swapedBytes = []
            swapedBytes.insert(0, inputItem[0:2])
            swapedBytes.insert(0, inputItem[2:4])

            # add swapped set of four bytes to our return items, converting from hex to int
            itemHexString = ''.join(swapedBytes)
            itemInt = int(itemHexString, 16)

            # each value is a timer for a zone that ticks down every five seconds from maxint
            MAXINT = 65536
            itemTicks = MAXINT - itemInt
            itemSeconds = itemTicks * 5

            itemLastClosed = self.humanTimeAgo(timedelta(seconds=itemSeconds))
            status = ''

            if itemHexString == "FFFF":
                itemLastClosed = "Currently Open"
                status = 'open'
            if itemHexString == "0000":
                itemLastClosed = "Last Closed longer ago than I can remember"
                status = 'closed'
            else:
                itemLastClosed = "Last Closed " + itemLastClosed
                status = 'closed'

            returnItems.append({'message': str(itemLastClosed), 'status': status})
        return returnItems

    # public domain from https://pypi.python.org/pypi/ago/0.0.6
    def delta2dict(self, delta):
        delta = abs(delta)
        return {
            'year':   int(delta.days / 365),
            'day':    int(delta.days % 365),
            'hour':   int(delta.seconds / 3600),
            'minute': int(delta.seconds / 60) % 60,
            'second': delta.seconds % 60,
            'microsecond': delta.microseconds
        }

    def humanTimeAgo(self, dt, precision=3, past_tense='{} ago', future_tense='in {}'):
        """Accept a datetime or timedelta, return a human readable delta string"""
        delta = dt
        if type(dt) is not type(timedelta()):
            delta = datetime.now() - dt

        the_tense = past_tense
        if delta < timedelta(0):
            the_tense = future_tense

        d = self.delta2dict(delta)
        hlist = []
        count = 0
        units = ('year', 'day', 'hour', 'minute', 'second', 'microsecond')
        for unit in units:
            if count >= precision: break     # met precision
            if d[unit] == 0: continue        # skip 0's
            s = '' if d[unit] == 1 else 's'  # handle plurals
            hlist.append('%s %s%s' % (d[unit], unit, s))
            count += 1
        human_delta = ', '.join(hlist)
        return the_tense.format(human_delta)


class AlarmServer(Resource):
    def __init__(self, config):
        Resource.__init__(self)

        self._triggerid = reactor.addSystemEventTrigger('before', 'shutdown', self.shutdownEvent)

        # Create Envisalink client connection
        self._envisalinkClientFactory = EnvisalinkClientFactory(config)
        self._envisaconnect = reactor.connectTCP(config.ENVISALINKHOST, config.ENVISALINKPORT, self._envisalinkClientFactory)

        # Store config
        self._config = config

        root = Resource()
        rootFilePath = sys.path[0] + os.sep + 'ext'
        root.putChild('app', File(rootFilePath))
        root.putChild('img', File(rootFilePath))
        root.putChild('api', self)
        factory = Site(root)
        # conditionally import twisted ssl to help avoid unwanted depdencies and import issues on some systems
        if config.LISTENTYPE.lower() == "tcp":
            self._port = reactor.listenTCP(config.LISTENPORT, factory)
        elif config.LISTENTYPE.lower() == "ssl":
            from twisted.internet import ssl
            self._port = reactor.listenSSL(config.LISTENPORT, factory,
                                           ssl.DefaultOpenSSLContextFactory(config.KEYFILE, config.CERTFILE))
        else:
            logging.warning("AlarmServer listen type %s unknown, server not started.", config.LISTENTYPE)

    def shutdownEvent(self):
        global shuttingdown
        shuttingdown = True
        logging.debug("Shutting down AlarmServer...")
        self._port.stopListening()
        logging.debug("Disconnecting from Envisalink...")
        self._envisaconnect.disconnect()

    def getChild(self, name, request):
        return self

    def render_GET(self, request):
        e = self._envisalinkClientFactory.envisalinkClient
        logging.debug(request.uri)
        query = urlparse.urlparse(request.uri)
        logging.debug(query)
        query_array = urlparse.parse_qs(query.query, True)
        if 'alarmcode' in query_array:
            alarmcode = str(query_array['alarmcode'][0])
        else:
            alarmcode = str(self._config.ALARMCODE)

        request.setHeader('content-type', 'application/json')
        myPath = query.path
        if myPath[-1] == "/":
            myPath = myPath[:-1]
        if myPath == '/api':
            return json.dumps(ALARMSTATE)
        elif myPath == '/api/alarm/arm':
            e.send_data(alarmcode + '2')
            #e.keypresses_to_partition(1, alarmcode + '2')
            return json.dumps({'response': 'Arm command sent to Envisalink.'})
        elif myPath == '/api/alarm/stayarm':
            e.send_data(alarmcode + '3')
            return json.dumps({'response': 'Arm Home command sent to Envisalink.'})
        elif myPath == '/api/alarm/chime':
            e.send_data(alarmcode + '9')
            return json.dumps({'response': 'Chime command sent to Envisalink.'})
        elif myPath == '/api/alarm/panic':
            e.send_data('B')
            return json.dumps({'response': 'Panic command sent to Envisalink.'})                        
        elif myPath == '/api/alarm/disarm':
            e.send_data(alarmcode + '1')
            #e.keypresses_to_partition(1, alarmcode + '1')
            return json.dumps({'response': 'Disarm command sent to Envisalink.'})
        elif myPath == '/api/partition':
            changeTo = query_array['changeto'][0]
            if not changeTo.isdigit():
                return json.dumps({'response': 'changeTo parameter was missing or not a number, ignored.'})
            else:
                e.change_partition(int(changeTo))
                return json.dumps({'response': 'Request to change current partition to %s was received.' % changeTo})
        elif myPath == '/api/testalarm':
            e.handle_realtime_cid_event('1132010050')
            return 'OK, boss'
        elif myPath == '/api/testdump':
            e.dump_zone_timers()
            return 'OK, boss'
        elif myPath == '/api/testreconnect':
            e.logout()
            return 'OK, boss'
        else:
            return NoResource().render(request)


def usage():
    print 'Usage: ' + sys.argv[0] + ' -c <configfile>'


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hc:", ["help", "config="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-c", "--config"):
            global conffile
            conffile = arg


if __name__ == "__main__":
    conffile = 'alarmserver.cfg'
    main(sys.argv[1:])

    print('Using configuration file %s' % conffile)
    config = AlarmServerConfig(conffile)
    loggingconfig = {'level': config.LOGLEVEL,
                     'format': '%(asctime)s %(levelname)s <%(name)s %(module)s %(funcName)s> %(message)s',
                     'datefmt': '%a, %d %b %Y %H:%M:%S'}
    if config.LOGFILE != '':
        loggingconfig['filename'] = config.LOGFILE
    logging.basicConfig(**loggingconfig)

    logging.info('Alarm Server Starting')
    logging.info('Currently Supporting Envisalink 2DS/3 only')
    logging.info('Tested on a Honeywell Vista 15p + EVL-3')

    # allow Twisted to hook into our logging
    observer = log.PythonLoggingObserver()
    observer.start()

    config.initialize_alarmstate()
    AlarmServer(config)

    try:
        reactor.run()
    except KeyboardInterrupt:
        print "Crtl+C pressed. Shutting down."
        logging.info('Shutting down from Ctrl+C')
        sys.exit()
