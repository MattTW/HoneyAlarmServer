#!/usr/bin/python
## Alarm Server
## Supporting Envisalink 2DS/3
## Original version for DSC Written by donnyk+envisalink@gmail.com, lightly improved by leaberry@gmail.com
## Honeywell version adapted by matt.weinecke@gmail.com
##
## This code is under the terms of the GPL v3 license.


import asyncore, asynchat
import ConfigParser
import os, socket, string, sys, httplib, urllib, urlparse, ssl
import StringIO, mimetools
import json
import hashlib
import time
import getopt
import logging
import threading
import struct, re

from envisalinkdefs import *
from plugins.basePlugin import BasePlugin
from baseConfig import BaseConfig
from datetime import datetime
from datetime import timedelta

ALARMSTATE={'version' : 0.1}
MAXPARTITIONS=16
MAXZONES=128
MAXALARMUSERS=47



class AlarmServerConfig(BaseConfig):
    def __init__(self, configfile):
        #call ancestor for common setup
        super(self.__class__, self).__init__(configfile)

        self.LOGURLREQUESTS = self.read_config_var('alarmserver', 'logurlrequests', True, 'bool')
        self.HTTPSPORT = self.read_config_var('alarmserver', 'httpsport', 8111, 'int')
        self.CERTFILE = self.read_config_var('alarmserver', 'certfile', 'server.crt', 'str')
        self.KEYFILE = self.read_config_var('alarmserver', 'keyfile', 'server.key', 'str')
        self.MAXEVENTS = self.read_config_var('alarmserver', 'maxevents', 10, 'int')
        self.MAXALLEVENTS = self.read_config_var('alarmserver', 'maxallevents', 100, 'int')
        self.ENVISALINKHOST = self.read_config_var('envisalink', 'host', 'envisalink', 'str')
        self.ENVISALINKPORT = self.read_config_var('envisalink', 'port', 4025, 'int')
        self.ENVISALINKPASS = self.read_config_var('envisalink', 'pass', 'user', 'str')
        self.ENVISAPOLLINTERVAL = self.read_config_var('envisalink','pollinterval',20,'int')
        self.ENVISAPOLLTIMEOUT = self.read_config_var('envisalink','polltimeout',45,'int')
        self.ENVISAKEYPADTIMEOUT = self.read_config_var('envisalink','keypadtimeout',20,'int')
        self.ALARMCODE = self.read_config_var('envisalink', 'alarmcode', 1111, 'int')
        self.EVENTTIMEAGO = self.read_config_var('alarmserver', 'eventtimeago', True, 'bool')
        self.LOGFILE = self.read_config_var('alarmserver', 'logfile', '', 'str')
        self.LOGLEVEL = self.read_config_var('alarmserver','loglevel','DEBUG','str')


        self.PARTITIONNAMES={}
        for i in range(1, MAXPARTITIONS+1):
            self.PARTITIONNAMES[i]=self.read_config_var('alarmserver', 'partition'+str(i), False, 'str', True)

        self.ZONENAMES={}
        for i in range(1, MAXZONES+1):
            self.ZONENAMES[i]=self.read_config_var('alarmserver', 'zone'+str(i), False, 'str', True)

        self.ALARMUSERNAMES={}
        for i in range(1, MAXALARMUSERS+1):
            self.ALARMUSERNAMES[i]=self.read_config_var('alarmserver', 'user'+str(i), False, 'str', True)

class HTTPChannel(asynchat.async_chat):
    def __init__(self, server, sock, addr):
        asynchat.async_chat.__init__(self, sock)
        self.server = server
        self.set_terminator("\r\n\r\n")
        self.header = None
        self.data = ""
        self.shutdown = 0

    def collect_incoming_data(self, data):
        self.data = self.data + data
        if len(self.data) > 16384:
        # limit the header size to prevent attacks
            self.shutdown = 1

    def found_terminator(self):
        if not self.header:
            # parse http header
            fp = StringIO.StringIO(self.data)
            request = string.split(fp.readline(), None, 2)
            if len(request) != 3:
                # badly formed request; just shut down
                self.shutdown = 1
            else:
                # parse message header
                self.header = mimetools.Message(fp)
                self.set_terminator("\r\n")
                self.server.handle_request(
                    self, request[0], request[1], self.header
                    )
                self.close_when_done()
            self.data = ""
        else:
            pass # ignore body data, for now

    def pushstatus(self, status, explanation="OK"):
        self.push("HTTP/1.0 %d %s\r\n" % (status, explanation))

    def pushok(self, content):
        self.pushstatus(200, "OK")
        self.push('Content-type: application/json\r\n')
        self.push('Expires: Sat, 26 Jul 1997 05:00:00 GMT\r\n')
        self.push('Last-Modified: '+ datetime.now().strftime("%d/%m/%Y %H:%M:%S")+' GMT\r\n')
        self.push('Cache-Control: no-store, no-cache, must-revalidate\r\n' )
        self.push('Cache-Control: post-check=0, pre-check=0\r\n')
        self.push('Pragma: no-cache\r\n' )
        self.push('\r\n')
        self.push(content)

    def pushfile(self, file):
        self.pushstatus(200, "OK")
        extension = os.path.splitext(file)[1]
        if extension == ".html":
            self.push("Content-type: text/html\r\n")
        elif extension == ".js":
            self.push("Content-type: text/javascript\r\n")
        elif extension == ".png":
            self.push("Content-type: image/png\r\n")
        elif extension == ".css":
            self.push("Content-type: text/css\r\n")
        self.push("\r\n")
        self.push_with_producer(push_FileProducer(sys.path[0] + os.sep + 'ext' + os.sep + file))

class EnvisalinkClient(asynchat.async_chat):
    def __init__(self, config):
        # Call parent class's __init__ method
        asynchat.async_chat.__init__(self)


        # Define some private instance variables
        self._buffer = []

        # Are we logged in?
        self._loggedin = False

        self._has_partition_state_changed = False

        # Set our terminator to \n
        self.set_terminator("\r\n")

        # Set config
        self._config = config

        # Reconnect delay
        self._retrydelay = 10

        # find plugins and load/config them
        self.plugins = []
        pluginClasses = BasePlugin.find_subclasses("./plugins/")
        for plugin in pluginClasses:
            plugincfg = "./plugins/" + plugin.__name__ + ".cfg"
            self.plugins.append(plugin(plugincfg))

        self.do_connect()

    def do_connect(self, reconnect = False):
        now = datetime.now()
        self._lastkeypadupdate = now
        self._lastpoll = now
        self._lastpollresponse = now
        # Create the socket and connect to the server
        if reconnect:
            logging.warning('Connection failed, retrying in '+str(self._retrydelay)+ ' seconds')
            self._buffer = []
            time.sleep(self._retrydelay)

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)

        self.connect((self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))

    def cleanup(self, reconnect = True):
        logging.debug("Cleaning up Envisalink client...")
        self._loggedin = False
        self.close()
        if reconnect: self.do_connect(True)

    def send_data(self,data):
        logging.debug('TX > '+data)
        self.push(data)

    def check_alive(self):
        if self._loggedin:
            now = datetime.now()

            #if a few seconds have passed since the last poll and we never received a response, something is wrong
            delta = now - self._lastpoll
            if self._lastpollresponse < self._lastpoll and delta > timedelta(seconds=self._config.ENVISAPOLLTIMEOUT):
                logging.error("Timed out waiting for poll response, resetting connection...")
                self.cleanup(True)
                return

            #is it time to poll again?
            if delta > timedelta(seconds=self._config.ENVISAPOLLINTERVAL):
              self._lastpoll = now
              self.send_command('00','')

            #if 10 seconds have passed and we haven't received a keypad update, something is wrong
            delta = now - self._lastkeypadupdate
            if delta > timedelta(seconds=self._config.ENVISAKEYPADTIMEOUT):
                #reset connection
                logging.error("No recent keypad updates from envisalink, resetting connection...")
                self.cleanup(True)
                return


    #application commands to the envisalink


    def send_command(self, code, data):
        to_send = '^'+code+','+data+'$'
        self.send_data(to_send)

    def change_partition(self,partitionNumber):
        if partitionNumber < 1 or partitionNumber > 8:
            logging.error("Invalid Partition Number %i specified when trying to change partition, ignoring.", partitionNumber)
            return
        if self._loggedin:
            self.send_command('01', str(partitionNumber))

    def dump_zone_timers(self):
        if self._loggedin:
            self.send_command('02','')


    #network communication callbacks


    def collect_incoming_data(self, data):
        # Append incoming data to the buffer
        self._buffer.append(data)

    def found_terminator(self):
        line = "".join(self._buffer)
        self.handle_line(line)
        self._buffer = []

    def handle_connect(self):
        logging.info("Connected to %s:%i" % (self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))

    def handle_close(self):
        logging.info("Disconnected from %s:%i" % (self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))
        self.cleanup(True)

    def handle_line(self, input):
        if input != '':

            logging.debug('----------------------------------------')
            logging.debug('RX < ' + input)
            if input[0] in ("%","^"):
                #keep first sentinel char to tell difference between tpi and Envisalink command responses.  Drop the trailing $ sentinel.
                inputList = input[0:-1].split(',')
                code = inputList[0]
                data = ','.join(inputList[1:])
            else:
                #assume it is login info
                code = input
                data = ''


            try:
                handler = "handle_%s" % evl_ResponseTypes[code]['handler']
            except KeyError:
                logging.warning('No handler defined for '+code+', skipping...')
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

    def handle_login_success(self,data):
        self._loggedin = True
        logging.info('Password accepted, session created')

    def handle_login_failure(self, data):
        logging.error('Password is incorrect. Server is closing socket connection.')

    def handle_login_timeout(self,data):
        logging.error('Envisalink timed out waiting for password, whoops that should never happen. Server is closing socket connection')

    def handle_poll_response(self,code):
        self._lastpollresponse = datetime.now()
        self.handle_command_response(code)

    def handle_command_response(self,code):
        responseString = evl_TPI_Response_Codes[code]
        logging.debug("Envisalink response: " + responseString)
        if code != '00':
          logging.error("error sending command to envisalink.  Response was: " + responseString)

    def handle_keypad_update(self,data):
        self._lastkeypadupdate = datetime.now()
        dataList = data.split(',')
        #make sure data is in format we expect, current TPI seems to send bad data every so ofen
        if len(dataList) !=5 or "%" in data:
            logging.error("Data format invalid from Envisalink, ignoring...")
            return

        partitionNumber = int(dataList[0])
        flags = IconLED_Flags()
        flags.asShort = int(dataList[1],16)
        userOrZone = dataList[2]
        beep = evl_Virtual_Keypad_How_To_Beep.get(dataList[3],'unknown')
        alpha = dataList[4]


        self.ensure_init_alarmstate(partitionNumber)
        ALARMSTATE['partition'][partitionNumber]['status'].update( {'alarm' : bool(flags.alarm), 'alarm_in_memory' : bool(flags.alarm_in_memory), 'armed_away' : bool(flags.armed_away),
                                                        'ac_present' : bool(flags.ac_present), 'armed_bypass' : bool(flags.bypass), 'chime' : bool(flags.chime),
                                                        'armed_zero_entry_delay' : bool(flags.armed_zero_entry_delay), 'alarm_fire_zone' : bool(flags.alarm_fire_zone),
                                                        'trouble' : bool(flags.system_trouble), 'ready' : bool(flags.ready), 'fire' : bool(flags.fire),
                                                        'armed_stay' : bool(flags.armed_stay),
                                                        'alpha' : alpha,
                                                        'beep' : beep,
                                                        })

        #if we have never yet received a partition state changed event,  we need to compute the armed state ourselves.   Don't want to always do it here because we can't also
        #figure out if we are in entry/exit delay from here
        if not self._has_partition_state_changed:
            ALARMSTATE['partition'][partitionNumber]['status'].update( {'armed' : bool(flags.armed_away or flags.armed_zero_entry_delay or flags.armed_stay)})

        #logging.debug(json.dumps(ALARMSTATE))


    def handle_zone_state_change(self,data):
        #Envisalink TPI is inconsistent at generating these, seem to be created heuristically from keypad update fault messages

        bigEndianHexString = ''
        #every four characters
        inputItems = re.findall('....',data)
        for inputItem in inputItems:
            # Swap the couples of every four bytes (little endian to big endian)
            swapedBytes = []
            swapedBytes.insert(0,inputItem[0:2])
            swapedBytes.insert(0,inputItem[2:4])

            # add swapped set of four bytes to our return items, converting from hex to int
            bigEndianHexString += ''.join(swapedBytes)

        # convert hex string to 64 bit bitstring
        bitfieldString = str(bin(int(bigEndianHexString, 16))[2:].zfill(64))

        # reverse every 16 bits so "lowest" zone is on the left
        zonefieldString = ''
        inputItems = re.findall('.'*16,bitfieldString)
        for inputItem in inputItems:
            zonefieldString += inputItem[::-1]

        for zoneNumber,zoneBit in enumerate(zonefieldString,start=1):
            zoneName = self._config.ZONENAMES[zoneNumber]
            if zoneName:
                logging.debug("%s (zone %i) is %s",zoneName,zoneNumber, "Open/Faulted" if zoneBit=='1' else "Closed/Not Faulted")


    def handle_partition_state_change(self,data):
        self._has_partition_state_changed = True
        for currentIndex in range(0,8):
            partitionStateCode = data[currentIndex*2:(currentIndex*2)+2]
            partitionState = evl_Partition_Status_Codes[str(partitionStateCode)]
            if partitionState['name'] != 'NOT_USED':
                partitionNumber = currentIndex + 1
                #TODO can we use dict.setdefault or defaultdict here instead?
                self.ensure_init_alarmstate(partitionNumber)
                previouslyArmed = ALARMSTATE['partition'][partitionNumber]['status'].get('armed',False)
                armed = partitionState['name'] in ('ARMED_STAY','ARMED_AWAY','ARMED_MAX')
                ALARMSTATE['partition'][partitionNumber]['status'].update({'exit_delay' : bool(partitionState['name'] == 'EXIT_ENTRY_DELAY' and not previouslyArmed),
                                                                           'entry_delay' : bool (partitionState['name'] == 'EXIT_ENTRY_DELAY' and previouslyArmed),
                                                                           'armed' : armed } )

                logging.debug('Parition ' + str(partitionNumber) + ' is in state ' + partitionState['name'])
                #logging.debug(json.dumps(ALARMSTATE))

    def handle_realtime_cid_event(self,data):
        eventTypeInt = int(data[0])
        eventType = evl_CID_Qualifiers[eventTypeInt]
        cidEventInt = int(data[1:4])
        cidEvent = evl_CID_Events[cidEventInt]
        partition = data[4:6]
        zoneOrUser = int(data[6:9])

        logging.debug('Event Type is '+eventType)
        logging.debug('CID Type is '+cidEvent['type'])
        logging.debug('CID Description is '+cidEvent['label'])
        logging.debug('Partition is '+partition)
        logging.debug(cidEvent['type'] + ' value is ' + str(zoneOrUser))

        #notify plugins about if it is an event about arming or alarm
        if cidEvent['type'] == 'user':
            currentUser = self._config.ALARMUSERNAMES[int(zoneOrUser)]
            if not currentUser: currentUser = 'Unknown!'
            currentZone = 'N/A'
        if cidEvent['type'] == 'zone':
            currentZone = self._config.ZONENAMES[int(zoneOrUser)]
            if not currentZone: currentZone = 'Unknown!'
            currentUser = 'N/A'
        logging.debug('Mapped User is ' + currentUser + '. Mapped Zone is ' + currentZone)
        if cidEventInt == 401 and eventTypeInt == 3:   #armed away or instant/max
            for plugin in self.plugins:
                plugin.armedAway(currentUser)
        if cidEventInt == 441 and eventTypeInt == 3:   #armed home
            for plugin in self.plugins:
                plugin.armedHome(currentUser)
        if cidEventInt == 401 and eventTypeInt == 1:  #disarmed away
            for plugin in self.plugins:
                plugin.disarmedAway(currentUser)
        if cidEventInt == 441 and eventTypeInt == 1:  #disarmed away
            for plugin in self.plugins:
                plugin.disarmedHome(currentUser)
        if cidEventInt in range(100,164) and eventTypeInt == 1:   #alarm triggered
            for plugin in self.plugins:
                plugin.alarmTriggered(cidEvent['label'], currentZone)
        if cidEventInt in range(100,164) and eventTypeInt == 3:  #alarm in memory cleared
            for plugin in self.plugins:
                plugin.alarmCleared(cidEvent['label'], currentZone)
        if cidEventInt is 406 and eventTypeInt == 1:              #alarm cancelled by user
            for plugin in self.plugins:
                plugin.alarmCleared(cidEvent['label'], currentZone)

    #note that a request to dump zone timers generates both a standard command response (handled elsewhere)
    #as well as this event
    def handle_zone_timer_dump(self,zoneDump):
        zoneTimers = self.convertZoneDump(zoneDump)
        for zoneNumber,zoneTimer in enumerate(zoneTimers,start = 1):
          zoneName = self._config.ZONENAMES[zoneNumber]
          if zoneName:
              logging.debug("%s (zone %i) %s",zoneName,zoneNumber,zoneTimer)

    #convert a zone dump into something humans can make sense of
    def convertZoneDump(self, theString):

        returnItems = []

        #every four characters
        inputItems = re.findall('....',theString)
        for inputItem in inputItems:
            # Swap the couples of every four bytes (little endian to big endian)
            swapedBytes = []
            swapedBytes.insert(0,inputItem[0:2])
            swapedBytes.insert(0,inputItem[2:4])

            # add swapped set of four bytes to our return items, converting from hex to int
            itemHexString = ''.join(swapedBytes)
            itemInt = int(itemHexString, 16)

            # each value is a timer for a zone that ticks down every five seconds from maxint
            MAXINT = 65536
            itemTicks = MAXINT - itemInt
            itemSeconds = itemTicks * 5

            itemLastClosed = self.humanTimeAgo(timedelta(seconds=itemSeconds))

            if itemHexString == "FFFF":
                itemLastClosed = "is currently Open"
            if itemHexString == "0000":
                itemLastClosed = "last Closed longer ago than I can remember"
            else:
                itemLastClosed = "last Closed " + itemLastClosed

            returnItems.append(str(itemLastClosed))
        return returnItems

    #public domain from https://pypi.python.org/pypi/ago/0.0.6
    def delta2dict( self, delta ):
        delta = abs( delta )
        return {
            'year'   : int(delta.days / 365),
            'day'    : int(delta.days % 365),
            'hour'   : int(delta.seconds / 3600),
            'minute' : int(delta.seconds / 60) % 60,
            'second' : delta.seconds % 60,
            'microsecond' : delta.microseconds
        }

    def humanTimeAgo(self, dt, precision=3, past_tense='{} ago', future_tense='in {}'):
        """Accept a datetime or timedelta, return a human readable delta string"""
        delta = dt
        if type(dt) is not type(timedelta()):
            delta = datetime.now() - dt

        the_tense = past_tense
        if delta < timedelta(0):
            the_tense = future_tense

        d = self.delta2dict( delta )
        hlist = []
        count = 0
        units = ( 'year', 'day', 'hour', 'minute', 'second', 'microsecond' )
        for unit in units:
            if count >= precision: break # met precision
            if d[ unit ] == 0: continue # skip 0's
            s = '' if d[ unit ] == 1 else 's' # handle plurals
            hlist.append( '%s %s%s' % ( d[unit], unit, s ) )
            count += 1
        human_delta = ', '.join( hlist )
        return the_tense.format(human_delta)

    def ensure_init_alarmstate(self,partitionNumber):
        if not 'partition' in ALARMSTATE: ALARMSTATE['partition']={'lastevents' : []}
        if partitionNumber in self._config.PARTITIONNAMES:
            if not partitionNumber in ALARMSTATE['partition']: ALARMSTATE['partition'][partitionNumber] = {'name' : self._config.PARTITIONNAMES[partitionNumber]}
        else:
            if not partitionNumber in ALARMSTATE['partition']: ALARMSTATE['partition'][partitionNumber] = {}
        if not 'lastevents' in ALARMSTATE['partition'][partitionNumber]: ALARMSTATE['partition'][partitionNumber]['lastevents'] = []
        if not 'status' in ALARMSTATE['partition'][partitionNumber]: ALARMSTATE['partition'][partitionNumber]['status'] = {}


class push_FileProducer:
    # a producer which reads data from a file object

    def __init__(self, file):
        self.file = open(file, "rb")

    def more(self):
        if self.file:
            data = self.file.read(2048)
            if data:
                return data
            self.file = None
        return ""

class AlarmServer(asyncore.dispatcher):
    def __init__(self, config):
        # Call parent class's __init__ method
        asyncore.dispatcher.__init__(self)

        # Create Envisalink client object
        self._envisalinkclient = EnvisalinkClient(config)

        #Store config
        self._config = config

        # Create socket and listen on it
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind(("", config.HTTPSPORT))
        self.listen(5)
        logging.info("AlarmServer listening at %s:%i", socket.gethostbyname(socket.gethostname()),config.HTTPSPORT)

    def cleanup(self):
        logging.debug("Cleaning up AlarmServer...")
        self.close()
        self._envisalinkclient.cleanup(False)

    def check_envisalink_alive(self):
        self._envisalinkclient.check_alive()

    def handle_accept(self):
        # Accept the connection
        conn, addr = self.accept()
        if (config.LOGURLREQUESTS):
            logging.info('Incoming web connection from %s' % repr(addr))

        try:
            HTTPChannel(self, ssl.wrap_socket(conn, server_side=True, certfile=config.CERTFILE, keyfile=config.KEYFILE, ssl_version=ssl.PROTOCOL_TLSv1), addr)
        except ssl.SSLError as e:
            logging.error("SSL error({0}): {1}".format(e.errno, e.strerror))
            return

    def handle_close(self):
        self.cleanup()

    def handle_request(self, channel, method, request, header):
        if (config.LOGURLREQUESTS):
            logging.info('Web request: '+str(method)+' '+str(request))

        query = urlparse.urlparse(request)
        query_array = urlparse.parse_qs(query.query, True)
        if 'alarmcode' in query_array:
            alarmcode = str(query_array['alarmcode'][0])
        else:
            alarmcode = str(self._config.ALARMCODE)

        if query.path == '/':
            channel.pushfile('index.html');
        elif query.path == '/api':
            channel.pushok(json.dumps(ALARMSTATE))
        elif query.path == '/api/alarm/arm':
            self._envisalinkclient.send_data(alarmcode+'2')
            channel.pushok(json.dumps({'response' : 'Arm command sent to Envisalink.'}))
        elif query.path == '/api/alarm/stayarm':
            self._envisalinkclient.send_data(alarmcode+'3')
            channel.pushok(json.dumps({'response' : 'Arm Home command sent to Envisalink.'}))
        elif query.path == '/api/alarm/disarm':
            self._envisalinkclient.send_data(alarmcode+'1')
            channel.pushok(json.dumps({'response' : 'Disarm command sent to Envisalink.'}))
        elif query.path == '/api/partition':
            changeTo = query_array['changeto'][0]
            if not changeTo.isdigit():
                channel.pushok(json.dumps({'response' : 'changeTo parameter was missing or not a number, ignored.'}))
            else:
                self._envisalinkclient.change_partition(int(changeTo))
                channel.pushok(json.dumps({'response' : 'Request to change current partition to %s was received.' % changeTo}))
        elif query.path == '/api/testalarm':
            self._envisalinkclient.handle_realtime_cid_event('1132010050')
            channel.pushok('OK, boss')
        elif query.path == '/api/testdump':
            self._envisalinkclient.dump_zone_timers()
            channel.pushok('OK, boss')
        elif query.path == '/api/config/eventtimeago':
            channel.pushok(json.dumps({'eventtimeago' : str(self._config.EVENTTIMEAGO)}))
        elif query.path == '/img/glyphicons-halflings.png':
            channel.pushfile('glyphicons-halflings.png')
        elif query.path == '/img/glyphicons-halflings-white.png':
            channel.pushfile('glyphicons-halflings-white.png')
        elif query.path == '/favicon.ico':
            channel.pushfile('favicon.ico')
        else:
            if len(query.path.split('/')) == 2:
                try:
                    with open(sys.path[0] + os.sep + 'ext' + os.sep + query.path.split('/')[1]) as f:
                        f.close()
                        channel.pushfile(query.path.split('/')[1])
                except IOError as e:
                    logging.error("I/O error({0}): {1}".format(e.errno, e.strerror))
                    channel.pushstatus(404, "Not found")
                    channel.push("Content-type: text/html\r\n")
                    channel.push("File not found")
                    channel.push("\r\n")
            else:
                if (config.LOGURLREQUESTS):
                    logging.info("Invalid file requested")

                channel.pushstatus(404, "Not found")
                channel.push("Content-type: text/html\r\n")
                channel.push("\r\n")


def usage():
    print 'Usage: '+sys.argv[0]+' -c <configfile>'

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


if __name__=="__main__":


    conffile='alarmserver.cfg'
    main(sys.argv[1:])

    print('Using configuration file %s' % conffile)
    config = AlarmServerConfig(conffile)
    loggingconfig = { 'level' : config.LOGLEVEL,
                      'format':'%(asctime)s %(levelname)s %(message)s',
                      'datefmt' : '%a, %d %b %Y %H:%M:%S'}
    if config.LOGFILE != '':
        loggingconfig['filename'] = config.LOGFILE
    logging.basicConfig(**loggingconfig)

    logging.info('Alarm Server Starting')
    logging.info('Currently Supporting Envisalink 2DS/3 only')
    logging.info('Tested on a Honeywell Vista 15p + EVL-3')


    server = AlarmServer(config)

    try:
        while True:
            asyncore.loop(timeout=2, count=1)
            server.check_envisalink_alive()
    except KeyboardInterrupt:
        print "Crtl+C pressed. Shutting down."
        logging.info('Shutting down from Ctrl+C')

        server.cleanup()
        sys.exit()
