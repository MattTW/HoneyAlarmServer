#!/usr/bin/python
## Alarm Server
## Supporting Envisalink 2DS/3
## Written by donnyk+envisalink@gmail.com
## Lightly improved by leaberry@gmail.com
##
## This code is under the terms of the GPL v3 license.


import asyncore, asynchat
import ConfigParser
import datetime
import os, socket, string, sys, httplib, urllib, urlparse, ssl
import StringIO, mimetools
import json
import hashlib
import time
import getopt


from envisalinkdefs import *


LOGTOFILE = False

class CodeError(Exception): pass

ALARMSTATE={'version' : 0.1}
KEYPADSTATE = [{}] * 8      #list of dictionaries, one for each possible partition
MAXPARTITIONS=16
MAXZONES=128
MAXALARMUSERS=47
CONNECTEDCLIENTS={}


def getMessageType(code):
    return evl_ResponseTypes[code]

def alarmserver_logger(message, type = 0, level = 0):
    if LOGTOFILE:
        outfile.write(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))+' '+message+'\n')
        outfile.flush()
    else:
        print (str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))+' '+message)
    

#currently supports pushover notifications, more to be added
#including email, text, etc.
#to be fixed!
def send_notification(config, message):
    if config.PUSHOVER_ENABLE == True:
        conn = httplib.HTTPSConnection("api.pushover.net:443")
        conn.request("POST", "/1/messages.json",
            urllib.urlencode({
            "token": "qo0nwMNdX56KJl0Avd4NHE2onO4Xff",
            "user": config.PUSHOVER_USERTOKEN,
            "message": str(message),
            }), { "Content-type": "application/x-www-form-urlencoded" })

class AlarmServerConfig():
    def __init__(self, configfile):

        self._config = ConfigParser.ConfigParser()
        self._config.read(configfile)

        self.LOGURLREQUESTS = self.read_config_var('alarmserver', 'logurlrequests', True, 'bool')
        self.HTTPSPORT = self.read_config_var('alarmserver', 'httpsport', 8111, 'int')
        self.CERTFILE = self.read_config_var('alarmserver', 'certfile', 'server.crt', 'str')
        self.KEYFILE = self.read_config_var('alarmserver', 'keyfile', 'server.key', 'str')
        self.MAXEVENTS = self.read_config_var('alarmserver', 'maxevents', 10, 'int')
        self.MAXALLEVENTS = self.read_config_var('alarmserver', 'maxallevents', 100, 'int')
        self.ENVISALINKHOST = self.read_config_var('envisalink', 'host', 'envisalink', 'str')
        self.ENVISALINKPORT = self.read_config_var('envisalink', 'port', 4025, 'int')
        self.ENVISALINKPASS = self.read_config_var('envisalink', 'pass', 'user', 'str')
        self.ENABLEPROXY = self.read_config_var('envisalink', 'enableproxy', True, 'bool')
        self.ENVISALINKPROXYPORT = self.read_config_var('envisalink', 'proxyport', self.ENVISALINKPORT, 'int')
        self.ENVISALINKPROXYPASS = self.read_config_var('envisalink', 'proxypass', self.ENVISALINKPASS, 'str')
        self.PUSHOVER_ENABLE = self.read_config_var('pushover', 'enable', False, 'bool')
        self.PUSHOVER_USERTOKEN = self.read_config_var('pushover', 'enable', False, 'bool')
        self.ALARMCODE = self.read_config_var('envisalink', 'alarmcode', 1111, 'int')
        self.EVENTTIMEAGO = self.read_config_var('alarmserver', 'eventtimeago', True, 'bool')
        self.LOGFILE = self.read_config_var('alarmserver', 'logfile', '', 'str')
        global LOGTOFILE
        if self.LOGFILE == '':
            LOGTOFILE = False
        else:
            LOGTOFILE = True

        self.PARTITIONNAMES={}
        for i in range(1, MAXPARTITIONS+1):
            self.PARTITIONNAMES[i]=self.read_config_var('alarmserver', 'partition'+str(i), False, 'str', True)

        self.ZONENAMES={}
        for i in range(1, MAXZONES+1):
            self.ZONENAMES[i]=self.read_config_var('alarmserver', 'zone'+str(i), False, 'str', True)

        self.ALARMUSERNAMES={}
        for i in range(1, MAXALARMUSERS+1):
            self.ALARMUSERNAMES[i]=self.read_config_var('alarmserver', 'user'+str(i), False, 'str', True)

        if self.PUSHOVER_USERTOKEN == False and self.PUSHOVER_ENABLE == True: self.PUSHOVER_ENABLE = False

    def defaulting(self, section, variable, default, quiet = False):
        if quiet == False:
            print('Config option '+ str(variable) + ' not set in ['+str(section)+'] defaulting to: \''+str(default)+'\'')

    def read_config_var(self, section, variable, default, type = 'str', quiet = False):
        try:
            if type == 'str':
                return self._config.get(section,variable)
            elif type == 'bool':
                return self._config.getboolean(section,variable)
            elif type == 'int':
                return int(self._config.get(section,variable))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            self.defaulting(section, variable, default, quiet)
            return default

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
        self.push('Last-Modified: '+ datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")+' GMT\r\n')
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


import ctypes
c_uint16 = ctypes.c_uint16

class IconLED_Bitfield( ctypes.LittleEndianStructure ):
    _fields_ = [
                ("alarm",     c_uint16, 1 ),
                ("alarm_in_memory", c_uint16, 1 ),
                ("armed_away",    c_uint16, 1 ),
                ("ac_present",       c_uint16, 1 ),
                ("bypass",       c_uint16, 1 ), 
                ("chime",       c_uint16, 1 ), 
                ("not_used1",       c_uint16, 1 ), 
                ("armed_zero_entry_delay",       c_uint16, 1 ), 
                ("alarm_fire_zone",       c_uint16, 1 ), 
                ("system_trouble",       c_uint16, 1 ), 
                ("not_used2",       c_uint16, 1 ), 
                ("not_used3",       c_uint16, 1 ), 
                ("ready",       c_uint16, 1 ), 
                ("fire",       c_uint16, 1 ), 
                ("low_battery",       c_uint16, 1 ), 
                ("armed_stay",       c_uint16, 1 )
               ]

class IconLED_Flags( ctypes.Union ):
    _fields_ = [
                ("b",      IconLED_Bitfield ),
                ("asShort", c_uint16    )
               ]
    _anonymous_ = ("b")

class EnvisalinkClient(asynchat.async_chat):
    def __init__(self, config):
        # Call parent class's __init__ method
        asynchat.async_chat.__init__(self)

        # Define some private instance variables
        self._buffer = []

        # Are we logged in?
        self._loggedin = False

        # Set our terminator to \n
        self.set_terminator("\r\n")

        # Set config
        self._config = config

        # Reconnect delay
        self._retrydelay = 10

        self.do_connect()

    def do_connect(self, reconnect = False):
        # Create the socket and connect to the server
        if reconnect == True:
            alarmserver_logger('Connection failed, retrying in '+str(self._retrydelay)+ ' seconds')
            for i in range(0, self._retrydelay):
                time.sleep(1)

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)

        self.connect((self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))

    def collect_incoming_data(self, data):
        # Append incoming data to the buffer
        self._buffer.append(data)

    def found_terminator(self):
        line = "".join(self._buffer)
        self.handle_line(line)
        self._buffer = []

    def handle_connect(self):
        alarmserver_logger("Connected to %s:%i" % (self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))

    def handle_close(self):
        self._loggedin = False
        self.close()
        alarmserver_logger("Disconnected from %s:%i" % (self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))
        self.do_connect(True)

    def handle_eerror(self):
        self._loggedin = False
        self.close()
        alarmserver_logger("Error, disconnected from %s:%i" % (self._config.ENVISALINKHOST, self._config.ENVISALINKPORT))
        self.do_connect(True)

    def send_data(self,data):
        alarmserver_logger('TX > '+data)
        self.push(data)

    def send_envisalink_command(self, code, data):
        to_send = '^'+code+','+data+'$'
        self.send_data(to_send)

    def handle_line(self, input):
        if input != '':
            for client in CONNECTEDCLIENTS:
                CONNECTEDCLIENTS[client].send_command(input, False)

            alarmserver_logger('----------------------------------------')
            alarmserver_logger('RX < ' + input)
            if input[0] in ("%","^"):
                #keep first sentinel char to tell difference between tpi and Envisalink command responses.  Drop the trailing $ sentinel.
                inputList = input[0:-1].split(',')
                code = inputList[0]
                data = ','.join(inputList[1:])
            else:
                #assume it is login info
                code = input
                data = ''

            #code=int(input[:3])
            #parameters=input[3:][:-2]
            #event = getMessageType(int(code))
            #message = self.format_event(event, parameters)
            
            
            try:
                handler = "handle_%s" % evl_ResponseTypes[code]['handler']
            except KeyError:
                #call general event handler
                #self.handle_event(code, parameters, event, message)
                self.handle_general(code,data)
                return

            try:
                handlerFunc = getattr(self, handler)
            except AttributeError:
                raise CodeError("Handler function doesn't exist")

            
            handlerFunc(data)
            alarmserver_logger('----------------------------------------')
 

    def format_event(self, event, parameters):
        if 'type' in event:
            if event['type'] in ('partition', 'zone'):
                if event['type'] == 'partition':
                    # If parameters includes extra digits then this next line would fail
                    # without looking at just the first digit which is the partition number
                    if int(parameters[0]) in self._config.PARTITIONNAMES:
                        if self._config.PARTITIONNAMES[int(parameters[0])]!=False:
                            # After partition number can be either a usercode
                            # or for event 652 a type of arm mode (single digit)
                            # Usercode is always 4 digits padded with zeros
                            if len(str(parameters)) == 5:
                                # We have a usercode
                                try:
                                    usercode = int(parameters[1:5])
                                except:
                                    usercode = 0
                                if int(usercode) in self._config.ALARMUSERNAMES:
                                    if self._config.ALARMUSERNAMES[int(usercode)]!=False:
                                        alarmusername = self._config.ALARMUSERNAMES[int(usercode)]
                                    else:
                                        # Didn't find a username, use the code instead
                                        alarmusername = usercode
                                    return event['name'].format(str(self._config.PARTITIONNAMES[int(parameters[0])]), str(alarmusername))
                            elif len(parameters) == 2:
                                # We have an arm mode instead, get it's friendly name
                                armmode = evl_ArmModes[int(parameters[1])]
                                return event['name'].format(str(self._config.PARTITIONNAMES[int(parameters[0])]), str(armmode))
                            else:
                                return event['name'].format(str(self._config.PARTITIONNAMES[int(parameters)]))
                elif event['type'] == 'zone':
                    if int(parameters) in self._config.ZONENAMES:
                        if self._config.ZONENAMES[int(parameters)]!=False:
                            return event['name'].format(str(self._config.ZONENAMES[int(parameters)]))

        return event['name'].format(str(parameters))



    #envisalink event handlers, some events are unhandled.
    def handle_login(self, data):
        self.send_data(self._config.ENVISALINKPASS)

    def handle_login_success(self,data):
        self._loggedin = True
        alarmserver_logger('Password accepted, session created')

    def handle_login_failure(self, data):
        alarmserver_logger('Password is incorrect. Server is closing socket connection.')

    def handle_login_timeout(self,data):
        alarmserver_logger('Envisalink timed out waiting for password, whoops that should never happen. Server is closing socket connection')

    def handle_keypad_update(self,data):
        dataList = data.split(',')
        partitionNumber = int(dataList[0])
        flags = IconLED_Flags()
        flags.asShort = int(dataList[1],16)
        userOrZone = dataList[2]
        beep = evl_Virtual_Keypad_How_To_Beep.get(dataList[3],'unknown')
        alpha = dataList[4]

 
        self.init_alarmstate(partitionNumber)
        ALARMSTATE['partition'][partitionNumber]['status'].update( {'alarm' : bool(flags.alarm), 'alarm_in_memory' : bool(flags.alarm_in_memory), 'armed_way' : bool(flags.armed_away),
                                                        'ac_present' : bool(flags.ac_present), 'armed_bypass' : bool(flags.bypass), 'chime' : bool(flags.chime),
                                                        'armed_zero_entry_delay' : bool(flags.armed_zero_entry_delay), 'alarm_fire_zone' : bool(flags.alarm_fire_zone),
                                                        'trouble' : bool(flags.system_trouble), 'ready' : bool(flags.ready), 'fire' : bool(flags.fire),
                                                        'armed_away' : bool(flags.armed_stay),
                                                        'alpha' : alpha,  
                                                        'beep' : beep,
                                                        })
        

        # 'partition' : { 'exit_delay' : False, 'entry_delay' : False, 'armed' : False,  },


        alarmserver_logger('update is for partition '+str(partitionNumber))
        alarmserver_logger('keypad update bit alarm is {0}'.format(bool(flags.alarm)))
        alarmserver_logger('keypad update bit alarm_in_memory is {0}'.format(bool(flags.alarm_in_memory)))
        alarmserver_logger('keypad update bit armed_away is {0}'.format(bool(flags.armed_away)))
        alarmserver_logger('keypad update bit ac_present is {0}'.format(bool(flags.ac_present)))
        alarmserver_logger('keypad update bit bypass is {0}'.format(bool(flags.bypass)))
        alarmserver_logger('keypad update bit chime is {0}'.format(bool(flags.chime)))
        alarmserver_logger('keypad update bit armed_zero_entry_delay is {0}'.format(bool(flags.armed_zero_entry_delay)))
        alarmserver_logger('keypad update bit alarm_fire_zone is {0}'.format(bool(flags.alarm_fire_zone)))
        alarmserver_logger('keypad update bit system_trouble is {0}'.format(bool(flags.system_trouble)))
        alarmserver_logger('keypad update bit ready is {0}'.format(bool(flags.ready)))
        alarmserver_logger('keypad update bit fire is {0}'.format(bool(flags.fire)))
        alarmserver_logger('keypad update bit armed_stay is {0}'.format(bool(flags.armed_stay)))
        alarmserver_logger('user or zone or numeric data: ' + userOrZone)
        alarmserver_logger('beep value: '+beep)
        alarmserver_logger('===>'+alpha)

    def handle_zone_state_change(self,data):
        #Honeywell Panels or Envisalink currently does not seem to generate these events
        alarmserver_logger('zone state change handler not implemented yet')

    def handle_partition_state_change(self,data):
        for currentIndex in range(0,8):
            partitionState = data[currentIndex*2:(currentIndex*2)+2]
            if partitionState != '00':
                partitionNumber = currentIndex + 1
                self.init_alarmstate(partitionNumber)
                #panel seems to send 07 for both entry and exit delay, TODO see if previous state was armed, then it is entry_delay.
                previouslyArmed = ALARMSTATE['partition'][partitionNumber]['status'].get('armed',False)
                ALARMSTATE['partition'][partitionNumber]['status'].update({'exit_delay' : bool(partitionState == '07' and not previouslyArmed), 
                                                                           'entry_delay' : bool (partitionState == '07' and previouslyArmed),
                                                                           'armed' : bool (partitionState == '04' or partitionState == '05' or partitionState == '06')} )

                alarmserver_logger('Parition ' + str(partitionNumber) + ' is in state ' + evl_Partition_Status_Codes[partitionState])
                alarmserver_logger(json.dumps(ALARMSTATE))

    def handle_realtime_cid_event(self,data):
        qualifier = evl_CID_Qualifiers[int(data[0])]
        cidEvent = evl_CID_Events[int(data[1:4])]
        partition = data[4:6]
        zoneOrUser = data[6:9]


        alarmserver_logger('Event Type is '+qualifier)
        alarmserver_logger('CID Type is '+cidEvent['type'])
        alarmserver_logger('CID Description is '+cidEvent['label'])
        alarmserver_logger('Partition is '+partition)
        alarmserver_logger(cidEvent['type'] + ' value is ' + zoneOrUser)


    def handle_general(self, code, data):
        alarmserver_logger('No handler defined for '+code+', skipping...')

    def handle_event(self, code, parameters, event, message):
        if 'type' in event:
            if not event['type'] in ALARMSTATE: ALARMSTATE[event['type']]={'lastevents' : []}

            if event['type'] in ('partition', 'zone'):
                if event['type'] == 'zone':
                    if int(parameters) in self._config.ZONENAMES:
                        if not int(parameters) in ALARMSTATE[event['type']]: ALARMSTATE[event['type']][int(parameters)] = {'name' : self._config.ZONENAMES[int(parameters)]}
                    else:
                        if not int(parameters) in ALARMSTATE[event['type']]: ALARMSTATE[event['type']][int(parameters)] = {}
                elif event['type'] == 'partition':
                    if int(parameters) in self._config.PARTITIONNAMES:
                        if not int(parameters) in ALARMSTATE[event['type']]: ALARMSTATE[event['type']][int(parameters)] = {'name' : self._config.PARTITIONNAMES[int(parameters)]}
                    else:
                        if not int(parameters) in ALARMSTATE[event['type']]: ALARMSTATE[event['type']][int(parameters)] = {}
            else:
                if not int(parameters) in ALARMSTATE[event['type']]: ALARMSTATE[event['type']][int(parameters)] = {}

            if not 'lastevents' in ALARMSTATE[event['type']][int(parameters)]: ALARMSTATE[event['type']][int(parameters)]['lastevents'] = []
            if not 'status' in ALARMSTATE[event['type']][int(parameters)]:
                if not 'type' in event:
                    ALARMSTATE[event['type']][int(parameters)]['status'] = {}
                else:
                    ALARMSTATE[event['type']][int(parameters)]['status'] = evl_Defaults[event['type']]

            if 'status' in event:
                ALARMSTATE[event['type']][int(parameters)]['status']=dict_merge(ALARMSTATE[event['type']][int(parameters)]['status'], event['status'])

            if len(ALARMSTATE[event['type']][int(parameters)]['lastevents']) > self._config.MAXEVENTS:
                ALARMSTATE[event['type']][int(parameters)]['lastevents'].pop(0)
            ALARMSTATE[event['type']][int(parameters)]['lastevents'].append({'datetime' : str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")), 'message' : message})

            if len(ALARMSTATE[event['type']]['lastevents']) > self._config.MAXALLEVENTS:
                ALARMSTATE[event['type']]['lastevents'].pop(0)
            ALARMSTATE[event['type']]['lastevents'].append({'datetime' : str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")), 'message' : message})

    def handle_zone(self, code, parameters, event, message):
        self.handle_event(code, parameters[1:], event, message)

    def handle_partition(self, code, parameters, event, message):
        self.handle_event(code, parameters[0], event, message)

    def init_alarmstate(self,partitionNumber):
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

    def handle_accept(self):
        # Accept the connection
        conn, addr = self.accept()
        if (config.LOGURLREQUESTS):
            alarmserver_logger('Incoming web connection from %s' % repr(addr))

        try:
            HTTPChannel(self, ssl.wrap_socket(conn, server_side=True, certfile=config.CERTFILE, keyfile=config.KEYFILE, ssl_version=ssl.PROTOCOL_TLSv1), addr)
        except ssl.SSLError as e:
            alarmserver_logger("SSL error({0}): {1}".format(e.errno, e.strerror))
            return

    def handle_request(self, channel, method, request, header):
        if (config.LOGURLREQUESTS):
            alarmserver_logger('Web request: '+str(method)+' '+str(request))

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
            channel.pushok(json.dumps({'response' : 'Request to arm received'}))
            self._envisalinkclient.send_data(alarmcode+'2')
        elif query.path == '/api/alarm/stayarm':
            channel.pushok(json.dumps({'response' : 'Request to arm in stay received'}))
            self._envisalinkclient.send_data(alarmcode+'3')
        elif query.path == '/api/alarm/armwithcode':
            channel.pushok(json.dumps({'response' : 'Request to arm with code received'}))
            self._envisalinkclient.send_data(str(query_array['alarmcode'][0])+'2')
        elif query.path == '/api/pgm':
            channel.pushok(json.dumps({'response' : 'Request to trigger PGM'}))
            #self._envisalinkclient.send_command('020', '1' + str(query_array['pgmnum'][0]))
            #self._envisalinkclient.send_command('071', '1' + "*7" + str(query_array['pgmnum'][0]))
            #time.sleep(1)
            #self._envisalinkclient.send_command('071', '1' + str(query_array['alarmcode'][0]))
        elif query.path == '/api/alarm/disarm':
            channel.pushok(json.dumps({'response' : 'Request to disarm received'}))
            self._envisalinkclient.send_data(alarmcode+'1')
        elif query.path == '/api/refresh':
            channel.pushok(json.dumps({'response' : 'Request to refresh data received'}))
            #self._envisalinkclient.send_command('001', '')
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
                    print "I/O error({0}): {1}".format(e.errno, e.strerror)
                    channel.pushstatus(404, "Not found")
                    channel.push("Content-type: text/html\r\n")
                    channel.push("File not found")
                    channel.push("\r\n")
            else:
                if (config.LOGURLREQUESTS):
                    alarmserver_logger("Invalid file requested")

                channel.pushstatus(404, "Not found")
                channel.push("Content-type: text/html\r\n")
                channel.push("\r\n")

class ProxyChannel(asynchat.async_chat):
    def __init__(self, server, proxypass, sock, addr):
        asynchat.async_chat.__init__(self, sock)
        self.server = server
        self.set_terminator("\r\n")
        self._buffer = []
        self._server = server
        self._clientMD5 = hashlib.md5(str(addr)).hexdigest()
        self._straddr = str(addr)
        self._proxypass = proxypass
        self._authenticated = False

        self.send_command('5053')

    def collect_incoming_data(self, data):
        # Append incoming data to the buffer
        self._buffer.append(data)

    def found_terminator(self):
        line = "".join(self._buffer)
        self._buffer = []
        self.handle_line(line)

    def handle_line(self, line):
        alarmserver_logger('PROXY REQ < '+line)
        if self._authenticated == True:
            self._server._envisalinkclient.send_command(line, '', False)
        else:
            self.send_command('500005')
            expectedstring = '005' + self._proxypass + get_checksum('005', self._proxypass)
            if line == ('005' + self._proxypass + get_checksum('005', self._proxypass)):
                alarmserver_logger('Proxy User Authenticated')
                CONNECTEDCLIENTS[self._straddr]=self
                self._authenticated = True
                self.send_command('5051')
            else:
                alarmserver_logger('Proxy User Authentication failed')
                self.send_command('5050')
                self.close()

    def send_command(self, data, checksum = True):
        if checksum == True:
            to_send = data+get_checksum(data, '')+'\r\n'
        else:
            to_send = data+'\r\n'

        self.push(to_send)

    def handle_close(self):
        alarmserver_logger('Proxy connection from %s closed' % self._straddr)
        if self._straddr in CONNECTEDCLIENTS: del CONNECTEDCLIENTS[self._straddr]
        self.close()

    def handle_error(self):
        alarmserver_logger('Proxy connection from %s errored' % self._straddr)
        if self._straddr in CONNECTEDCLIENTS: del CONNECTEDCLIENTS[self._straddr]
        self.close()

class EnvisalinkProxy(asyncore.dispatcher):
    def __init__(self, config, server):
        self._config = config
        if self._config.ENABLEPROXY == False:
            return

        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        alarmserver_logger('Envisalink Proxy Started')

        self.bind(("", self._config.ENVISALINKPROXYPORT))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            alarmserver_logger('Incoming proxy connection from %s' % repr(addr))
            handler = ProxyChannel(server, self._config.ENVISALINKPROXYPASS, sock, addr)

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
    if LOGTOFILE:
        outfile=open(config.LOGFILE,'a')
        print ('Writing logfile to %s' % config.LOGFILE)

    alarmserver_logger('Alarm Server Starting')
    alarmserver_logger('Currently Supporting Envisalink 2DS/3 only')
    alarmserver_logger('Tested on a Honeywell Vista 15p + EVL-3')


    server = AlarmServer(config)
    proxy = EnvisalinkProxy(config, server)

    try:
        while True:
            asyncore.loop(timeout=2, count=1)
            # insert scheduling code here.
    except KeyboardInterrupt:
        print "Crtl+C pressed. Shutting down."
        alarmserver_logger('Shutting down from Ctrl+C')
        if LOGTOFILE:
            outfile.close()
        
        server.shutdown(socket.SHUT_RDWR) 
        server.close() 
        sys.exit()