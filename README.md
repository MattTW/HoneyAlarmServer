This project uses the [Ademco TPI provided by Eyez-On](http://forum.eyez-on.com/FORUM/viewtopic.php?f=6&t=301).  It processes events and passes commands to the Envisalink server and provides an easy to use HTTP interface for clients.

This project was originally a fork of the [AlarmServer project for DSC panels](https://github.com/juggie/AlarmServer) - credit to them for the base code.   However, the API's between DSC and Honeywell are so different that it didn't make sense to try to maintain a single codebase.

This is still beta software.  So far it has only been tested with an Envisalink 3 and Honeywell Vista 15p panel.

#### What Works ####

 + keypad update and partition state updates sent by the Envisalink as documented in the TPI are tracked by the Alarm Server and can be retrieved via the Web API.  
 + Some CID events (alarm arm/disarm) are processed and trigger plugin events.
 + HTTP calls to get current AlarmState, and to arm, disarm and armstay the alarm system are working.
 + Events are triggered for most alarm arming and disarming conditions
 + The [Mac Launcher app](https://github.com/gschrader/Alarm-Server-Launcher) originally writted for the DSC version of the server works with this app.

#### What Doesn't Work ####

+ The Web Interface app is not yet working.
+ Zone state change messages from the TPI seem to currently be buggy and are only logged at this time.
+ The Alarm state returned by the HTTP api call only returns partition state information so far.
+ Events for Alarm triggered/cleared are not yet working
+ The "FF" TPI command and application level commands to the Envisalink are not yet implemented.


Plugin System
-------------
A very basic plugin system has been implemented.   The plugins directory is searched for any python files containing classes that inherit from BasePlugin.

These classes override whatever events they are interested in responding to.  A cfg file of the format *ClassName*.cfg is automatically loaded if present.


Config
-------
Please see the alarmserver-example.cfg and rename to alarmserver.cfg and
customize to requirements.

There are example plugins in the plugin-examples directory.  Copy/modify and place them in the plugins directory along with a valid cfg file to use them



OpenSSL Certificate Howto
-------------------

The ssl certificates that are provided are intended for demo purposes only.  
Please use openssl to generate your own. A quick HOWTO is below.

To generate a self signed cert issue the following in a command prompt:
`openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout server.key -out server.crt`

Openssl will ask you some questions. The only semi-important one is the 'common name' field.
You want this set to your servers fqdn. IE alarmserver.example.com.

If you have a real ssl cert from a certificate authority and it has intermediate certs then you'll need to bundle them all up or the webbrowser will complain about it not being a valid cert. To bundle the certs use cat to include your cert, then the intermediates (ie cat mycert.crt > combined.crt; cat intermediates.crt >> combined.crt)


Dependencies:
-------------

On windows, pyOpenSSL is required.
http://pypi.python.org/pypi/pyOpenSSL


Launchers
---------
* [MacOSX](https://github.com/gschrader/Alarm-Server-Launcher)

REST API Info
-------------

*/api*

* Returns a JSON dump of all currently known states

*/api/alarm/arm*

* Quick arm

*/api/alarm/armwithcode?alarmcode=1111*

* Arm with a code
  * Required param = **alarmcode**

*/api/alarm/stayarm*

* Stay arm, no code needed

*/api/alarm/disarm*

* Disarm system
   * Optional param = **alarmcode**
   * If alarmcode param is missing the config file value is used instead
