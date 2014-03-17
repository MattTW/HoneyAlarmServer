This project uses the [Ademco TPI provided by Eyez-On](http://forum.eyez-on.com/FORUM/viewtopic.php?f=6&t=301) to allow it to be used with Honeywell/Ademco security panels.

This is a heavily modified version of the parent project.   The parent project only implements the DSC Envisalink TPI and does not support Honeywell/Ademco panels.  The interfaces provided by the Envisalink vendor are fundamenatally different, this project's modifications may never be pulled back into the parent - that remains to be seen. 

This is still beta software.  So far it has only been tested with an Envisalink 3 and Honeywell Vista 15p panel.    The server has logic for the 0,1,2, and 3 commands from the Envisalink giving status updates about the panel.   0,2 state changes are tracked by the Alarm Server and can be retrieved via the Web API.   1,3 log debug messages only at this time.  FF TPI command and application commands to the Envisalink are not yet implemented.

The Web Interface app is not yet working.   However the underlying api, arm, disarm, and armstay http service calls are working, but are providing different data then the sample web client expects.

-------------

The ssl certificates that are provided are intended for demo purposes only.  
Please use openssl to generate your own. A quick HOWTO is below.

As with any project documentation is key, there is plenty more to go in here and
it will hopefully be soon!

Config:
Please see the alarmserver-example.cfg and rename to alarmserver.cfg and
customize to requirements.


Web Interface
-------------
The web interface uses a responsive design which limits the scrolling on both desktop and mobile.

### Desktop ###
![Desktop](http://gschrader.github.io/Alarm-Server-Launcher/desktop.png)

### Mobile ###
![Mobile](http://gschrader.github.io/Alarm-Server-Launcher/mobile.png)


OpenSSL Certificate Howto
-------------------

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

*/api/pgm*

* Activate a PGM output:
  * Required param = **pgmnum**
  * Required param = **alarmcode**

*/api/refresh*

* Refresh data from alarm panel

*/api/config/eventtimeago* 

* Returns status of eventtimeago from the config file

