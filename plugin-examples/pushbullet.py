import logging
import os
import pushbullet

from basePlugin import BasePlugin
from pushbullet import Listener
from pushbullet import Pushbullet

#Fill out the following from here
API_KEY = 'APIKEY'
HTTP_PROXY_HOST = None
HTTP_PROXY_PORT = None
#to here

pb = Pushbullet(API_KEY)
note = 0
title = 0

def on_push(data):
	print('Received data:\n{}'.format(data))
	
class PBPlugin(BasePlugin):

	

	def armedAway(self, user):
		global note
		global title
		note = "Security system armed away by " + user
		title = "Alarm Server Security Alert"
		self.post()

	def armedHome(self, user):
		global note
		global title
		note = "Security system armed stay by " + user
		title = "Alarm Server Security Alert"
		self.post()

	def disarmedAway(self, user):
		global note
		global title
		note = "Security system disarmed from away status by " + user
		title = "Alarm Server Security Alert"
		self.post()

	def disarmedHome(self, user):
		global note
		global title
		note = "Security system disarmed from stay status by " + user
		title = "Alarm Server Security Alert"
		self.post()

	def alarmTriggered(self, user):
		global note
		global title
		note = "Security Alarm triggered at " + zone
		title = "Alarm Server Security Alert"
		self.post()

	def alarmCleared(self, user):
		global note
		global title
		note = "The Triggered Alarm has been cleared"
		title = "Alarm Server Security Alert"
		self.post()

	def envisalinkUnresponsive(self, user):
		global note
		global title
		note = "EVL not responding"
		title = "Alarm Server Security Alert"
		self.post()

	def post(self):
	    pb = Pushbullet(API_KEY)
 	    push = pb.push_note(title, note)

	    s = Listener(account=pb,
 	                on_push=on_push,
 	                http_proxy_host=HTTP_PROXY_HOST,
 	                http_proxy_port=HTTP_PROXY_PORT)
