import ConfigParser
from baseConfig import BaseConfig

class BasePlugin(BaseConfig):

    def __init__(self, configfile):
        #call ancestor for common setup
        super(BasePlugin, self).__init__(configfile)


    #methods that ancestors should implement if wanting to act on condition
    def armedAway(self,user):
      """implement when you want on alarm system being armed away"""
      return

    def armedHome(self,user):
      return

    def disarmedAway(self,user):
      return

    def disarmedHome(self,user):
      return

    def alarmTriggered(self,zone):
      return

    def alarmCleared(self,zone):
      return

    def isGuest(self,user): return isinstance(user, basestring) and user.lower().startswith('guest')
