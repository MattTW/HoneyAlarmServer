import os,logging
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

    #simple plugin system
    subclasses=[]

    @classmethod
    def find_subclasses(cls,path):
        """ Find all subclass of of this class in py files located below path
        (does look in sub directories)
        """


        for root, dirs, files in os.walk(path):
            for name in files:
                if name.endswith(".py") and not name.startswith("__"):
                    path = os.path.join(root[2:], name)     #remove ./ from beginning of root
                    modulename = path.rsplit('.', 1)[0].replace('/', '.')
                    cls.look_for_subclass(modulename)

        return cls.subclasses

    @classmethod
    def look_for_subclass(cls, modulename):
        logging.debug("searching %s" % (modulename))
        module=__import__(modulename)

        #walk the dictionaries to get to the last one
        d=module.__dict__
        for m in modulename.split('.')[1:]:
            d=d[m].__dict__

        #look through this dictionary for things that are subclass of Job but are not Job itself
        for key, entry in d.items():
            if key == cls.__name__:
                continue

            try:
                if issubclass(entry, cls):
                    logging.debug("Found subclass: "+key)
                    cls.subclasses.append(entry)
            except TypeError:
                #this happens when a non-type is passed in to issubclass. We
                #don't care as it can't be a subclass of Job if it isn't a type
                continue
