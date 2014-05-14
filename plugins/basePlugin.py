import ConfigParser

class BasePlugin(object):

    #methods that ancestors should implement if wanting to act on condition
    def armedAway(self):
      """implement when you want on alarm system being armed away"""
      return

    def armedHome(self):
      return

    def armedInstant(self):
      return

    def disarmed(self):
      return

    #utility methods for config
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
