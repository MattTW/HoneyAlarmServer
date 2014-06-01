import ConfigParser


class BaseConfig(object):
    def __init__(self, configfile):
        self._config = ConfigParser.ConfigParser()
        self._config.read(configfile)

    def defaulting(self, section, variable, default, quiet=False):
            if quiet is False:
                print('Config option ' + str(variable) + ' not set in ['+str(section)+'] defaulting to: \''+str(default)+'\'')

    def read_config_var(self, section, variable, default, type='str', quiet=False):
        try:
            if type == 'str':
                return self._config.get(section, variable)
            elif type == 'bool':
                return self._config.getboolean(section, variable)
            elif type == 'int':
                return int(self._config.get(section, variable))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            self.defaulting(section, variable, default, quiet)
            return default
