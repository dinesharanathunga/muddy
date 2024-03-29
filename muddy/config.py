import pkg_resources
import ConfigParser
from configobj import ConfigObj, flatten_errors
import os

import validate
validator = validate.Validator()

import os.path
ffw_user_dir = os.path.join(os.path.expanduser("~"),  ".muddy")

def load_config():
    settings = ConfigParser.RawConfigParser()
    spec_file = pkg_resources.resource_filename(__name__,"/config/configspec.cfg")
    settings = ConfigObj(configspec=spec_file, encoding='UTF8')
# User's FFW settings
    user_config_file = os.path.join(ffw_user_dir, "muddy.cfg")
    settings.merge(ConfigObj(user_config_file))
# FFW settings in current directory
    settings.merge(ConfigObj("muddy.cfg"))
# FFW settings specified by environment variable
    try:
        ffwcfg = os.environ['muddy_CFG']
        settings.merge(ConfigObj(ffwcfg))
    except KeyError:
        pass

    results = settings.validate(validator)
    if results != True:
        for (section_list, key, _) in flatten_errors(settings, results):
            if key is not None:
                error_msg=('Invalid key "%s" in section "%s"' % (key, ', '.join(section_list)))
                print("Error loading configuration file: %s"%error_msg)
                raise SystemExit
            else:
# ignore missing sections - use defaults
                pass
    return settings

#NOTE: this only gets loaded once package-wide if imported as import autonetkit.config
settings = load_config()
