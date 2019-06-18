'''
    Author: Dinesha Ranathunga
    Version: 1.0
    Date: 02/02/2018
    Description: Exception classes.
'''

class MuddyException(Exception):
    """ Application Exception base class"""
    # the following fails to populate exception.message
    def __init__(self, *args):
        # *args is used to get a list of the parameters passed in
        self.args = [a for a in args]
        # TODO: is there a better way to incorporate inner exception messages?
        message=''
        for arg in self.args:
            if isinstance(arg,Exception):
                message= message + ': ' + arg.message
            else:
                message= message + ': ' + arg
        self.message=message

class MuddyIncorrectFileFormatException(MuddyException):
    """ Incorrect file format"""

class OutputPathInvalidException(MuddyException):
    """ Incorrect output folder"""

class SecurityPolicyException(MuddyException):
    """ Security policy error"""

class PolicyRuleException(MuddyException):
    """ Policy rule error """

class ZoneConduitTopologyException(MuddyException):
    """ Zone-conduit topology error """

class SecurityZoneException(MuddyException):
    """ Security zone error """

class SecurityConduitException(MuddyException):
    """ Security conduit error"""

class  NetworkTopologyException(MuddyException):
    """ Network topology error"""

class  GraphHandlerException(MuddyException):
    """ Graph loader error"""

class  NetworkBuilderException(MuddyException):
    """ Network builder error"""

class HelperException(MuddyException):
    """ Helper error """

class ProtocolException(MuddyException):
    """ Protocol error"""

class ParseException(MuddyException):
    """ Parser error """

class ArgumentException(MuddyException):
    """ Argument error """

class AlgebraicModelHelperException(MuddyException):
    """ Algebraic model helper error """

class OverlayNotFound(MuddyException):

    def __init__(self, errors):
        self.Errors = errors

    def __str__(self):
        return 'Overlay %s not found' % self.Errors


