import pkg_resources
import log as log
from library.exception import ParseException
import threading
import sys

try:
    FFW_VERSION = pkg_resources.get_distribution("muddy").version
except pkg_resources.DistributionNotFound:
    FFW_VERSION = "dev"

def console_entry():
    """If come from console entry point"""
    args = parse_options()
    main(args)

def parse_options(argument_string=None):
    """Parse user-provided options"""
    import argparse
    usage = "muddy -f input.txt"
    version = "%(prog)s " + str(FFW_VERSION)
    parser = argparse.ArgumentParser(description=usage, version=version)

    input_group = parser.add_mutually_exclusive_group()

    input_group.add_argument('--createmud', nargs=1)
    input_group.add_argument('--checkmud', nargs=1)
    input_group.add_argument('--bpcompare', nargs=1)

    parser.add_argument('--debug', action="store_true",
                        default=False, help="Debug mode")
    if argument_string:
        arguments = parser.parse_args(argument_string.split())
    else:
        # from command line arguments
        arguments = parser.parse_args()
    return arguments

def main(options):
    from input_parser import InputParser
    log.info("muddy %s" % FFW_VERSION)

    if options.debug:
        import logging
        logger = logging.getLogger("muddy")
        logger.setLevel(logging.DEBUG)

    try:
        # run on background thread
        #thread = threading.Thread(target=parse_input, args=[options])
        #thread.daemon = True                            # Daemonize thread
        #thread.start()
        #while(thread.isAlive()):
        #    pass
        parse_input(options)

    except ParseException,e:
        log.debug("Error checking policy", exc_info=True)
        sys.exit("Unable to check policy.")
    except Exception, err:
        log.error(
            "Error checking MUD policy: %s. More information may be available in the debug log." % err)
        log.debug("Error checking MUD policy", exc_info=True)
        sys.exit("Unable to check MUD policy.")

def parse_input(options):
    """ validate and parse input high-level description file"""
    from input_parser import InputParser
    if options.createmud:
        log.info("Create MUD file(s) from flow rules in path: %s"%(options.createmud[0]))
        try:
            InputParser().create_mud_files(options.createmud[0])
        except BaseException,e:
            log.error('%s'%e.message)

    if options.checkmud:
        log.info("Check MUD file consistency using metagraphs")
        try:
            InputParser().check_mud_consistency(options.checkmud[0])
        except BaseException,e:
            log.error('%s'%e.message)

    if options.bpcompare:
        log.info("Check best practice compliance of MUD policy: %s"%(options.bpcompare[0]))
        try:
            InputParser().check_bp_compliance(options.bpcompare[0])
        except BaseException,e:
            log.error('%s'%e.message)

# !! The main function are only here for debug. The real compiler don't need this`!!
if __name__ == '__main__':
    import sys
    global warningfound
    from input_parser import InputParser

    csv_path = '/Documents/IOT/deviceFlowRules'
    InputParser().create_mud_files(csv_path)
    mudfile_path = '/Documents/IOT/results'
    InputParser().check_mud_consistency(mudfile_path)
    file = '/Documents/IOT/results/NetatmoWeatherStation/device_mud_profile.json'
    InputParser().check_bp_compliance(file)
    file1 = '/Users/a1070571/Documents/IOT/firmwarechanges/amazonEcho/amazonEchoMudnew.json'
    file2 = '/Users/a1070571/Documents/IOT/firmwarechanges/amazonEcho/amazonEchoMudOld.json'
    InputParser().get_mud_policy_semantic_difference(file2, file1)

