import logging
import logging.handlers
import config


muddy_logger = logging.getLogger("muddy")
if not muddy_logger.handlers:
    console_formatter = logging.Formatter("%(levelname)-1s %(message)s")
    ch = logging.StreamHandler()
    #ch.setLevel(logging.INFO)
    ch.setFormatter(console_formatter)
    muddy_logger.addHandler(ch)

    file_logging = config.settings['Logging']['file']
    if file_logging:
        LOG_FILENAME =  "muddy.log"
        #fh = logging.FileHandler(LOG_FILENAME)
        LOG_SIZE = 2097152 # 2 MB
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILENAME, maxBytes=LOG_SIZE, backupCount=5)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s %(levelname)s "
            "%(funcName)s %(message)s")
        fh.setFormatter(formatter)
        muddy_logger.addHandler(fh)

muddy_logger.setLevel(logging.INFO)
# Reference for external access
logger = muddy_logger
# Use approach of Pika, allows for muddy.log.debug("message")
debug = logger.debug
error = logger.error
info = logger.info
warning = logger.warning
exception = logger.exception
critical = logger.critical
