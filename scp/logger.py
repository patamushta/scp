import eventlet
from eventlet.green import thread, threading

import logging
# from OpenStack Swift
logging.thread = eventlet.green.thread
logging.threading = eventlet.green.threading
logging._lock = logging.threading.RLock()


FORMAT = '[%(asctime)s]   %(levelname)-8s %(message)s'
datefmt = '%Y-%m-%d %H:%M:%S'
logging.basicConfig(format=FORMAT, datefmt=datefmt)
LOGGER = logging.getLogger('output-point')
LOGGER.setLevel(logging.DEBUG)

def log(msg):
    LOGGER.info(msg)
