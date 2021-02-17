import threading
import logging
from time import sleep

from syspce_message import *


log = logging.getLogger('sysmoncorrelator')

class Engine(threading.Thread):
    def __init__(self, data_buffer_in, data_condition_in,
                                 src, daemon):

        threading.Thread.__init__(self)
        self.data_buffer_in = data_buffer_in
        self.data_condition_in = data_condition_in
        self._running = False
        self.name = ''
        self.module_id = -1
        self.origin = Module.ENGINE_MANAGER
        self.src = src
        self.daemon_ = daemon


    def run(self):
        self._running = True
        self.do_action()

    def send_message(self, content):

        message = Message(self.data_buffer_in, self.data_condition_in)
        message.send(MessageType.ALERT,
             MessageSubType.DETECT,
             self.module_id,
             self.src,
                                 self.origin,
                                 [content])


    def do_action(self):
        # To be overridden
        pass

    def terminate(self):
        self._running = False
        log.debug("%s ending..." % (self.name))
