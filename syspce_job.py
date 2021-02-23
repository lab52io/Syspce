import threading
import logging
import uuid

from syspce_message import *

log = logging.getLogger('sysmoncorrelator')

class Job(threading.Thread):
    def __init__(self, data_buffer_in, data_condition_in,
                             job_type, task_type, origin):

        threading.Thread.__init__(self)
        self.data_buffer_in = data_buffer_in
        self.data_condition_in = data_condition_in

        self.jobid = str(uuid.uuid4())
        self.name = 'Job_' + self.jobid
        self.module_id = Module.JOB

        self._running = False
        self.job_type = job_type
        self.task_type = task_type

        # % of managers tasks progress
        self.inputs_progress = 0
        self.engines_progress = 0

        # Job modules Status
        self.IM_job_done = True
        self.EM_job_done = True

        self.origin = origin

        #Input manager config tasks message
        self._IM_message = None

        #Engine manager config tasks message
        self._EM_message = None

        #Control manager message
        self._CM_message = None

        self._CM_original_content = []
        self._CM_original_message_type = -1
        self._CM_original_message_sub_type = -1

        self._EM_original_content = []
        self._EM_original_message_type = -1
        self._EM_original_message_sub_type = -1

    def run(self):
        self._running = True
        log.debug("%s working..." % (self.name))

        #Job not configured
        if not self._EM_message or not self._CM_message:
            log.error("%s - not configured " % (self.name))
            self.terminate()
        else:
            # Sending first message
            if self._IM_message:
                self.IM_job_done = False
                self._IM_message.send()
                log.debug("%s - sent message to INPUT MANAGER " % (self.name))
            else:
                self.EM_job_done = False
                self._EM_message.send()
                log.debug("%s - sent message to ENGINE MANAGER " % (self.name))



        while self._running:
            with self.data_condition_in:
                messages = self._read_messages(self.data_buffer_in)

                while not messages and self._running:
                    log.debug("%s - Wainting for messages " % (self.name))
                    self.data_condition_in.wait(1)
                    messages = self._read_messages(self.data_buffer_in)

            for message in messages:

                #routing algorithm
                ###################

                # management action terminate
                if message._subtype == MessageSubType.TERMINATE:
                    self.terminate()

                elif message._subtype == MessageSubType.STOP_JOB:
                    self.terminate_notify()

                # management action job done
                elif message._origin == Module.INPUT_MANAGER and \
                         message._type == MessageType.COMMAND and \
                         message._subtype == MessageSubType.JOB_DONE:

                    self.IM_job_done = True

                # management action job done
                elif message._origin == Module.ENGINE_MANAGER and \
                         message._type == MessageType.COMMAND and \
                         message._subtype == MessageSubType.JOB_DONE:

                    self.EM_job_done = True

                # message comming from IM with data, lets send it to EM
                elif message._origin == Module.INPUT_MANAGER:
                    try:
                        #print message._content

                        self.EM_job_done = False
                        self.configure_EM(self._EM_original_message_type,
                                                          self._EM_original_message_sub_type,
                                                          self._EM_original_content)

                        self._EM_message._content = list(self._EM_original_content)
                        self._EM_message._content += message._content
                        self._EM_message.send()

                        log.debug("%s - sent message to ENGINE MANAGER " % (self.name))
                    except Exception, e:
                        log.error("%s - failed:  %s " % (self.name, e))
                        self.terminate()

                # message comming from IM with data, lets send it to EM
                elif message._origin == Module.ENGINE_MANAGER:
                    try:
                        self.configure_CM(self._CM_original_message_type,
                                                          self._CM_original_message_sub_type,
                                                          self._CM_original_content)

                        self._CM_message._content = list(self._CM_original_content)
                        self._CM_message._content += message._content
                        self._CM_message._type = message._type
                        self._CM_message._subtype = message._subtype
                        self._CM_message._src = message._src
                        self._CM_message.send()

                        log.debug("%s - sent message to CONTROL MANAGER " % (self.name))
                    except Exception, e:
                        log.error("%s - failed:  %s " % (self.name, e))
                        self.terminate()
                else:
                    self.terminate()

                # Finally check if all modules did their job
                if self.IM_job_done and self.EM_job_done:
                    self.terminate()

        log.debug("%s terminated." % (self.name))

    def configure_IM(self, message_type, message_sub_type, content):

        self._IM_message = Message(self.data_buffer_in,
                                                           self.data_condition_in,
                                                           message_type,
                                                           message_sub_type,
                                                           self.name,
                                                           Module.INPUT_MANAGER,
                                                           Module.JOB,
                                                           content)

    def configure_EM(self,message_type, message_sub_type, content):
        self._EM_original_content = content
        self._EM_original_message_type = message_type
        self._EM_original_message_sub_type = message_sub_type

        self._EM_message = Message(self.data_buffer_in,
                                                           self.data_condition_in,
                                                           message_type,
                                                           message_sub_type,
                                                           self.name,
                                                           Module.ENGINE_MANAGER,
                                                           Module.JOB,
                                                           content)

    def configure_CM(self, message_type, message_sub_type, content):
        self._CM_original_content = content
        self._CM_original_message_type = message_type
        self._CM_original_message_sub_type = message_sub_type

        self._CM_message = Message(self.data_buffer_in,
                                                           self.data_condition_in,
                                                           message_type,
                                                           message_sub_type,
                                                           self.name,
                                                           Module.CONTROL_MANAGER,
                                                           self.origin,
                                                           content)


    def _read_messages(self, data_buffer_in):
        message_list = []

        # checking if this message is for me
        len_buffer = len(data_buffer_in)
        i = 0

        while i != len_buffer:
            message = data_buffer_in[i]

            if (message._dst == self.name):
                log.debug("%s - found message from  %s " % (self.name, message._src))

                # it's mine , let's pop it
                message_list.append(data_buffer_in.pop(i))
                len_buffer -= 1

            elif (message._subtype == MessageSubType.TERMINATE):
                log.debug("%s - found message from  %s " % (self.name, message._src))

                # it's mine , but its a terminate dont pop it
                message_list.append(data_buffer_in[i])
                break
            else:
                i += 1

        return message_list

    def terminate_notify(self):
        ''' Notify managers to stop current tasks'''

        # Notify managers to stop current activity regarding this job
        Message(self.data_buffer_in,self.data_condition_in ).send(
                        MessageType.COMMAND, MessageSubType.STOP_JOB,
                        self.name, Module.INPUT_MANAGER)

        Message(self.data_buffer_in,self.data_condition_in).send(
                        MessageType.COMMAND, MessageSubType.STOP_JOB,
                        self.name, Module.ENGINE_MANAGER)

        log.debug("%s ending and managers notified..." % (self.name))

    def terminate(self):
        self._running = False
        log.debug("%s ending..." % (self.name))
