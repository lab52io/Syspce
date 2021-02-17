import threading
import logging

from syspce_message import *


log = logging.getLogger('sysmoncorrelator')


class Manager_(threading.Thread):
    def __init__(self, data_buffer_in, data_condition_in):
        threading.Thread.__init__(self)
        self.data_buffer_in = data_buffer_in
        self.data_condition_in = data_condition_in
        self.modules_list = {}

        self._running = False

        # to be set by the subclass
        self.name = ''
        self.module_id = None
        self.messages_accepted = []

    def run(self):
        self._running = True
        log.debug("%s ready" % (self.name))

        while self._running:
            with self.data_condition_in:

                # get only messages to our module
                messages = self._read_messages(self.data_buffer_in)

                while not messages and self._running:
                    # check if all modules did their jobs
                    self.check_alive_modules()

                    log.debug("%s - Wainting for commands/data " % (self.name))
                    self.data_condition_in.wait(1)
                    messages = self._read_messages(self.data_buffer_in)

            self._process_messages(messages)

        log.debug("%s terminated." % (self.name))


    def _read_messages(self, data_buffer_in):
        message_list = []

        # checking if this message is for me
        len_buffer = len(data_buffer_in)
        i = 0

        while i != len_buffer:
            message = data_buffer_in[i]

            if (message._dst == self.module_id) and \
                (message._type in self.messages_accepted):

                # it's mine , let's pop it
                message_list.append(data_buffer_in.pop(i))
                len_buffer -= 1
            else:
                i += 1

        return message_list

    def send_message(self, destination, message_subtype,
                                     origin, content):

        message = Message(self.data_buffer_in, self.data_condition_in)
        message.send(MessageType.COMMAND,
             message_subtype,
             self.module_id,
             destination,
                                 origin,
                                 [content])

    def _process_messages(self, message_list):
        # To be implemented by the subclass
        pass

    def add_working_module(self, job_name, modules):
        ''' Associate which modules are related to one job
                Dicckey jobname , module is a list of object
                modules.
        '''
        if self.modules_list.has_key(job_name):
            self.modules_list[job_name] += modules
        else:
            self.modules_list[job_name] = modules

    def stop_job_modules(self, job_name):
        ''' Stops a job, one job can involve multiple modules'''
        log.debug("%s stoping modules from %s" % (self.name, job_name))

        if self.modules_list.has_key(job_name):
            for module in self.modules_list[job_name]:
                if module.is_alive():
                    module.terminate()
                    module.join()

            # if I'm CM dont send to myself job done
            if self.name != Module.CONTROL_MANAGER:

                #Inform that all done to the Job module
                self.send_message(job_name, MessageSubType.JOB_DONE,
                                                        self.module_id, [])

            del self.modules_list[job_name]

        else:
            log.debug("%s module %s dosen't exist" % (self.name, job_name))

    def _terminate(self):
        for job_name in self.modules_list:
            for module in self.modules_list[job_name]:
                if module.is_alive():
                    log.debug("%s terminating %s %s" % (self.name, module.name, module.ident))
                    module.terminate()
                    module.join()

        self._running = False

    def check_alive_modules(self):
        ''' Checks if all modules in modules list are alive
                and decide if a Job is done (1 Job -> N worker modules)
                if done then notify to current Job held by CM
        '''

        jobs_list = self.modules_list.keys()

        if not jobs_list:
            log.debug("[%s] No jobs alive" % (self.name))

        for job_name in jobs_list:
            all_modules_done = True

            '''
            for module in self.modules_list[job_name]:
                    if module.is_alive():
                            log.debug("[%s] module  %s alive" % (self.name,module.name))
                            all_modules_done = False
            '''

            i = 0
            while i < len(self.modules_list[job_name]):
                module = self.modules_list[job_name][i]
                if module.is_alive():
                    log.debug("[%s] module  %s alive" % (self.name,module.name))
                    all_modules_done = False
                    i += 1
                else:
                    self.modules_list[job_name].pop(i)

            if all_modules_done:
                log.debug("[%s] All modules from %s did their work" % (self.name,job_name))
                del self.modules_list[job_name]

                # if I'm CM dont send to myself job done
                if self.name != Module.CONTROL_MANAGER:

                    #Inform that all done to the Job module
                    self.send_message(job_name, MessageSubType.JOB_DONE,
                                                      self.module_id, [])

    def daemon_module_executing(self, job_name):
        if self.modules_list.has_key(job_name):
            for module in self.modules_list[job_name]:
                if module.is_alive() and module.daemon_:
                    return True
        else:
            print "No existe la clave %s en:" % job_name
            print self.modules_list
        return False
