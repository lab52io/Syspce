try:
    from enum import Enum
except:
	print "Missing dependencies enum"
	print "#pip install enum34 --user"
	exit(1)




class MessageType(Enum):
    UNKNOW = 0
    DATAIN = 1
    COMMAND = 2
    ALERT = 3
    COMMAND_RES = 4

class MessageSubType(Enum):
    UNKNOW = 0
    TERMINATE = 1
    READ_FROM_FILE = 2
    READ_FROM_EVENTLOG = 3
    FILTER_DATA = 4
    DETECT = 5
    READ_FROM_MEMDUMP = 6
    SHOW_JOBS = 7
    STOP_JOB = 8
    JOB_DONE = 9
    STATS = 10
    SHOW_CONFIG = 11
    SET_CONFIG = 12
    RUN = 13

class JobType(Enum):
    UNKNOW = 0
    DAEMON = 1
    SINGLE_ACTION = 2


class Module(Enum):
    UNKNOW = 0
    INPUT_MANAGER = 1
    ENGINE_MANAGER = 2
    CONTROL_MANAGER = 3
    SYSPCE_CORE = 4
    INPUT_EVTX = 5
    INPUT_EVENTLOG = 6
    JOB = 7
    FILTER_ENGINE = 8
    CONSOLE = 9
    MANAGE_TREE = 10
    HIERARCHY_ENGINE = 11
    BASELINE_ENGINE = 12
    INPUT_VOLATILITY = 13

class Origin(Enum):
    UNKNOW = 0
    CONSOLE = 1
    NETWORK = 2
    SYSPCE_CORE = 3


class Message(object):

    def __init__(self, buffer, condition, type = 0,
                 subtype = 0, src= 0, dst= 0, origin= 0,
                 content= []):

        self._type = type
        self._subtype = subtype
        self._src = src
        self._dst = dst
        self._origin = origin
        self._content = content

        self.buffer = buffer
        self.condition = condition

    def __str__(self):
        string = self.get_dicctionary()

        return str(string)

    def get_dicctionary(self):
        dicc = {}
        dicc['type'] = self._type
        dicc['subtype'] = self._subtype
        dicc['src'] = self._src
        dicc['dst'] = self._dst
        dicc['origin'] = self._origin
        dicc['content'] = self._content

        return dicc

    def send(self, type=0, subtype=0, src=0, dst=0, origin=0, content=[]):

        if type:
            self._type = type
            self._subtype = subtype    
            self._src = src
            self._dst = dst

            # which command/module produced the creation of this 
		    # message, needed for identify which module produced
		    # de requested action/command.
            self._origin = origin

            self._content = content

        with self.condition:
            self.buffer.append(self)
            #print str(self.buffer[0]) + "\n"
            self.condition.notify_all()

