#!/usr/bin/python3
import traceback

class Watcher(object):
    def __init__(self, obj=None, attr=None, log_file='files/log.txt', enabled=False):
        """
            Debugger that watches for changes in object attributes
            obj - object to be watched
            attr - string, name of attribute
            log_file - string, where to write output
        """

        self.log_file=log_file
        with open(self.log_file, 'wb'): pass
        if obj:
            self.value = getattr(obj, attr)
        self.obj = obj
        self.attr = attr
        self.enabled = enabled # Important, must be last line on __init__.

    def __call__(self, *args, **kwargs):
        kwargs['enabled'] = True
        self.__init__(*args, **kwargs)

    def check_condition(self):
        tmp = getattr(self.obj, self.attr)
        result = tmp != self.value
        self.value = tmp
        return result

    def trace_command(self, frame, event, arg):
        if not self.enabled:
            return self.trace_command
        if not self.check_condition():
            return self.trace_command
        with open(self.log_file, 'ab') as f:
            print >>f, "Value of",self.obj,".",self.attr,"changed!"
            print >>f,"###### Before this line:"
            print >>f,''.join(traceback.format_stack(frame))
        return self.trace_command
import sys
watcher = Watcher()
sys.settrace(watcher.trace_command)
