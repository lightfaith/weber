#!/usr/bin/env python3
"""
Commands and config methods are implemented here.
"""

from source import weber
from source import lib
from source import log
import os, sys

def reload_config():
    log.info('Loading config file...')
    with open(os.path.join(os.path.dirname(sys.argv[0]), 'config'), 'r') as f:
        for line in f.readlines():
            line = line.strip()
            if len(line) == 0 or line.startswith('#'):
                continue
            k, _, v = line.partition('=')
            log.debug_config('  line: \'%s\'' % (line))
            k = k.strip()
            v = v.strip()
            if v.isdigit():
                v = int(v)
            if lib.positive(v):
                v = True
            if lib.negative(v):
                v = False
            weber.config[k] = v
            log.info('  %s = %s' % (k, v))
            log.debug_config('  parsed: %s = %s (%s)' % (k, v, str(type(v))))
    log.ok('Go!')



"""
Universal class for commands.
"""
class Command():
    def __init__(self, command, description, function):
        self.command = command
        self.description = description
        self.function = function

    def run(self, *args):
        return self.function(*args)

    def __repr__(self):
        return 'Command(%s)' % (self.command)

    def __str__(self):
        return 'Command(%s)' % (self.command)

"""
Function to add new command
"""
def add_command(command):
    weber.commands[command.command.partition(' ')[0]] = command


"""
Function to run commands, apply filters etc.
"""
def run_command(fullcommand):
    log.debug_command('  Fullcmd: \'%s\'' % (fullcommand))
    command, _, grep = fullcommand.partition('~')
    # only help?
    if command.endswith('?') and len(command)>1:
        lines = ['    %-13s %s' % (v.command, v.description) for k, v in weber.commands.items() if k.startswith(command[:-1]) and len(k)-len(command[:-1])<=1]
    else:
        try:
            command, *args = command.split(' ')
            log.debug_command('  Command: \'%s\'' % (command))
            log.debug_command('  Args:    %s' % (str(args)))
            lines = weber.commands[command].run(*args)
        except Exception as e:
            log.err('Cannot execute command '+str(e)+'.')
            return
    log.tprint('\n'.join([line for line in lines if grep in line]))


"""
TEST COMMANDS
"""
def test_function(*args):
    result = []
    result.append('Hello world!')
    result.append('It is a nice day, IS IT NOT??')
    result += log.ok('It works!', stdout=False)
    result.append(str(args))
    return result
add_command(Command('test', 'prints test message', test_function))
add_command(Command('testa', 'prints test equation', lambda *args: ['1+1=2']))


