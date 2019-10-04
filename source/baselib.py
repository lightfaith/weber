#!/usr/bin/env python3
"""
General-purpose stuff without any project dependencies is defined here.
"""
import difflib
import subprocess


def positive(x):
    if type(x) == str:
        x = x.lower()
    if x in ['yes', 'y', '+', '1', 1, 'true', 't', True]:
        return True
    return False


def negative(x):
    if type(x) == str:
        x = x.lower()
    if x in ['no', 'n', '-', '0', 0, 'false', 'f', False]:
        return True
    return False


def quit_string(x):
    if type(x) != str:
        return False
    x = x.lower()
    if x in ['quit', 'exit', 'q', 'end', ':wq']:
        return True
    return False


def find_between(data, startbytes, endbytes, startpos=0, endpos=0, inner=False):
    """
    This function goes through data[startpos:endpos] and locates 
    substrings 'startbytes.*endbytes'.

    inner specifies whether startbytes and endbytes should be 
    included in match_string.

    Returns:
        list of (absolute_position, match_string)
    """
    if endpos == 0:
        endpos = len(data)
    result = []
    while True:
        try:
            """set up start, find end from it"""
            offset = data.index(startbytes, startpos)
            start = offset+(len(startbytes) if inner else 0)
            end = data.index(endbytes, start)+(0 if inner else len(endbytes))
            if end > endpos:
                """stop if outside the scope"""
                break
            result.append((offset, data[start:end]))
            """prepare for next search"""
            startpos = end
        except ValueError:  # out of bounds (no more matches)?
            break
    return result


def split_escaped(string, delimiter):
    if len(delimiter) != 1:
        raise ValueError('Invalid delimiter: ' + delimiter)
    ln = len(string)
    i = 0
    j = 0
    while j < ln:
        if string[j] == '\\':
            if j + 1 >= ln:
                yield string[i:j].replace('\\', '')
                return
            j += 1
        elif string[j] == delimiter:
            yield string[i:j].replace('\\', '')
            i = j + 1
        j += 1
    yield string[i:j].replace('\\', '')


def chunks(data, size):
    return[data[x:x+size] for x in range(0, len(data), size)]


def get_desired_indices(desired_str, minimum, maximum, fails=None):
    # 'fails' is None or list to be filled with bad 'desired' values
    indices = []
    #noproblem = True
    if not desired_str:
        # use all
        return list(range(minimum, maximum + 1))
    # parse
    for desired in desired_str.split(','):
        start = minimum
        end = maximum
        if '-' in desired:
            # interval
            _start, _, _end = desired.partition('-')
            if _start.isdigit():
                start = min([max([start, int(_start)]), end])
            elif not _start:
                pass
            else:
                #noproblem = False
                if fails:
                    fails.append(desired)
            if _end.isdigit():
                end = max([min([end, int(_end)]), start])
            elif not _end:
                pass
            else:
                #noproblem = False
                if fails:
                    fails.append(desired)
            if start > end:
                tmp = start
                start = end
                end = tmp
            indices.extend(range(start, end+1))
        else:
            # single value
            if desired.isdigit():
                indices.append(int(desired))
    return indices


def run_command(command):
    """
    Run command in shell.

    Args:
        command (str) - command to execute

    Returns:
        return code
        standard output
        standard error output
    """
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    return (p.returncode, out, err)


def diff_lines(lines_1, lines_2, form='D'):
    """
    Diffs 2 sets of lines. 

    Args:
        lines_1 (list of str): first sample
        lines_2 (list of str): second sample
        form (str): diff form to perform
                    D - full diff (default)
                    1 - only lines unique to first set
                    2 - only lines unique to second set
                    c - only common lines
                    d - only different lines
    """
    lines = [line for line in difflib.Differ().compare(lines_1, lines_2)
             if not line.startswith('?')]
    """alert with respect to form"""
    if form == '1':
        lines = [line[2:] for line in lines if line.startswith('-')]
    elif form == '2':
        lines = [line[2:] for line in lines if line.startswith('+')]
    elif form == 'c':
        lines = [line[2:] for line in lines
                 if not line.startswith(('-', '+'))]
    elif form == 'd':
        lines = [line for line in lines
                 if line.startswith(('-', '+'))]
    return lines


# --
