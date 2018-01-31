#!/usr/bin/env python3
import os
import stat

_fd_types = (
    ('REG', stat.S_ISREG),
    ('FIFO', stat.S_ISFIFO),
    ('DIR', stat.S_ISDIR),
    ('CHR', stat.S_ISCHR),
    ('BLK', stat.S_ISBLK),
    ('LNK', stat.S_ISLNK),
    ('SOCK', stat.S_ISSOCK)
)

fd_comments = {}

def fd_table_status(desired=None):
    result = []
    for fd in range(1024):
        try:
            s = os.fstat(fd)
        except:
            continue
        for fd_type, func in _fd_types:
            if func(s.st_mode):
                break
        else:
            fd_type = str(s.st_mode)
        if desired is None or desired == fd_type:
            result.append((fd, fd_type))
    return result

def fd_table_status_logify(fd_table_result):
    #return ('Open file handles: ' +
    #        ', '.join(['{0}: {1}'.format(*i) for i in fd_table_result]))
    return '\n'.join(['  %d - %s' % (fd, str(fd_comments.get(fd))) for fd,_ in fd_table_result])

def fd_table_status_str(desired=None):
    return fd_table_status_logify(fd_table_status(desired))

def fd_add_comment(fds, comment):
    if fds is None:
        return
    if type(fds) == int:
        fds = [fds]
    for fd in fds:
        fd_comments[fd] = comment


