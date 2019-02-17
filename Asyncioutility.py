import argparse
import math
import os
import ssl
import string
import sys
import unicodedata as uni
from abc import ABCMeta, abstractmethod
from math import inf as f


ASCIIPRINTABLE = string.printable
from typing import List

Arg = List[str]
option = argparse.ArgumentParser(description="即时通信-IM，含加密功能")


def get_option(parmlist: Arg, option):
    """
    get the parameter to start with.
    :param parmlist: the options you choose, alias argv[1:].
     """
    parsedoption = option.parse_args(parmlist)

    return parsedoption


def terminal_clean(content: str):
    """
    Erase the terminal STDIN.

    IMPORTANT：The actual you need to know is the width(displayed on
     the terminal) of a charater, chinese characteristic is 2,while
      most eastern characteristic is 1.

     TO be Simple ,a *** not perfect *** way use unicodedata.east_asian_width().
     Someone may try Urwid, https://github.com/urwid/urwid.

    :param content_length:
    :return: None
    """
    width, height = os.get_terminal_size()
    content_width = 0
    for i in content:
        content_width += 1
        if i not in ASCIIPRINTABLE and uni.east_asian_width(i) in "FW":
            content_width += 1
    back = '\033[F\033[K' * math.ceil(content_width / width)
    sys.stdout.write(back)
    return None


def get_sslcontex(sslProtocol, sslverify, check_hostname, selfcafile,
                  selfcakey, verify_cafile, verify_cafile_capath, serverside,
                  needcheck=True):
    """
    Return ssl context.

    :param sslProtocol:
    :param sslverify:
    :param check_hostname: Boolean.
    :param selfcafile:
    :param selfcakey:
    :param verify_cafile:
    :param verify_cafile_capath:
    :param serverside: Boolean.
    :param needcheck: Boolean.
    :return:
    """
    context = ssl.SSLContext(sslProtocol)
    context.verify_mode = sslverify
    context.check_hostname = check_hostname

    if needcheck or serverside:
        context.load_cert_chain(selfcafile, selfcakey)

    if needcheck:
        context.load_verify_locations(cafile=verify_cafile,
                                      capath=verify_cafile_capath)
        context.verify_mode = ssl.CERT_REQUIRED

    return context


class Monitor(object):

    def __init__(self, selfname: str, in_=None, out_=None):
        self._last = None
        self._input = in_
        self._output = out_
        self.selfname = selfname
        self._peername = None

    def __call__(self, name: str, content: str):
        """
        Display contents or shutdown if the other exit.

        :param name: the name of content owner.
        :param content: received from peer side.
        """

        if self._output == sys.stdout and self._input == sys.stdin:
            o = sys.stdout
            if name == self._last:
                if self._last == self.selfname:
                    return
            else:
                self._last = name
                if name == self._peername:
                    o.write("\033[0;31;42m" + name + ":" + "\033[0m\n")
                elif name == self.selfname:
                    terminal_clean(content)
                    o.write("\033[0;32;41m" + name + ":" + "\033[0m\n")
                else:
                    o.write("\033[0;32;47m" + name + ":" + "\033[0m\n")
            o.write("\033[0;32;0m" + content + "\033[0m")
        else:
            raise NotImplementedError("please implement your input and output")


class MetaStorage(metaclass=ABCMeta):
    """
    Interface for database which stores content.
    """

    @abstractmethod
    def read_list(self, name):
        """
        Return list of conversation have received by name.
        :param name:
        :return:
        """
        pass

    @abstractmethod
    def write(self, data, timestamp):
        """
        Store the content of Group, in database.
        :param data:
        :return:
        """
        pass

    @abstractmethod
    def save(self):
        """
         Persist data.
        :return:
        """
        pass

    @abstractmethod
    def join_in(self, name: bytes):
        """
        Add a new member.
        :param name:
        :return:
        """
        pass

    @abstractmethod
    def is_member(self, name: bytes):
        """
        Return Whether name is member.
        :param name:
        :return:
        """
        pass

    @abstractmethod
    def update(self, name, timestamp):
        """
        Update content received timestamp of name.
        :param name:
        :param timestamp:
        :return:
        """
        pass

    @abstractmethod
    def timestamp(self):
        """

        :return: unique index for storage of  exactly same  conversation,as
        they(must be unique) are stored in set.
        """
        pass


class RedisStorage(MetaStorage):
    """
    Redis interface.
    """

    def __init__(self, handle, groupname: str):
        """

        :param handle: the handle of redis.
        :param groupname:
        """
        self._handle = handle
        self.groupname = groupname
        self._groupcontent = groupname + ":content"
        self._grouptimestamp = groupname + ":timestamp"
        self._handle.set(self._grouptimestamp, 0, nx=True)
        self.index = int(self._handle.get(self._grouptimestamp))

    def is_member(self, name: str):
        return self._handle.hexists(self.groupname, name)

    def join_in(self, name: str):
        return self._handle.hset(self.groupname, name, self.index)

    def write(self, data, timestamp:int):
        # timestamp is added to make data unique.

        # Below is not suitable as b":" may appear.
        # bytelen=math.ceil(timestamp.bit_length()/8)
        # bytestimestamp=timestamp.to_bytes(bytelen,byteorder="little")
        self._handle.zadd(self._groupcontent, data[:-1] + b":"
                          + str(timestamp).encode(), timestamp)

    def read_list(self, name):
        timestamp = self._handle.hget(self.groupname, name)
        content = self._handle.zrangebyscore(self._groupcontent,
                                             int(timestamp), f)
        ps = []
        # remove the timestamp.
        for i in content:
            ps.append(i.rsplit(b":", maxsplit=1)[0])
        return b"\n".join(ps[1:])+b"\n"

    def update(self, name, timestamp):
        return self._handle.hset(self.groupname, name, timestamp)

    def save(self):
        self._handle.save()

    def timestamp(self):
        self._handle.incr(self._grouptimestamp)
        self.index += 1
        return self.index


class DummyStorage(MetaStorage):
    """
    Dummy interface When Storage is not needed.
    """
    def __init__(self, handle, groupname: str):
        """

        :param handle: the handle of redis.
        :param groupname:
        """
        self._handle = handle
        self.groupname = groupname
        self._groupcontent = groupname + ":content"
        self._grouptimestamp = groupname + ":timestamp"
        self._index = int(self._handle.get(self._grouptimestamp))

    def not_implemented(self):
        pass

    timestamp = save = update = read_list = write = join_in = is_member = \
        not_implemented
