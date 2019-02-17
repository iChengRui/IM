#!/usr/bin/env python3
# -*- coding:utf8 -*-
"""
Server for  a chat room.
"""
import asyncio
import os
import selectors
import signal
import socket
import ssl
import sys
from abc import ABCMeta, abstractmethod
from math import inf as f
from ssl import Purpose
import redis
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(BASE_DIR))
from IM.imutility import get_option, option

# Your own CA,you can change it
MY_CA = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.crt"
MY_CA_KEY = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.key"

# trusted CA(the peers)
TRUSTED_CA = BASE_DIR + os.sep + "trustedCA"
TRUSTED_CA_FILE = TRUSTED_CA + os.sep + "CAfile.pem"

option.add_argument('-i', '--IP', help="本端IP地址", action='store',
                    required=True)
option.add_argument('-p', '--PORT', help="本端端口", action='store',
                    type=int, required=True)
option.add_argument('-S', '--SERVER', help="存储数据库IP地址", action='store',
                    required=True)
option.add_argument('-P', '--SERVERPORT', help="存储数据库端口", action='store',
                    type=int, default=6379)
option.add_argument('-K', '--KEY', help="存储数据库密码", action='store',
                    default=None)
option.add_argument('-d', '--DB', help="数据库序号", action='store',
                    type=int, default=0)
option.add_argument('-n', '--NAME', help="群组名称", action='store',
                    type=str, required=True)

# Mapping connction to members.
gb_connpair = dict()

gb_selector = selectors.DefaultSelector()


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
        self._group = groupname
        self._groupcontent = groupname + ":content"

    def is_member(self, name: str):
        return self._handle.hexists(self._group, name)

    def join_in(self, name: str):
        return self._handle.hset(self._group, name, t())

    def write(self, data, timestamp):
        self._handle.zadd(self._groupcontent, data, timestamp)

    def read_list(self, name):
        timestamp = self._handle.hget(self._group, name)
        content = self._handle.zrangebyscore(self._groupcontent, float(timestamp), f)
        return b"".join(content[1:])

    def update(self, name, timestamp):
        return self._handle.hset(self._group, name, timestamp)

    def save(self):
        self._handle.save()


def quit_handle(dbhandle: object):
    """
    Save data before quit.
    :param dbhandle:
    :return:
    """

    def handler(signum, stackframe):
        dbhandle.save()
        return None

    return handler

def t():
    """
    Return current time as string.
    :return:
    """
    return str(time.time())

class ServerProtocol(asyncio.Protocol):
    handle = None

    def __init__(self):
        self.timestamp = list()
        self.name = None

    def connection_made(self, transport):
        global  gb_connpair
        self.transport = transport

    def data_received(self, data):
        global  gb_connpair

        timestamp = t()
        others = gb_connpair.copy()
        if self.name is None:
            self.name, _ = data.split(b":")

            if self.handle.is_member(self.name):
                content = self.handle.read_list(self.name)
                self.transport.write(content)
                self.timestamp.append(timestamp)
            else:
                self.handle.join_in(self.name)

            gb_connpair[self] = self.name
            data =b" join in\n"
        else:
            others.pop(self, None)

        if data == b'\n':
            self.handle.update(self.name, timestamp[0])
            del self.timestamp[0]
        else:
            data=self.name+b":"+data
            self.handle.write(data, float(timestamp))
            for con, name in others.items():
                try:
                    print(name)
                    con.transport.write(data)
                    con.timestamp.append(timestamp)
                except:
                    gb_connpair.pop(con, None)

    def connection_lost(self, exc):
        global gb_connpair
        gb_connpair.pop(self,None)
        self.transport.close()

    def eof_received(self):
        self.connection_lost(None)



def main():
    """
    Start up,One group One Process.
    :return:
    """
    parsedoption = get_option(sys.argv[1:], option)

    h = redis.Redis(host=parsedoption.SERVER, port=parsedoption.SERVERPORT,
                    password=parsedoption.KEY)
    r = RedisStorage(h, parsedoption.NAME)
    ServerProtocol.handle = r

    ctx = ssl.SSLContext()
    ctx.load_cert_chain(MY_CA, keyfile=MY_CA_KEY)
    ctx.load_verify_locations(cafile=TRUSTED_CA_FILE, capath=TRUSTED_CA)

    loop = asyncio.get_event_loop()

    coro = loop.create_server(ServerProtocol, host=parsedoption.IP,
                              port=parsedoption.PORT, backlog=512,
                              ssl=ctx,
                              reuse_address=True, reuse_port=True
                              )

    server = loop.run_until_complete(coro)

    for i in [signal.SIGHUP, signal.SIGINT, signal.SIGTSTP]:
        signal.signal(i, quit_handle(r))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        r.save()

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    main()
