#!/usr/bin/env python3
# -*- coding:utf8 -*-
"""
Server for  a chat room.
"""
import socket
import os
import sys
import selectors
import ssl
import redis
from abc import ABCMeta, abstractmethod
from time import time as t
from math import inf as f
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(BASE_DIR))
from IM.imutility import get_option, option

# Your own CA,you can change it
MY_CA = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.crt"
MY_CA_KEY = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.key"

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

# Member join in immediately.
gb_initial_group = set()
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
        # Bug !!! As set can't store same contents.
        self._handle.zadd(self._groupcontent, data, timestamp)

    def read_list(self, name):
        timestamp = self._handle.hget(self._group, name)
        content = self._handle.zrangebyscore(self._groupcontent, timestamp, f)
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


def rcv(conn):
    """
    Return content from the conn.
    :param conn:
    :return:
    """
    content = bytearray()
    global gb_initial_group
    global gb_connpair
    while True:
        piece = conn.recv(4096)
        content.extend(piece)
        if len(content) > 0:
            if len(piece) == 0 or b'\n' in piece:
                break
        else:
            try:
                gb_initial_group.remove(conn)
            except KeyError:
                try:
                    gb_connpair.pop(conn)
                except KeyError:
                    pass
                except:
                    pass
            except:
                pass
            break
    return bytes(content)


def accept_(conn,handle):
    """
    Accept new comer.

    :param conn:
    :return:
    """
    global gb_initial_group, gb_connpair, gb_selector
    con,addr= conn.accept()
    gb_initial_group.add(con)
    gb_selector.register(con, selectors.EVENT_READ, add_new)


def add_new(conn, handle):
    """
    Add new comer to a group.

    :param conn:
    :param handle:
    :return:
    """
    global gb_initial_group, gb_connpair, gb_selector
    content = rcv(conn)
    timestamp = t()
    gb_selector.unregister(conn)
    if content:
        joiner = ssl.wrap_socket(conn,
                                 keyfile=MY_CA_KEY,
                                 certfile=MY_CA,
                                 server_side=True,
                                 cert_reqs=ssl.CERT_NONE,
                                 )
        peername, _ = content.split(b":")
        others = gb_connpair.copy()
        gb_connpair[joiner] = peername
        handle.write(b"".join((peername, b" join in\n")), timestamp)
        if handle.is_member(peername):
            content = handle.read_list(peername)
            joiner.sendall(content)
            handle.update(peername, timestamp)
        else:
            handle.join_in(peername)
        for con, name in others.items():
            try:
                con.sendall(peername + b" join in\n")
                handle.update(name, timestamp)
            except:
                gb_connpair.pop(con)
        gb_initial_group.remove(conn)
        gb_selector.register(joiner, selectors.EVENT_READ, broadcast)
    else:
        gb_initial_group.remove(conn)


def broadcast(conn, handle):
    """
    Broadcasting conntent received.
    :param conn:
    :param handle:
    :return:
    """
    global gb_connpair
    content = rcv(conn)
    if content:
        others = gb_connpair.copy()
        others.pop(conn)
        timestamp = t()
        content = b"".join((gb_connpair[conn], b":", content))
        handle.write(content, timestamp)
        handle.update(gb_connpair[conn],timestamp)
        for con, name in others.items():
            try:
                con.sendall(content)
                handle.update(name, timestamp)
            except:
                gb_connpair.pop(con)
    else:
        # Actually,when conn ends connection,it will disappear.
        # Following is useless.
        try:
            del gb_connpair[conn]
        except KeyError:
            pass


def main():
    """
    Start up,One group One Process.
    :return:
    """
    parsedoption = get_option(sys.argv[1:], option)

    h = redis.Redis(host=parsedoption.SERVER, port=parsedoption.SERVERPORT,
                    password=parsedoption.KEY)
    r = RedisStorage(h, parsedoption.NAME)

    sock = socket.socket()
    sock.bind((parsedoption.IP, parsedoption.PORT))
    sock.listen()
    gb_selector.register(sock, selectors.EVENT_READ, accept_)
    for i in [signal.SIGHUP, signal.SIGINT, signal.SIGTSTP]:
        signal.signal(i, quit_handle(r))
    while True:
        events = gb_selector.select()
        for key, handle in events:
            callback = key.data
            handle = r
            callback(key.fileobj, handle)


if __name__ == '__main__':
    main()
