#!/usr/bin/env python3
# -*- coding:utf8 -*-
"""
Asyncio Server for  a chat room or a listener waiting for connection.
"""

import asyncio
import hmac
import logging
import os
import random
import socket
import ssl
import sys
from string import ascii_letters, digits
from time import gmtime, strftime

import redis

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(BASE_DIR))
from IM.Asyncioutility import RedisStorage, DummyStorage, get_sslcontex, option, \
    get_option, Monitor

# the logging file
LOGGING_DIR = BASE_DIR + os.sep + "Logging" + os.sep + "receiver" + os.sep

# Your own CA,you can change it
MY_CA = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.crt"
MY_CA_KEY = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.key"

# trusted CA(the peers)
TRUSTED_CA = BASE_DIR + os.sep + "trustedCA"
TRUSTED_CA_FILE = TRUSTED_CA + os.sep + "CAfile.pem"

# Mapping connction to members.
gb_connpair = {}
# Server for one or group.
gb_sockonce = True

gb_sslauthenkey = get_sslcontex(ssl.PROTOCOL_TLS, ssl.CERT_NONE, False,
                                MY_CA, MY_CA_KEY, TRUSTED_CA_FILE, TRUSTED_CA,
                                True, needcheck=False)

gb_ssl = get_sslcontex(ssl.PROTOCOL_TLS, ssl.CERT_REQUIRED, False,
                       MY_CA, MY_CA_KEY, TRUSTED_CA_FILE, TRUSTED_CA,
                       True, needcheck=True)


def random_string(slen: int = 10):
    """
    Return  a string which length is slen.
    :param slen:
    :return:
    """
    samplestr = random.sample(ascii_letters + digits, slen)
    samplestr.append('\n')
    return "".join(samplestr).encode()


def get_input(in_, selfdisplay, prefx, out):
    data = in_.readline()
    if data:
        selfdisplay(selfdisplay.selfname, data)

        data = prefx + data.encode()
        out(data)


class ServerProtocol(asyncio.Protocol):
    """
    Transports and protocols IO.
    Handle is an instance for storage DB.
    """
    handle = None
    in_ = None
    out_ = None

    def __init__(self, peername, loop):
        self.timestamp = list()
        self._name = peername
        self._loop = loop
        self.transport = None

        if gb_sockonce:
            self._prefx = peername + ":" + ServerProtocol.out_.selfname + ":"
        else:
            self._prefx = ServerProtocol.handle.groupname + ":" + peername + ":"

        self._prefx = self._prefx.encode()

    def connection_made(self, transport):

        global gb_sockonce, gb_connpair
        self.transport = transport

        if gb_sockonce:
            self._loop.add_reader(self.in_, get_input, sys.stdin, self.out_,
                                  self._prefx, self.transport.write)
        else:
            if self.handle.is_member(self._name):
                content = self.handle.read_list(self._name)
                self.transport.write(content)
                self.timestamp.append(self.handle.index)
            else:
                self.handle.join_in(self._name)

            gb_connpair[self] = self._name
            data = self._prefx + b" join in\n"
            self.broadcast(data)

    def data_received(self, data):
        global gb_sockonce
        if gb_sockonce:
            selfname, peername, content = data.decode().split(":", maxsplit=2)
            self.out_(peername, content)
        else:
            self.broadcast(data)

    def broadcast(self, data):

        global gb_connpair
        timestamp = self.handle.timestamp()
        others = gb_connpair.copy()
        others.pop(self, None)

        if data == b'\n':
            self.handle.update(self._name, self.timestamp[0])
            try:
                del self.timestamp[0]
            except Exception:
                pass
        else:
            self.handle.write(data, timestamp)
            for con, name in others.items():
                try:
                    con.transport.write(data)
                    con.timestamp.append(timestamp)
                except Exception as e:
                    logging.debug("connection lost:{}:{}".format(self, e))
                    gb_connpair.pop(con, None)

    def connection_lost(self, exc):
        global gb_connpair
        gb_connpair.pop(self, None)
        self.transport.close()

    def eof_received(self):
        self.connection_lost(None)


class PassiveConnectAuthenkey(object):
    def __init__(self, key=None):
        self._conn = {}
        self._rcvdigest = {}
        self._rcvdigestlen = {}
        self._key = key

    def __call__(self, eventloop, conn, peername):

        if self._key is None:
            key = input("enter the password:")
            self._key = key

        if not self._conn.get(conn, None):
            message = random_string()
            conn.send(message)

            eventloop.remove_reader(conn.fileno())
            eventloop.add_reader(conn.fileno(), self, eventloop, conn, peername)

            digest = hmac.new(self._key.encode("utf8"), message).hexdigest()

            logging.debug("message:{}:key:{}:digest:{}".format(
                message, self._key, digest))

            self._conn[conn] = digest
            self._rcvdigestlen[conn] = len(digest.encode())
            self._rcvdigest[conn] = b""
        try:
            self._rcvdigest[conn] = self._rcvdigest[conn] + conn.recv(4096)
        except BlockingIOError:
            logging.debug("{}:BlockingIOError".format(conn))
            pass

        if len(self._rcvdigest[conn]) == self._rcvdigestlen[conn]:

            conn.send(b'\n')

            logging.debug("receive digest:{}".format(self._rcvdigest[conn]))

            if hmac.compare_digest(self._conn[conn],
                                   self._rcvdigest[conn].decode("utf8")):

                logging.debug("authenticated")
                loop.remove_reader(conn.fileno())

                coro = loop.connect_accepted_socket(
                    lambda: ServerProtocol(peername, loop),
                    conn, ssl=gb_sslauthenkey)

                asyncio.ensure_future(coro, loop=eventloop)

                logging.debug("wrap peersock finished")
            else:
                logging.error("authentication failed")
                conn.close()

                self._conn.pop(conn, None)
                self._rcvdigest.pop(conn, None)
                self._rcvdigestlen.pop(conn, None)


def passive_connect_plain(eventloop, conn, peername):
    """Add connection to event loop.

    :param loop: Event loop.
    :param conn: connection to the other side
    :param peername: the other name.
    :return:
    """
    loop.remove_reader(conn.fileno())
    coro = loop.create_connection(
        lambda: ServerProtocol(peername, loop), sock=conn)
    asyncio.ensure_future(coro, loop=eventloop)


def passive_connect_ssl(eventloop, conn, peername, sslcxt=gb_ssl):
    loop.remove_reader(conn.fileno())

    coro = loop.connect_accepted_socket(
        lambda: ServerProtocol(peername, loop),
        conn, ssl=sslcxt)

    asyncio.ensure_future(coro, loop=eventloop)


async def accept_(loop, sock, shake, sockonce, name):
    while True:
        conn, addr = await loop.sock_accept(sock)
        loop.add_reader(conn.fileno(), shake, conn, loop)
        if sockonce:
            content = "personal:" + name + "\n"
        else:
            content = "group:" + name + "\n"
        conn.sendall(content.encode())
        if sockonce:
            sock.close()
            break


class HandShake(object):
    """
    Waiting for the other side choice of connection.
    """

    def __init__(self, way, shakeway):
        self._waitedconn = {}
        self._way = way
        self._shakeway = shakeway

    def __call__(self, conn, eventloop):
        try:
            while b'\n' not in self._waitedconn.setdefault(conn, b""):
                content = conn.recv(2048)
                self._waitedconn[conn] = self._waitedconn[conn] + content
        except Exception as e:
            logging.error("unknown failure:{}".format(e))
            conn.close()
            raise
        else:
            peername, way = self._waitedconn[conn].decode().strip().split(":")
            try:
                self._shakeway[self._way, way](eventloop, conn, peername)
            except KeyError:
                logging.error(
                    "KeyError failure:selfway-{}:way-{}".format(self._way, way))
                conn.close()
            finally:
                self._waitedconn.pop(conn, None)


if __name__ == '__main__':

    # logging
    logfile = LOGGING_DIR + strftime("%Y-%m-%d", gmtime()) + ".log"
    fmt = "{levelname!s}:{asctime}:{filename!s}:{lineno!s}:{message!s}"
    logging.basicConfig(filename=logfile, format=fmt, style='{',
                        level=logging.DEBUG)

    option.add_argument('-i', '--IP', help="本端IP地址", action='store',
                        required=True)
    option.add_argument('-p', '--PORT', help="本端端口", action='store',
                        type=int, required=True)
    option.add_argument('-k', '--KEY', help="存储数据库密码", action='store',
                        default=None)
    option.add_argument('-S', '--SERVER', help="存储数据库IP地址", action='store',
                        default='localhost')
    option.add_argument('-P', '--SERVERPORT', help="存储数据库端口",
                        action='store', type=int, default=6379)
    option.add_argument('-K', '--DBKEY', help="存储数据库密码", action='store',
                        default=None)
    option.add_argument('-D', '--DB', help="数据库序号", action='store',
                        type=int, default=0)
    option.add_argument('-n', '--NAME', help="群组或个人名称", action='store',
                        type=str, required=True)
    option.add_argument('-m', '--WAY', help="群组或个人", action='store',
                        choices=['personal', 'group'], type=str, required=True)

    parsedoption = get_option(sys.argv[1:], option)

    passive_connect_authenkey = PassiveConnectAuthenkey(parsedoption.KEY)

    shakeway = {
        ('personal', 'plaintext'): passive_connect_plain,
        ('personal', 'AuthenKey'): passive_connect_authenkey,
        ('personal', 'SSL'): passive_connect_ssl,
        ('group', 'plaintext'): passive_connect_ssl,
        ('group', 'AuthenKey'): passive_connect_authenkey,
        ('group', 'SSL'): passive_connect_ssl,
    }

    if parsedoption.WAY == "group":
        h = redis.Redis(host=parsedoption.SERVER, port=parsedoption.SERVERPORT,
                        password=parsedoption.KEY)
        r = RedisStorage(h, parsedoption.NAME)
        gb_sockonce = False
    else:
        r = DummyStorage(None, parsedoption.NAME)
        ServerProtocol.in_ = sys.stdin
        ServerProtocol.out_ = Monitor(parsedoption.NAME, sys.stdin, sys.stdout)

    ServerProtocol.handle = r

    sock = socket.socket()
    sock.bind((parsedoption.IP, parsedoption.PORT))
    sock.listen()
    sock.setblocking(False)

    loop = asyncio.get_event_loop()
    handshake = HandShake(parsedoption.WAY, shakeway)
    loop.run_until_complete(
        accept_(loop, sock, handshake, gb_sockonce, parsedoption.NAME))
    try:
        loop.run_forever()
    except Exception:
        loop.close()
