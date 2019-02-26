#!/usr/bin/env python3
# -*- coding: utf8 -*-

"""
One to one  and one to group instant message communication,support plain text,
SSL,Authenticated key,certificate.

This is client side connecting to others actively.

Before certificate is used,send your cert to the other side /trustedCA/CAfile.pem.
Download and use it DIRECTLY.

"""
import hmac
import logging
import os
import selectors
import socket
import ssl
import string
import sys
from time import gmtime, strftime, sleep

ASCIIPRINTABLE = string.printable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.dirname(BASE_DIR))
from IM.Asyncioutility import get_option, option, terminal_clean

# logging file directory
LOGGING_DIR = BASE_DIR + os.sep + "Logging" + os.sep + "sender" + os.sep

# trusted CA(the peers)
TRUSTED_CA = BASE_DIR + os.sep + "trustedCA"
TRUSTED_CA_FILE = TRUSTED_CA + os.sep + "CAfile.pem"

# Your own CA
MY_CA = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.crt"
MY_CA_KEY = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.key"
# the password for the above key,must be string, None if no password
MY_CA_KEY_PWD = "1234"

TIMEOUT = 20


class Connector(object):
    """
    Class which handle the connection.
    """

    def __init__(self, sock=None, conntype=None, key=None, const=None,
                 output=sys.stdout, input_=sys.stdin, myname=None,
                 timeout=None, othername=None, way=None):
        """

        :param sock: the sock you will connect or listen.
        :param conntype: whether and how messages are enciphered.there are
        three choices('plaintext', 'AuthenKey', 'SSL').
        :param key: your cert private key
        :param const: the global variables.
        :param output: interface displays message.
        :param timeout: timeout in seconds.
        :param myname: your name.
        # TODO
        :param output
        :param input_


        """
        self.multi = self.multiplex()
        self.timeout = timeout
        self.last = "info"  # the person sends the last message
        self.key = key
        self.output = output
        self.input_ = input_
        self.myname = myname
        self._othername = othername
        self._way = way

        self.peersock = sock
        self.conntype = conntype
        if conntype != "plaintext":
            if const:
                self.ssl_param_init(const)
            else:
                logging.error("lack constant variable")
                raise Exception("lack constant variable")

        logging.info("Try to connect:{0!s}".format(self.peersock))
        self.connect()
        self.peersock.settimeout(None)
        self.show("info", "Connection succeeds.Start your conversation.\n")

        logging.info("Connect succeeds:{0!s}:{1!s}".format(self.conntype,
                                                           self._othername))
        self.multi.register(self.peersock, selectors.EVENT_READ, self.read)

    def connect(self):
        """
        The active connector make connection.
        depending on the conntype, do the connection.

        :return: a connected socket.
        """
        if self.conntype == 'plaintext':
            pass
        elif self.conntype == 'AuthenKey':
            if self.key is None:
                self.key = input("enter the password:")
                message = bytearray()
                while b'\n' not in message:
                    ps = self.peersock.recv(4096)
                    message.extend(ps)
                    if len(ps) == 0:
                        break
            logging.debug("Active:message:{}:key:{}".format(message, self.key))

            digest = hmac.new(self.key.encode("utf8"), message).hexdigest()
            self.peersock.sendall(digest.encode("utf8"))
            c=None

            while c!=b"\n":
                sleep(1)
                try:
                    # Socket is non-blocking.
                    c = self.peersock.recv(1)
                except Exception as e:
                    logging.debug("sock receive no info :{}".format(e))

            logging.debug("received comparision :{}".format(c))
            try:
                self.peersock = ssl.wrap_socket(self.peersock)
            except Exception:
                logging.error("authentication failed")
                raise Exception("can't Authenticate,Check your password")
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False
            logging.info("Acitve:RUSTED_CA_FILE:{}:TRUSTED_CA:{}".format(
                self.TRUSTED_CA_FILE, self.TRUSTED_CA))

            context.load_verify_locations(cafile=self.TRUSTED_CA_FILE,
                                          capath=self.TRUSTED_CA)
            if not self.key:
                self.key = self.MY_CA_KEY_PWD
            logging.info("MY_CA:{}:MY_CA_KEY:{}:key:{}".format(self.MY_CA,
                                                               self.MY_CA_KEY,
                                                               self.key))

            context.load_cert_chain(self.MY_CA, keyfile=self.MY_CA_KEY,
                                    password=self.key)
            self.peersock = context.wrap_socket(self.peersock)
            logging.debug("wrapp peersock finished")

    def ssl_param_init(self, const):
        """
        Initialize the SSL environment,if necessary.
        :param const: the dictionary which contains the params.
        :return: None
        """
        param = [
            'MY_CA', 'MY_CA_KEY', 'MY_CA_KEY_PWD',
            'TRUSTED_CA', 'TRUSTED_CA_FILE',
        ]
        for i in param:
            setattr(self, i, const[i])

    def read(self, conn, mask):
        """
         IO reading from yourself or peer end.
        :param conn: the connection.
        :param mask: useless,retaining.
        :return: None.
        """
        if conn == self.input_:
            content = self.input_.readline()
            if content=='\n':
                return
            if self.last == self.myname:
                name = ""
            else:
                name = self.myname
                self.last = name
            self.show(name, content)
            content = self._othername + ":" + self.myname + ":" + content
            self.peersock.sendall(content.encode("utf8"))
        else:
            content = bytearray()
            while True:
                piece = conn.recv(4096)
                content.extend(piece)
                if len(content) > 0:
                    if b'\n' in piece or len(piece) == 0:
                        content = content.decode("utf8")
                        break
                else:
                    content = 'peer is closed:{}\n'.format(conn)
                    self.show('info', content)
                    self.multi.unregister(conn)
                    conn.close()
                    logging.info(content)
                    sys.exit(0)
            self.parse_contents(content)

    @staticmethod
    def multiplex():
        """
        IO multiplex constructor.
        :return: a selector instance.
        """
        return selectors.DefaultSelector()

    def show(self, name: str, content: str):
        """
        Display contents or shutdown if the other exit.

        :param name: the name of content owner.
        :param content: received from peer side.
        """

        if self.output == sys.stdout and self.input_ == sys.stdin:
            o = sys.stdout
            if name is not "":
                if name == self._othername:
                    o.write("\033[0;31;42m" + name + ":" + "\033[0m\n")
                elif name == self.myname:
                    terminal_clean(content)
                    o.write("\033[0;32;41m" + name + ":" + "\033[0m\n")
                else:
                    o.write("\033[0;32;47m" + name + ":" + "\033[0m\n")
            else:
                if self.last == self.myname:
                    return
            o.write("\033[0;32;0m" + content + "\033[0m")
        else:
            self.output(name, content)

    def init_input(self, input_=None):
        """"
        input.
        input,a file-like object.
        """
        self.input_ = input_
        self.multi.register(input_, selectors.EVENT_READ, self.read)

    def parse_contents(self, content: str):
        
        contentlist = content.splitlines(keepends=True)

        for i in contentlist:
            if self._way == "group":
                groupname, contenttext = i.split(":", maxsplit=1)
            else:
                # groupname=peername
                groupname, peername, contenttext = i.split(":", maxsplit=2)
            if self.last == self._othername:
                name = ""
            else:
                name = self._othername
                self.last = name

            self.show(name, contenttext)

        if self._way == "group":
            self.peersock.send(b'\n')


def main():
    # logging
    logfile = LOGGING_DIR + strftime("%Y-%m-%d", gmtime()) + ".log"
    fmt = "{levelname!s}:{asctime}:{filename!s}:{lineno!s}:{message!s}"
    logging.basicConfig(filename=logfile, format=fmt, style='{',
                        level=logging.DEBUG)
    # get params
    parsedoption = get_option(sys.argv[1:], option)

    my_name = parsedoption.SELFNAME

    try:
        sock = socket.create_connection((parsedoption.IP, parsedoption.PORT),
                                        TIMEOUT)
    except (socket.error, socket.timeout) as e:
        logging.error("socket creation Failure:{}".format(e))
        raise
    except Exception as e:
        logging.error("unknown Failure:{}".format(e))
        raise

    message = my_name[:20] + ":" + parsedoption.METHOD + "\n"
    sock.sendall(message.encode("utf8"))
    way, peername = sock.recv(1024).decode().strip().split(":")

    if way == "group" and parsedoption.METHOD == "plaintext":
        parsedoption.METHOD = "SSL"
    try:
        connector = Connector(sock=sock, conntype=parsedoption.METHOD,
                              key=parsedoption.KEY, const=globals(),
                              myname=my_name, timeout=TIMEOUT,
                              othername=peername, way=way)
    except (socket.error, socket.timeout) as e:
        logging.error("socket creation Failure:{}".format(e))
        raise
    except Exception as e:
        logging.error("unknown Failure:{}".format(e))
        raise
    # STDIN, receive your input.
    connector.init_input(sys.stdin)

    while True:
        events = connector.multi.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    option.add_argument('-i', '--IP', help="对端IP地址", action='store',
                        required=True)
    option.add_argument('-p', '--PORT', help="对端端口", action='store',
                        type=int, required=True)
    option.add_argument('-k', '--KEY', help="CA私钥密码", action='store')
    option.add_argument('-m', '--METHOD', help="通信的方式(明文，密码，密钥)",
                        action='store',
                        choices=['plaintext', 'AuthenKey', 'SSL'],
                        default='plaintext')
    option.add_argument('-n', '--SELFNAME', help="自己的名字", action='store',
                        type=str, required=True)

    main()
