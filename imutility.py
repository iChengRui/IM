import argparse
import hmac
import logging
import math
import os
import selectors
import ssl
import sys
from typing import List
import unicodedata as uni
import string

Arg = List[str]
asciiprintable = string.printable
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
        if i not in asciiprintable and uni.east_asian_width(i) in "FW":
            content_width += 1
    back = '\033[F\033[K' * math.ceil(content_width / width)
    sys.stdout.write(back)
    return None


class Connector(object):
    """
    Class which handle the connection.
    """

    def __init__(self, sock=None, conntype=None, key=None, active=True,
                 const=None, output=sys.stdout, input_=sys.stdin, myname=None,
                 timeout=None):
        """

        :param sock: the sock you will connect or listen.
        :param conntype: whether and how messages are enciphered.there are
        three choices('plaintext', 'AuthenKey', 'SSL').
        :param key: your cert private key
        :param active: if you're listening False; otherwise True.
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
        self.active = active  # you connect actively or passively
        self.last = "info"  # the person sends the last message
        self.key = key
        self.output = output
        self.input_ = input_
        self.myname = myname
        if active:
            self.peersock = sock
            self.conntype = conntype
            self.peername = input("peer name:")
            if conntype != "plaintext":
                if const:
                    self.ssl_param_init(const)
                else:
                    logging.error("lack constant variable")
                    raise Exception("lack constant variable")

            logging.info("Try to connect:{0!s}".format(self.peersock))
            self.connect_active()
            self.peersock.settimeout(None)
            self.show("info", "Connection succeeds.Start your conversation.\n")
            self.last = "info"
            logging.info("Connect succeeds:{0!s}:{1!s}".format(self.conntype,
                                                               self.peername))
            self.multi.register(self.peersock, selectors.EVENT_READ, self.read)
        else:
            if const:
                self.ssl_param_init(const)
            else:
                logging.error("lack constant variable")
                raise Exception("lack constant variable")

            self.multi.register(sock, selectors.EVENT_READ, self.accept)

    def connect_active(self):
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

            message = input("input a sentence(20 words or less):").encode(
                'utf-8')
            self.peersock.send(message)
            logging.debug("Active:message:{}:key:{}".format(message, self.key))

            digest = hmac.new(self.key.encode("utf8"), message).hexdigest()

            recvdigest = self.peersock.recv(4096)
            logging.debug("receive authentic digest:{}".format(recvdigest))

            if hmac.compare_digest(digest, recvdigest.decode("utf8")):
                logging.debug("authenticated")
                self.peersock.send(b"\n")
                self.peersock = ssl.wrap_socket(self.peersock)
                logging.debug("wrap peersock finished")
            else:
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

    def connect_passive(self):
        """
        The passive sock which is listening.
        depending on the other side choice of conntype, do the connection.

        :return: a connected socket.
        """
        if self.conntype == 'plaintext':
            pass

        elif self.conntype == 'AuthenKey':
            if not self.key:
                self.key = input("enter the password:")

            message = self.peersock.recv(4096)
            logging.debug("passive:message is:{}:key is:{}".format(
                message, self.key))

            digest = hmac.new(self.key.encode("utf8"), message).hexdigest()
            self.peersock.send(digest.encode("utf8"))
            logging.debug("digest has been send")

            if self.peersock.recv(4096) != b"\n":
                logging.error("Athentic failed")
                raise Exception("Can't Authenticate,Check your password")

            self.peersock = ssl.wrap_socket(self.peersock,
                                            keyfile=self.MY_CA_KEY,
                                            certfile=self.MY_CA,
                                            server_side=True,
                                            cert_reqs=ssl.CERT_NONE,
                                            )
            logging.debug("wrapp peersock finished")
        else:
            logging.info("MY_CA:{}:MY_CA_KEY:{}:key:{}:RUSTED_CA_FILE:{}"
                         ":TRUSTED_CA:{}".format(self.MY_CA, self.MY_CA_KEY,
                                                 self.key, self.TRUSTED_CA_FILE,
                                                 self.TRUSTED_CA))
            self.peersock = ssl.wrap_socket(self.peersock,
                                            keyfile=self.MY_CA_KEY,
                                            certfile=self.MY_CA,
                                            server_side=True,
                                            cert_reqs=ssl.CERT_REQUIRED,
                                            ca_certs=self.TRUSTED_CA_FILE)
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
            if self.last == self.myname:
                name = ""
            else:
                name = self.myname
                self.last = name
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
            if self.last == self.peername:
                name = ""
            else:
                name = self.peername
                self.last = name
        self.show(name, content)

    def multiplex(self):
        """
        IO multiplex constructor.
        :return: a selector instance.
        """
        return selectors.DefaultSelector()

    def accept(self, sock, mask):
        """
        Waiting for the other to connect.
        :param sock: the listening socket.
        :param mask: useless, retaining.
        :return: None
        """
        self.peersock, addr = sock.accept()
        if self.timeout is not None:
            self.peersock.settimeout(self.timeout * 8)

        message = self.peersock.recv(4096).decode("utf8").split(":")
        self.peername = message[0].strip()
        self.conntype = message[1].strip()
        logging.info("Recive connction from:{}:"
                     "conncet type:{}".format(self.peername, self.conntype))
        self.show("info", "connection from:" + self.peername + "authentic way:" \
                  + self.conntype + '\n')
        self.last = "info"
        self.multi.unregister(sock)
        sock.close()

        self.connect_passive()
        self.multi.register(self.peersock, selectors.EVENT_READ, self.read)
        self.peersock.settimeout(None)
        self.show("info", "Authentication succeeds.Start your conversation.\n")
        self.last = "info"
        logging.info("Connected to :{}".format(self.peername))

    def show(self, name: str, content: str):
        """
        Display contents or shutdown if the other exit.

        :param name: the name of content owner.
        :param content: received from peer side.
        """
        if self.output == sys.stdout and self.input_ == sys.stdin:
            o = sys.stdout
            if name is not "":
                if name == self.peername:
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

    def init_input(self, input=None):
        """"
        input.
        input,a file-like object.
        """
        self.input_ = input
        self.multi.register(input, selectors.EVENT_READ, self.read)
