import asyncio
import logging
import os
import socket
import sys
from time import gmtime, strftime
import ssl
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.dirname(BASE_DIR))
from IM.imutility import Connector, get_option, option

# logging file directory
LOGGING_DIR = BASE_DIR + os.sep + "Logging" + os.sep + "sender" + os.sep

# trusted CA(the peers)
TRUSTED_CA = BASE_DIR + os.sep + "trustedCA"
TRUSTED_CA_FILE = TRUSTED_CA + os.sep + "CAfile.pem"

# Your own CA
MY_CA = BASE_DIR + os.sep + "myCA" + os.sep + "otherCA.crt"
MY_CA_KEY = BASE_DIR + os.sep + "myCA" + os.sep + "otherCA.key"
# the password for the above key,must be string, None if no password
MY_CA_KEY_PWD = "1234"

MY_NAME = "Sender"
TIMEOUT = 20

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


def get_input(in_, out):
    data = in_.readline().encode()
    if data:
        out(data)


class ClientProtocol(asyncio.Protocol):
    def __init__(self, name, loop):
        self._name = name.encode()
        self._loop = loop
        self._transport = None
        self._namelen=len(self._name)

    def connection_made(self, transport):
        self._transport = transport
        self._transport.write(self._name + b':' + b"ssl" + b'\n')
        # TODO find out why it doesn't work.
        # self._loop.add_reader(sys.stdin,
        #                       self._transport.write,
        #                       sys.stdin.readline().encode())
        self._loop.add_reader(sys.stdin, get_input, sys.stdin,
                              self._transport.write)

    def data_received(self, data):
        print(data.decode())
        self._transport.write(b'\n')

    def connection_lost(self, exc):
        print('The server closed the connection')
        print('Stop the event loop')
        self._loop.stop()


def main():

    parsedoption = get_option(sys.argv[1:], option)
    MY_NAME = parsedoption.SELFNAME
    loop = asyncio.get_event_loop()

    ctx = ssl.SSLContext()
    ctx.load_cert_chain(MY_CA, keyfile=MY_CA_KEY, password=MY_CA_KEY_PWD)
    ctx.load_verify_locations(cafile=TRUSTED_CA_FILE, capath=TRUSTED_CA)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False

    coro = loop.create_connection(lambda: ClientProtocol(MY_NAME, loop),
                                  parsedoption.IP, parsedoption.PORT,
                                  ssl=ctx)
    loop.run_until_complete(coro)

    loop.run_forever()
    loop.close()


if __name__ == '__main__':
    main()
