#!/usr/bin/env python3
# -*- coding: utf8 -*-

"""
One to one instant message communication,support plain text,SSL,Authenticated
key,certificate.
This is client side connecting to others actively.
Before certificate is used,send your cert to the other side /trustedCA/CAfile.pem.
Download and use it DIRECTLY.

"""

import logging
import os
import socket
import sys
from time import gmtime, strftime

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
option.add_argument('-n','--SELFNAME',help="自己的名字",action='store',
                    type=str,required=True)

def main():
    # logging
    logfile = LOGGING_DIR + strftime("%Y-%m-%d", gmtime()) + ".log"
    fmt = "{levelname!s}:{asctime}:{filename!s}:{lineno!s}:{message!s}"
    logging.basicConfig(filename=logfile, format=fmt, style='{',
                        level=logging.INFO)
    # get params
    parsedoption = get_option(sys.argv[1:], option)
    MY_NAME=parsedoption.SELFNAME

    try:
        sock = socket.create_connection((parsedoption.IP, parsedoption.PORT),
                                        TIMEOUT)
    except (socket.error, socket.timeout) as e:
        logging.error("socket creation Failure:{}".format(e))
        raise
    except Exception as e:
        logging.error("unknown Failure:{}".format(e))
        raise

    message = MY_NAME[:20] + ":" + parsedoption.METHOD + "\n"
    sock.sendall(message.encode("utf8"))
    try:
        connector = Connector(sock=sock, conntype=parsedoption.METHOD,
                              key=parsedoption.KEY, const=globals(),
                              myname=MY_NAME, timeout=TIMEOUT)
    except (socket.error, socket.timeout) as e:
        logging.error("socket creation Failure:{}".format(e))
        raise
    except Exception as e:
        logging.error("unknown Failure:{}".format(e))
        raise
    # STDIN, receive your input.
    connector.init_input(sys.stdin)
    # STDOUT, receive your output.
    # connector.init_output(sys.stdout)
    while True:
        events = connector.multi.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    main()
