#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
One to one instant message communication,support plain text,SSL,Authenticated
key,certificate.
This is server side waiting for others to connect.
Before certificate is used,add peer cert to the /trustedCA/CAfile.pem.
Download and use it DIRECTLY.

"""

import logging
import os
import socket
import sys
from time import gmtime, strftime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(BASE_DIR))
from IM.imutility import Connector, get_option,option


# the logging file
LOGGING_DIR = BASE_DIR + os.sep + "Logging" + os.sep + "receiver" + os.sep

# trusted CA(the peers)
TRUSTED_CA = BASE_DIR + os.sep + "trustedCA"
TRUSTED_CA_FILE = TRUSTED_CA + os.sep + "CAfile.pem"

# Your own CA,you can change it
MY_CA = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.crt"
MY_CA_KEY = BASE_DIR + os.sep + "myCA" + os.sep + "myCA.key"
# the password for the above key,must be string, None if no password
MY_CA_KEY_PWD = None

MY_NAME = "Receiver"
TIMEOUT = 15

option.add_argument('-i', '--IP', help="对端或本端IP地址", action='store',
                    required=True)
option.add_argument('-p', '--PORT', help="对端或本端端口", action='store',
                    type=int, required=True)
option.add_argument('-k', '--KEY', help="CA私钥密码", action='store')


def main():
    # logging
    logfile = LOGGING_DIR + strftime("%Y-%m-%d", gmtime()) + ".log"
    fmt = "{levelname!s}:{asctime}:{filename!s}:{lineno!s}:{message!s}"
    logging.basicConfig(filename=logfile, format=fmt, style='{',
                        level=logging.INFO)
    logging.basicConfig()
    # get params
    parsedoption = get_option(sys.argv[1:],option)

    sock = socket.socket()
    sock.bind((parsedoption.IP, parsedoption.PORT))
    sock.listen(1)
    logging.info("start listening-IP:{}PORT:{}".format(parsedoption.IP,
                                                       parsedoption.PORT))
    try:
        conn = Connector(sock, active=False, myname=MY_NAME, const=globals())
    except (socket.error, socket.timeout) as e:
        logging.error("socket creation Failure:{}".format(e))
        raise
    except Exception as e:
        logging.error("unknown Failure:{}".format(e))
        raise

    logging.info("Multiplex started")
    # STDIN, receive your input.
    conn.init_input(sys.stdin)
    # STDOUT, receive your output.
    # conn.init_output(sys.stdout)

    while True:
        events = conn.multi.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == "__main__":
    main()
