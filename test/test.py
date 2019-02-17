#!/usr/bin/env python3
#  -*- coding: utf8 -*-

import os
import sys
import multiprocessing as mltp
import signal

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(BASE_DIR))

from IM.imsender import main as snd_main
from IM.imreceiver import main as rev_main

gb_evnt=mltp.Event()

def as_input(io_, content: str):
    io_.write(content)
    io_.flush()

def get_output(io_):
    t=io_.readline()
    return t


def reciever():
    port = 8888
    needconnect = True
    while needconnect:
        try:
            sys.argv[1:] = ["-i", "localhost", "-p", str(port)]
            rev_main()
        except ConnectionRefusedError:
            port += 1
        except:
            print("Unexpected Error.")
            sys.exit(-1)
        else:
            needconnect = False


def sender(method: str):
    incontent = ["-i", "localhost", "-p", None, "-m", None]
    needconnect = True
    port = 8888

    incontent[5] = method

    while needconnect:
        try:
            incontent[3] = str(port)
            sys.argv[1:] = incontent
            gb_evnt.set()
            snd_main()
            print("in sender main",file=sys.stderr)
        except ConnectionRefusedError:
            port += 1
        except:
            print("Unexpected Error.")
            sys.exit(-1)
        else:
            needconnect = False
    print("in Sender")

class TestSender():

    def __init__(self, method):

        if sys.platform.startswith("win"):
            print("windows platform is not supported."
                  "Use Linux instead.")
            sys.exit(0)


        revoutr, revoutw = os.pipe()
        revinr, revinw = os.pipe()
        revpid = os.fork()
        if revpid:
            os.close(revoutw)
            os.close(revinr)
            self.revin = os.fdopen(revinw, "w")
            self.revout = os.fdopen(revoutr, "r")

            sndoutr, sndoutw = os.pipe()
            sndinr, sndinw = os.pipe()
            sndpid = os.fork()
            if sndpid:
                os.close(sndoutw)
                os.close(sndinr)
                self.sndin = os.fdopen(sndinw,"w")
                self.sndout = os.fdopen(sndoutr, "r")
                # for Record
                self.revrecord = open("recieverecord", "w+")
                self.sndrecord = open("senderrecord", "w+")
                gb_evnt.wait()
                # os.write(sndinw,b"receiver\n")
                as_input(self.sndin, "Receiver\n")
                self.revrecord.write(get_output(self.revout))
                as_input(self.sndin, "changes\n")
                # as_input(self.sndin, "great!\n")

                self.revrecord.write(get_output(self.revout))
                self.revrecord.write(get_output(self.revout))
                self.revrecord.write(get_output(self.revout))
                self.revrecord.write(get_output(self.revout))
                self.revrecord.write(get_output(self.revout))
                self.revrecord.write(get_output(self.revout))

                # Terminate
                os.kill(sndpid, signal.SIGQUIT)
                os.kill(revpid, signal.SIGQUIT)
                self.revrecord.close()
                self.sndrecord.close()
            else:
                os.close(sndoutr)
                os.close(sndinw)
                os.dup2(sndinr, sys.stdin.fileno())
                os.dup2(sndoutw,sys.stdout.fileno())
                sender(method)
        else:
            os.close(revoutr)
            os.close(revinw)
            os.dup2(revinr, sys.stdin.fileno())
            os.dup2(revoutw,sys.stdout.fileno())
            reciever()


if __name__ == '__main__':
    TestSender("plaintext")
