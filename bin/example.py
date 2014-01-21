#!/usr/bin/env python

import logging
import argparse
from socket import socket, SOCK_RAW, AF_PACKET
from rawsocket.linklayer import Ethernet

class PFPacketSender:
    def __init__(self, interface):
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((interface, 0))

    def send(self, frame):
        self.sock.send(frame)

    def __str__(self):
        return "PF_PacketSender"


class Logger:
    def __init__(self,  log_level=logging.DEBUG):
        self.log_level = log_level

    def get_formatter(self):
        return logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def get_logger(self, module_name):
        """Returns a Logger instance for the specified module_name"""
        logger = logging.getLogger(module_name)
        logger.setLevel(self.log_level)
        log_handler = logging.StreamHandler()
        log_handler.setFormatter(self.get_formatter())
        logger.addHandler(log_handler)
        return logger

def parse_args():
    parser = argparse.ArgumentParser(description="Run Ethernet Packet sender", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--interface", help="Ethernet Interface", default="eth0")
    parser.add_argument("-v", "--verbose", type=int, default=logging.DEBUG, help="Log verbosity")
    return parser.parse_args()

def main():
    args = parse_args()
    log = Logger().get_logger("main")
    log.info("Starting....")
    src_mac = None
    with open("/sys/class/net/%s/address" % args.interface) as f:
        src_mac = f.read().strip()

    ether = Ethernet(log, PFPacketSender(args.interface), src_mac)
    ether.xmit("ARP", hex(123))


if __name__ == '__main__':
    main()
