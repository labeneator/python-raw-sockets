import struct


class EthernetExceptions:

    class MissingEtherDevice(Exception):
        pass

    class UnknownEtherType(Exception):
        pass

    class InvalidMACAddress(Exception):
        pass

    class OverSizedFrame(Exception):
        pass


class EtherTypes(object):
    """ Sourced from
    http://www.cavebear.com/archive/cavebear/Ethernet/type.html
    """
    SUPPORTEDTYPES = {
        "IP"        : 0x0800,
        "ARP"       : 0x0806,
        "RARP"      : 0x8035,
        "IPX"       : 0x8037,
        "EtherTalk" : 0x809B,
        "IPV6"      : 0x86DD
    }

    @classmethod
    def get_ethertype_from_name(cls, short_name):
        ether_type = EtherTypes.SUPPORTEDTYPES.get(short_name)
        if not ether_type:
            raise EthernetExceptions.UnknownEtherType("%s" % short_name)
        return struct.pack(">H", ether_type)


class Ethernet():
    def __init__(self, log,
                 ether_device,
                 src_mac_addr,
                 dst_mac_addr='ff:ff:ff:ff:ff:ff',
                 mtu=1500):
        self.ether_device = ether_device
        self.log = log
        self.src_mac_addr = src_mac_addr
        # defaults to this if missing from mkframe
        self.dst_mac_addr = dst_mac_addr
        self.mtu = mtu

    def mk_ether_type(self, ether_type_name):
        self.log.debug("looking for ether type: '%s'" % ether_type_name)
        return EtherTypes.get_ethertype_from_name(ether_type_name)

    def mac_str_to_hex(self, mac_address):
        """
        Receives a string mac address and returns an on-the-wire
        representation of it
        """
        mac_octets = [int(octet, 16) for octet in mac_address.split(":")]
        return struct.pack("B"*6, *mac_octets)

    def mk_src_mac(self, src_mac_addr):
        return self.mac_str_to_hex(src_mac_addr)

    def mk_dst_mac(self, dst_mac_addr):
        return self.mac_str_to_hex(dst_mac_addr)

    def mk_frame(self, dst_mac_addr, ether_type_name, msg):
        if not dst_mac_addr:
            dst_mac_addr = self.dst_mac_addr
        dst_mac = self.mk_dst_mac(dst_mac_addr)
        src_mac = self.mk_src_mac(self.src_mac_addr)
        ether_type = self.mk_ether_type(ether_type_name)
        return "".join([dst_mac, src_mac, ether_type, msg])

    def pad_frame(self, frame):
        """ Make sure that frames are 60 bytes long. The ethernet spec
        requires 64 byte frames. The 4 bytes CRC gets appended by the card.
        https://en.wikipedia.org/wiki/Ethernet_II_framing#Runt_frames
        """
        if len(frame) < 60:
            pad_len = 60 - len(frame)
            padding = struct.pack("B", 0) * pad_len
            frame += padding
        return frame

    def sanity_check_ether_device(self):
        if not hasattr(self.ether_device, 'send'):
            raise EthernetExceptions.MissingEtherDevice(
                "Etherdevice %s has no send method" % self.ether_device
            )

    def sanity_check_mac_addresses(self, src_mac_addr, dst_mac_addr):
        if not src_mac_addr:
            raise EthernetExceptions.InvalidMACAddress(
                "Source mac address is not defined")

        if len(src_mac_addr.split(":")) != 6:
            raise EthernetExceptions.InvalidMACAddress(
                "Invalid source mac address size")

        if not dst_mac_addr:
            raise EthernetExceptions.InvalidMACAddress(
                "Destination mac address is not defined")

        if len(dst_mac_addr.split(":")) != 6:
            raise EthernetExceptions.InvalidMACAddress(
                "Invalid destination mac address size")

    def validate_frame(self, frame):
        frame_size = len(frame)
        if frame_size > self.mtu:
            raise EthernetExceptions.OverSizedFrame(
                "Frame size:%s MTU:%s" % (frame_size, self.mtu))

    def xmit(self, ether_proto, msg, dst_mac_addr=None):
        if not dst_mac_addr:
            dst_mac_addr = self.dst_mac_addr

        self.log.debug("xmit request: src:%s: dst:%s proto:%s" % (
            self.src_mac_addr,
            dst_mac_addr,
            ether_proto))
        self.sanity_check_ether_device()
        self.sanity_check_mac_addresses(self.src_mac_addr, dst_mac_addr)
        frame = self.mk_frame(dst_mac_addr, ether_proto, msg)
        frame = self.pad_frame(frame)
        self.validate_frame(frame)
        self.log.info("EtherProto: %s: sending %s  bytes through %s" % (
            ether_proto, len(frame), self.ether_device))
        self.log.debug("Message: %s" % frame.encode("hex"))
        self.ether_device.send(frame)


if __name__ == '__main__':
    import logging

    class Logger:
        def __init__(self,  log_level=logging.DEBUG):
            self.log_level = log_level

        def get_formatter(self):
            return logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        def get_logger(self, module_name):
            """Returns a Logger instance for the specified module_name"""
            logger = logging.getLogger(module_name)
            logger.setLevel(self.log_level)
            log_handler = logging.StreamHandler()
            log_handler.setFormatter(self.get_formatter())
            logger.addHandler(log_handler)
            return logger

    class DevNullSender:
        def send(self, frame):
            pass

        def __str__(self):
            return "DevNullSender"

    def main():
        log = Logger().get_logger("main")
        log.info("Starting....")
        src_mac = open("/sys/class/net/eth0/address").read().strip()

        ether = Ethernet(log, DevNullSender(), src_mac)
        ether.xmit("ARP", hex(123))

    main()
