""" socket wrappers """

import eventlet
from eventlet.queue import Queue
from eventlet.green import socket

from scp.protocols import ScpPacket, Spif2Packet, UnexpectedProtocol, \
                          determine_packet_type, Disconnection
from scp.logger import LOGGER
from scp.common import str_uuid



class SockWrapper(object):
    """ base class for SFK and Client(Rengine) sockets wrappers """

    NATIVE_PACKET = ScpPacket # placeholder, change it in successors
    
    def __init__(self):
        self.queue_send = Queue()
        self.queue_recv = Queue()
        self.appid = None

        # interface
        self.sock = None

    # interface for packet dispatchers - dockers

    def put_packet(self, packet):
        self.queue_send.put(packet)

    def get_packet(self):
        return self.queue_recv.get()


    # sender and recver started as greenthreads

    def sender(self, callback=lambda: None): 
        """get packet from sending queue, send it via sock. 
           By convention, packet type checking performed 
           before putting in queue
        """
        try:
            while True:
                packet = self.queue_send.get()
                data = packet.assemble()
                self.sock.sendall(data)
                # TODO if DEBUG
                try:
                    if packet.get_msg_type() == 'pong':
                        LOGGER.debug('pong sent %s' % self)
                except AttributeError:
                    pass

        except Exception:
            LOGGER.error(str(self) + " sender error")
        eventlet.spawn_n(callback)


    def recver(self, callback=lambda: None):
        """ recieve packets from sock, 
            check packet's type, 
            put packet to recv queue
        """
        f = self.sock.makefile()
        try:
            while True:
                try:
                    packet_class = determine_packet_type(f)
                except Disconnection as e:
                    raise Disconnection

                if packet_class == self.NATIVE_PACKET:
                    packet = packet_class()
                    packet.read_fields(f)  
                    self.queue_recv.put(packet)
                else:
                    LOGGER.error(
                        "{0} recver: unexpected magic".format(str(self)))
                    raise UnexpectedProtocol
                
        except Disconnection as e:
            LOGGER.info("Disconnection: {0}".format(str(self)))
        except Exception as e:
            LOGGER.error("recver error: {0} {1}".format(str(self), str(e)))
        LOGGER.info(str(self) + " recver terminate")
        eventlet.spawn_n(callback)


    def close_socket(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            LOGGER.info("{0} sockwrapper close socket".format(str(self)))
        except Exception as e:
            LOGGER.error("Fails socket close: %s" % str(e))



class SfkSockWrap(SockWrapper):

    NATIVE_PACKET = ScpPacket

    def __init__(self, sock=None, appid=None, token=None, sfk_id=None):
        super(SfkSockWrap, self).__init__() # make queues
        self.sock = sock 
        self.appid = appid
        self.token = token
        self.sfk_id = sfk_id


    def __repr__(self):
        return "%s:%s" % ("SfkSockWrap", str_uuid(self.appid))



class ClientSockWrap(SockWrapper):
    """ Client from Rengine """ 
    NATIVE_PACKET = Spif2Packet

    def __init__(self, sock=None, addr=None, guid=None):
        super(ClientSockWrap, self).__init__() # make queues
        self.sock = sock
        self.addr = addr
        self.guid = guid


    def __repr__(self):
        return "%s:%s" % ("ClientSockWrap", str_uuid(self.guid))
