# model of client for testing purpouses
import struct 
import eventlet
import json
import sys
import uuid

from eventlet.green import socket

import scp.protocols as prot
import scp.protobufs.sfk_pb2 as SfkPb
from scp.logger import LOGGER
from scp.common import str_uuid

from sfkmodel import serialize_int, SfkModel

ADDRESS = ('127.0.0.1', 6008)
appids = ['abcdef00', 'abcdef11']

ID = 'A'
APPID_NO = 0


class ClientModel(SfkModel):
    
    NATIVE_PACKET = prot.Spif2Packet
    
    def __init__(self, appid=''):
        super(ClientModel, self).__init__()
        self.appid = appid
        self.sock = socket.socket()


    def _make_session_packet(self):
        packet = prot.Spif2Packet()
        magic = prot.Spif2Packet.MAGIC

        # make protobuf field
        pb = SfkPb.Msg()
        pb.mtype = pb.SESSION
        pb.session.fid = 273 # just a placeholder, hmm.. 
                             # let it be an absolute temperature zero
        params = json.dumps({'sfk-url':'tcp://127.0.0.1:6009/' + self.appid})
        pb.session.params = params
        protobuf = pb.SerializeToString()

        data = ''

        buf = (serialize_int(magic) + 
               serialize_int(len(protobuf)) +
               serialize_int(len(data)) + 
               protobuf + 
               data)

        packet.set_raw_packet(buf)
        return packet

    def _make_message_packet(self, n):
        pb = SfkPb.Msg()
        pb.mtype = pb.DATA
        pb.data.content_type = "simple"
        pb.data.payload = "test"
        protobuf = pb.SerializeToString()

        data = ID + ("0000" + str(n))[-4:]
        return prot.Spif2Packet(protobuf=protobuf, data=data)


    def connect(self, addr):
        super(ClientModel, self).connect(addr) 
        

    def send_packet(self, packet):
        super(ClientModel, self).send_packet(packet)


    def recved_packets_processor(self):
        try:
            while True:
                packet = self.queue_recv.get()
                LOGGER.info("recved: %s" % packet.bindata)
        except Exception as e:
            LOGGER.error("recved_packets_processor: %s" % str(e))


    def test(self, interval, n):
        for i in range(n):
            eventlet.sleep(interval)
            packet = self._make_message_packet(i)
            self.queue_send.put(packet)


if __name__ == '__main__':

    try:
        ID = sys.argv[1]
    except Exception:
        LOGGER.info("Default value for ID(%s) will be used" % ID)

    try:
        APPID_NO = int(sys.argv[2])
    except Exception:
        LOGGER.info("Default value for APPID_NO(%d) will be used" % APPID_NO)

    client = ClientModel(appid=appids[APPID_NO])
    client.connect(ADDRESS)
    client.send_packet(client._make_session_packet())
    eventlet.spawn_n(client.recver)
    eventlet.spawn_n(client.sender)
    eventlet.spawn_n(client.recved_packets_processor)

    client.test(2, 5)
    
    eventlet.event.Event().wait()
