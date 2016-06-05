# model of sfk for testing purpouses
import struct
import eventlet
import sys
import StringIO
import requests
import json
import urlparse
import urllib2
import time
import os.path as osp

from eventlet.green import socket
from eventlet.queue import Queue
from eventlet.event import Event

import scp.protocols as prot
import scp.sockwraps as swrp
import scp.protobufs.scp_pb2 as scp_pb
import scp.protobufs.sfk_pb2 as sfk_pb2
from scp.logger import LOGGER
from scp.common import str_uuid

DIRECTORY = osp.split(osp.abspath(__file__))[0]

ADDRESS = ('127.0.0.1', 6009)
#ADDRESS = ('10.40.56.164', 6009)
PING_PERIOD = 4

STATIC_SERV_URL = 'http://localhost:8080/upload' # will be update when appid/token will be known

URI_PATH = json.load(open(osp.join(DIRECTORY, 'uri_path.json')))


def serialize_int(number):
    return struct.pack('!I', number)


class SfkModel(swrp.SockWrapper):
 
    NATIVE_PACKET = prot.ScpPacket

    def __init__(self, appid='', token=''):
        super(SfkModel, self).__init__()
        self.appid = appid 
        self.token = token
        self.sock = socket.socket()
        self.guids = set() 


    def _make_auth_packet(self):
        pb = scp_pb.Msg()
        pb.mtype = pb.AUTH
        pb.auth.token = self.token
        pb.auth.appid = self.appid
        protobuf = pb.SerializeToString()
        return prot.ScpPacket(protobuf=protobuf) 


    def _make_ping_packet(self):
        pb = scp_pb.Msg()
        pb.mtype = pb.PING
        pb.ping.ctime = 0
        protobuf = pb.SerializeToString()
        return prot.ScpPacket(protobuf=protobuf)


    def _make_message_packet(self, guid):
        pb = scp_pb2.Msg()
        pb.mtype = pb.MESSAGE
        protobuf = pb.SerializeToString()
        return prot.ScpPacket(guid=guid, protobuf=protobuf)


    def _make_reply_packet(self, payload='', guid=None):
        if guid not in self.guids:
            LOGGER.error("No session with guid %s" % str_uuid(guid))

        pb = sfk_pb2.Msg()
        pb.mtype = pb.DATA
        pb.data.content_type = "simple"
        pb.data.payload = "test"
        protobuf = pb.SerializeToString()
        data = "%s %s %s" % (self.appid, payload, str_uuid(guid))
        spif = prot.Spif2Packet(protobuf=protobuf, data=data)
        return prot.ScpPacket(guid=guid, data=spif.assemble())


    def connect(self, addr):
        self.sock.connect(addr)
        
    
    def send_packet(self, packet):
        data = packet.assemble() 
        try:
            self.sock.sendall(data)
        except Exception as e:
            LOGGER.error("Sending auth packet fails: " + str(e))
        else:
            LOGGER.info("Auth packet sent successfully.")
    

    def recved_packets_processor(self):
        try:
            while True:
                packet = self.queue_recv.get()
                self.guids.add(packet.guid)
                mtype = packet.get_msg_type()    
                payload = None
                if mtype == 'msg':
                    buf = StringIO.StringIO(packet.data)
                    pack_class = prot.determine_packet_type(buf)
                    client_pack = pack_class()
                    client_pack.read_fields(buf)
                    payload = client_pack.bindata
                elif mtype == 'sfkcontent':
                    SfkModel.sfkcontent_handler(packet)
                    continue
                elif mtype == 'session_dropped':
                    self.guids.remove(packet.guid)
                    LOGGER.info('session dropped guid {0}'.format(
                        str_uuid(packet.guid)))
                    continue
                elif mtype == 'pong':
                    LOGGER.info('Pong recieved')
                else:
                    LOGGER.error("Unknown message type: {0}".format(mtype))
                            
                LOGGER.info('recved packet guid {0}; mtype {1}'.format(
                                                  str_uuid(packet.guid),
                                                  mtype))
                if payload:
                    LOGGER.info('message: %s' % payload)
                    reply = self._make_reply_packet(payload=payload, 
                                                    guid=packet.guid)
                    self.queue_send.put(reply)
                    LOGGER.info('reply is sent')
        except Exception as e:
            LOGGER.exception("recved_packets_processor: " + str(e))


    def pinger(self):
        try:
            while True:
                eventlet.sleep(PING_PERIOD)
                ping = self._make_ping_packet()
                self.queue_send.put(ping)
                LOGGER.info("PING! In sending queue %d" % self.queue_send.qsize())
        except Exception as e:
            LOGGER.exception("Pinger fails: %s" % str(e))
    
    @staticmethod
    def sfkcontent_handler(packet):
        LOGGER.info("Got SfkContent protobuf")
        uri, request_id, headers = packet.get_sfkcontent() 
        LOGGER.info("uri: %s" % uri)
        LOGGER.info("request_id: %s" % request_id)

        url = '/'.join([STATIC_SERV_URL, request_id, uri])
        LOGGER.info("URL: %s" % url)

#        time.sleep(2)

        if uri in URI_PATH:
            data=open(URI_PATH[uri], 'rb').read()
            headers={'Content-Type': 'image/jpg',
                     'X-SCP-Status': '200 OK'}
        else:
            LOGGER.error("Chpoken uri: %s" % uri)
            data='No way!'
            headers={'Content-Type': 'text/plain', 
                     'X-SCP-Status': '404 Not Found'}

        r = requests.post(url, 
                          data=data, 
                          headers=headers)
        LOGGER.info("Uri %s sent, with response code %s" % (uri, r.status_code))
        if int(r.status_code) != 200:
            LOGGER.error(r.text)

        LOGGER.info("request headers")
        for header in headers:
            LOGGER.info(header)

        LOGGER.info("response headers")
        for header, val in r.headers.items():
            LOGGER.info("%s: %s" % (header, val))

        return None




auths = [('abcdef00', 'token00'), 
         ('abcdef11', 'token11'),
         ('f85f43d1-1182-4c8a-89c6-3b8ada6e7302', 'p65DUFHYyaxDAdu2zpEy59sarC8eQVyadYnoDeSV')]

if __name__ == '__main__':
    try:
        index = int(sys.argv[1])
    except IndexError:
        print "usage: python sfkmodel n, where n in [0,1,2]"
        sys.exit(1)

    sfk = SfkModel(appid=auths[index][0], token=auths[index][1])
    sfk.connect(ADDRESS)
    sfk.send_packet(sfk._make_auth_packet())
    eventlet.spawn_n(sfk.recver)
    eventlet.spawn_n(sfk.sender)
    eventlet.spawn_n(sfk.recved_packets_processor)
    eventlet.spawn_n(sfk.pinger)
    eventlet.event.Event().wait()
