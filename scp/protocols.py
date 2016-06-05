# -*- coding: utf-8 -*-
import struct
import json

from urlparse import urlparse

from scp.protobufs import scp_pb2, sfk_pb2
from scp.logger import LOGGER
from scp.common import with_timeout

from eventlet.timeout import Timeout




# hardcoded now...
CONFIG = {'scp_protocol':
            {'scp_timeout': 4,
             'scp_max_protobuf_len': 4096,
            }
         }

SCP_TIMEOUT = CONFIG['scp_protocol']['scp_timeout']
SCP_MAX_PROTOBUF_LEN = CONFIG['scp_protocol']['scp_max_protobuf_len']

DEBUG = True



class ProtocolError(Exception):
    pass

class UnexpectedProtocol(ProtocolError):
    pass

class FieldExtractionError(ProtocolError):
    pass

class Disconnection(Exception):
    pass

class TimeoutError(ProtocolError): pass 


class Packet(object):
    """ Interface base class for scp and spif packets.
        Packet object read its fields from fileobj 
        (e.g. made from socket or StringIO)
        assemble itself from its fields, return string (i.e. byte array)
    """
    
    MAGIC = 0x0

    
    def __init__(self):
        self.raw_packet = None # packet as byte array 

    @staticmethod
    def _read_int(fileobj):
        try:
            data = fileobj.read(4)
            if not data:
                LOGGER.info("disconnection")   # хотелось бы таки знать, что именно отвалилось
                return None
            return struct.unpack('!I', data)[0]
        except Exception as e:
            LOGGER.error(
                "cannot read int field from socket: {0}".format(str(e)))
            return None
       

    # common functionality

    def set_raw_packet(self, raw_packet):
        self.raw_packet = raw_packet


    # common abstract interface for both types of packets   

    def read_fields(self, fileobj):
        """ read fields of packet from fileobj according to protocol spec """
        pass

    def assemble(self):
        """ assemble packet from fields according to protocol spec """
        pass



class ScpPacket(Packet):

    # << packet description >>
    # 4 bytes  BigEndian  magic
    # 1 byte   ---        flags
    # 16 bytes ---        GUID ( endianness senseless, cuz no convertions are made on it)
    # 4 bytes  BigEndian  Message_Length 
    # Message_Length bytes - initial message 
    # TODO Protobuf???
    
    MAGIC = 0xD15EA5EF
    
    def __init__(self, flags='\x00',
                       guid='\x00'*16,
                       protobuf='',
                       data=''):
        super(ScpPacket, self).__init__()
        self.flags = flags 
        self.guid = guid 
        if not protobuf:
            pb = scp_pb2.Msg()
            pb.mtype = pb.MESSAGE
            self.protobuf = pb.SerializeToString()
        else:
            self.protobuf = protobuf
        self.data = data
            
    # implementation of common interface

    #@with_timeout(SCP_TIMEOUT, ProtocolError('Timeout while recieving scp packet'))
    def read_fields(self, fileobj):
        timeout = Timeout(SCP_TIMEOUT, TimeoutError('Timeout while recv scp packet'))
        try:

            s = fileobj

            self.flags = s.read(1)
            self.guid = s.read(16)
            pb_len = self._read_int(s)
            data_len = self._read_int(s)

            if pb_len == None or data_len == None:
                raise ProtocolError('Protobuf or data length not supplied')
            
            # protobuf len issues
            if pb_len > SCP_MAX_PROTOBUF_LEN:
                raise ProtocolError('Protobuf lenght too large')
            elif pb_len > 0:
                self.protobuf = s.read(pb_len)
            else:
                raise ProtocolError('Protobuf lenght 0')
            
            # data len issues
            if data_len != 0:
                self.data = s.read(data_len)
            else:
                self.data = ''

        except TimeoutError as e:
            LOGGER.error("Timeout fired while recv field of packet")
            raise ProtocolError(str(e))
        finally:
            timeout.cancel()

        # clean alternative representation of packet
        self.set_raw_packet(None)


    def assemble(self):
        if self.raw_packet != None:
            return self.raw_packet

        packet = (struct.pack('!I', self.MAGIC) + 
                  self.flags +
                  self.guid +
                  struct.pack('!I', len(self.protobuf)) +
                  struct.pack('!I', len(self.data)) +
                  self.protobuf + 
                  self.data) 
        return packet

    # packet-type specific interface

    def get_msg_type(self):
        pb = scp_pb2.Msg()
        try:
            pb.ParseFromString(self.protobuf)
        except Exception as e:
            LOGGER.error("Cannot parse protobuf")
            return None

        msg_type = {
            pb.AUTH: 'auth',
            pb.PING: 'ping',
            pb.MESSAGE: 'msg',
            pb.PONG: 'pong',
            pb.SFKCONTENT: 'sfkcontent',
            pb.SESSION_DROPPED: 'session_dropped',
        }.get(pb.mtype, None)
#        if msg_type is None:
#            raise ProtocolError("bad mtype")
#        else:   # no one catch this exception!!!
        return msg_type

    def get_sfkcontent(self):
        try:
            pb = scp_pb2.Msg()
            pb.ParseFromString(self.protobuf)
            if pb.mtype == pb.SFKCONTENT:
                uri = pb.content.identifier
                request_id = pb.content.request_id
                headers = []
                for header in pb.content.headers:
                    headers.append(header)
                return (uri, request_id, headers)
            else:
                raise FieldExtractionError("Not SfkContent packet, try to extract uri and headers")
        except Exception as e:
            raise FieldExtractionError("Can't extract SkfContent field", e)

    def get_msg(self):
        """ return msg - payload of packet """ 
        return self.data

    def get_guid(self):
        return self.guid

    def make_pong(self):
        pb = scp_pb2.Msg()
        pb.mtype = pb.PONG
        pb.pong.ctime = 0
        pong = ScpPacket(guid=self.guid, protobuf=pb.SerializeToString())
        return pong

    @staticmethod
    def make_sfkcontent(uri, request_id, headers=None):
        """ headers: list of strings like "Accept-Encoding: gzip,deflate,sdch"  """
        pb = scp_pb2.Msg()
        pb.mtype = pb.SFKCONTENT
        pb.content.identifier = uri
        pb.content.request_id = request_id
        for header in headers:
            pb.content.headers.append(header)
        return ScpPacket(protobuf=pb.SerializeToString())

    @staticmethod
    def make_session_dropped(guid):
        pb = scp_pb2.Msg()
        pb.mtype = pb.SESSION_DROPPED
        return ScpPacket(guid=guid, protobuf=pb.SerializeToString())

    def get_auth_info(self): # from sfk in very first packet
        """ extract appid, token from very first (auth) packet from sfk.
            return (None, None) if any errors happened
        """
        pb = scp_pb2.Msg()
        try:
            pb.ParseFromString(self.protobuf)
        except Exception as e:
            LOGGER.error(str(e))
            return None, None
        else:
            return pb.auth.appid, pb.auth.token
    

class Spif2Packet(Packet):
    # protocol description
    # 4 bytes BigEndian magic
    # 4 bytes BigEndian Protobuf_Len 
    # 4 bytes BigEndian BinaryData_Len
    # Protobuf Data
    # Binary Data

    MAGIC = 0xFEED5EED

    def __init__(self, protobuf='', data=''):
        super(Spif2Packet, self).__init__()
        self.protobuf = protobuf 
        self.bindata  = data 


    # implementation of common interface 

    def read_fields(self, fileobj):
        protobuf_len = self._read_int(fileobj)
        binary_len = self._read_int(fileobj)
        if protobuf_len == None or binary_len == None:
            raise ProtocolError

        self.protobuf = fileobj.read(protobuf_len)
        self.bindata = fileobj.read(binary_len)
        
        self.set_raw_packet(None)

    def assemble(self):
        if self.raw_packet:
            return self.raw_packet
            
        packet = (struct.pack('!I', self.MAGIC) + 
                  struct.pack('!I', len(self.protobuf)) + 
                  struct.pack('!I', len(self.bindata)) + 
                  self.protobuf +
                  self.bindata)
        
        return packet

    # packet-type specific interface

    def get_appid(self): # from client
        try:
            pb = sfk_pb2.Msg()
            pb.ParseFromString(self.protobuf)
            sfk_url = json.loads(pb.session.params)['sfk-url']
            parsed_url = urlparse(sfk_url)
            appid = parsed_url.path[1:] # drop '/' symbol
            return appid
        except Exception as e:
            LOGGER.error('in get_appid: ' + str(e))

        raise FieldExtractionError("cannot extract appid")
        

_CHRILDREN_PACKETS = (ScpPacket, Spif2Packet)

def determine_packet_type(fileobj):
    """ reads magic from fileobj, return one of children packets - scp or spif2 """
    # TODO timeout ??
    magic = Packet._read_int(fileobj)
    if magic is None:
        raise Disconnection("disconnected")

    for packet in _CHRILDREN_PACKETS:
        if magic == packet.MAGIC:
            return packet
    LOGGER.debug("magic: %s" % magic)
    raise UnexpectedProtocol("cannot determine packet type")
