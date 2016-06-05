import uuid

from scp.sockwraps import ScpPacket, Spif2Packet 
from scp.logger import LOGGER
from scp.common import str_uuid

class DockerError(Exception):
    pass

class SfkDocker(object):
    """ Dispatcher of incoming packets from sfk:
        Takes packets from SFK socket wrapper's recv queue.
        Unpacks packet. 
        Determine its msg-type from protobuf.
        Determine its destination from GUID or msg-type if Msg Type 
                                                          smth like Ping.
        Puts unpacked packet into sending queue of client sock wrapper.
        Ping packet turned into Pong and put into SFK sock wrapper
    """

    def __init__(self, sfk=None, appid=None, sfk_id=None):
        self.client_sockwraps = {} # {'guid' :client sock wrapper}
        self.sfk = sfk  # sfk sock wrapper object
        self.appid = appid
        self.sfk_id = sfk_id


    def add_session(self, guid, client):
        # one connection to sfk serve many clients!
        self.client_sockwraps[guid] = client
    

    def del_client(self, guid):
        del self.client_sockwraps[guid]
    

    def _unpack_scp_to_spif2(self, packet):
        msg = packet.get_msg()
        spif2packet = Spif2Packet()
        spif2packet.set_raw_packet(msg)
        return spif2packet


    def mainloop(self, callback=lambda: None):
        try:
            while True:
                packet = self.sfk.get_packet()
                msg_type = packet.get_msg_type()
                
                if msg_type == 'msg':
                    guid = packet.get_guid()
                    client_sockwrap = self.client_sockwraps.get(guid, None)
                    if client_sockwrap is None:
                        # client already disconnected
                        LOGGER.info('Client with guid %s not connected' % str_uuid(guid))
                        continue
                    else:
                        spif2packet = self._unpack_scp_to_spif2(packet)
                        client_sockwrap.put_packet(spif2packet)
                
                elif msg_type == 'ping':
                    pong = packet.make_pong()
                    self.sfk.put_packet(pong)
                    LOGGER.debug("appid %s; sfk_id %s - recieved ping" % \
                                 (self.appid, self.sfk_id))

                else:
                    raise DockerError("unknown msg_type")

        except Exception:
            LOGGER.exception("Sfk Docker fails")
            callback()
                


class ClientDocker(object):
    """ Dispatcher of incoming packets from client-rengine """
    
    def __init__(self, client=None, sfk=None, guid=None, addr=None):
        self.client_sockwrap = client
        self.sfk_sockwrap = sfk    
        self.guid = guid
        self.addr = addr
    
    def _pack_spif2_to_scp(self, packet):
        new_pack = ScpPacket(guid=self.guid, 
                             data=packet.assemble())
        return new_pack

    def mainloop(self, callback=lambda: None):
        try:
            while True:
                packet = self.client_sockwrap.get_packet()
                new_packet = self._pack_spif2_to_scp(packet)
                self.sfk_sockwrap.put_packet(new_packet)
        except Exception as e:
            LOGGER.error("ClientDocker {0} {1}".format(str_uuid(self.guid), str(e)))
            callback()


    # specific methods
    def send_first(self, packet):
        new_packet = self._pack_spif2_to_scp(packet)
        self.sfk_sockwrap.put_packet(new_packet)
