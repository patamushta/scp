import uuid
import json

import eventlet
import eventlet.event
from eventlet.timeout import Timeout
from eventlet.green import socket

from scp.protocols import ScpPacket, Spif2Packet, UnexpectedProtocol, \
                      ProtocolError, \
                      determine_packet_type, FieldExtractionError, \
                      Disconnection
from scp.logger import LOGGER
from scp.supervizor import SfkSupervizor
from scp.common import str_uuid, with_timeout
from scp.httpserver import run_httpserver

NEED_AUTH = False # changed in __init__.py by command line key

CONFIG = {}


class Registrar(object):
    """
       Recieve connections from clients and sfks, 
       start sockwrappers and dockers,
       balance requests from clients between same-appid sfk instances.
    """

    def __init__(self):
        self.sfks = {} # supervizor - manager of sfk subsystem
                       # {appid: { uuid: SFK supervizor }}
                       # uuid - additional identifier for allowing
                       # access of many sfk with equal appid
        self.info = Information()


    def _is_sfk_connectable(self, appid): 
        return appid in self.sfks


    def _get_sfk(self, appid):
        """ perform simple balancing """
        try:
            sfk_ids = self.sfks[appid]
        except KeyError:
            # TODO meaningful exception
            raise Exception("No such appid registered: %s" % appid)
        connects = {}
        for sfk_id in sfk_ids:
            connects[sfk_id] = self.info.sfk_num_connects(appid, sfk_id)
        least_connected_id = min(sfk_ids, key=lambda i: connects[i])
        sfk_supervizor = self.sfks[appid][least_connected_id]
        return sfk_supervizor, least_connected_id 


    def _generate_guid(self):
        return uuid.uuid4().bytes 


    def _recv_packet(self, expected_packet_class, sock):
        f = sock.makefile()
        timeout = Timeout(CONFIG['scp_protocol']['scp_timeout'])
        try:
            packet_class = determine_packet_type(f)
        except Timeout as t:
            if t is not timeout:
                LOGGER.error("Accidently catch wrong timeout!")
            else:
                LOGGER.error("Timeout fired when try to recieve magic")
            return None
        except (UnexpectedProtocol, Disconnection) as e:
            LOGGER.error(e)
            return None
        finally:
            timeout.cancel()


        if packet_class != expected_packet_class: 
            LOGGER.error("Authorization fails: unexpected packet type")
            return None

        packet = packet_class()
        # TODO timeout
        try: 
            packet.read_fields(f)
        except socket.error as e:
            LOGGER.error("Cannot recieve packet correctly, %s" % e)
            return None 
        except ProtocolError as e:
            LOGGER.error("Cannot recieve packet correctly, %s" % e)
            return None
        except Exception as e:
            LOGGER.error("Cannot recieve packet correctly, %s" % e)
            return None

        return packet


    # function for eventlet.serve
    def register_rengine(self, sock, addr):
        packet = self._recv_packet(Spif2Packet, sock) 
        if packet == None:
            sock.close()
            return

        try:
            appid  = packet.get_appid()
        except ProtocolError:
            LOGGER.error(
                "cannot extract appid needed for just connected client")
            sock.close()
            return

        if not self._is_sfk_connectable(appid):
            LOGGER.error(
                "attempt connecting to non-connected sfk with appid " \
                + str(appid))
            sock.close()
            return 
       
        sfk, sfk_id = self._get_sfk(appid) # after _is_connectable check
                                           # always correct
        guid = self._generate_guid()
        self.info.add_client(appid, sfk_id, guid, addr)

        LOGGER.info(
            'Register: Client connected to appid {0} with guid {1}'.format(
                                                 appid, str_uuid(guid)))
        # waiting for death_event prevents eventlet.serve from closing socket
        death_event = eventlet.event.Event()
        sfk.start_client(sock=sock, guid=guid, addr=addr, 
                         first_packet=packet, death_event=death_event)
        death_event.wait()
        LOGGER.info(
            'Register: death_event from rengine guid {0}'.format(
                                                 str_uuid(guid)))


    def remember_sfk(self, sfk_supervizor, appid, sfk_id):
        """ remember sfk supervizor """
        self.sfks.setdefault(appid, {})[sfk_id] = sfk_supervizor


    def forget_sfk(self, appid, sfk_id):
        """ forget sfk supervizor """
        if len(self.sfks[appid]) == 1:
            del self.sfks[appid]
        else:
            del self.sfks[appid][sfk_id]


    # function for eventlet.serve
    def register_sfk(self, sfk_sock, sfk_addr):
        auth_packet = self._recv_packet(ScpPacket, sfk_sock)

        # basic auth packet check
        basic_test_passed = False # just init value
        error_msg = ""

        if auth_packet == None:
            error_msg = "Error when auth packed recved"
        elif auth_packet.get_msg_type() != 'auth':
            error_msg = "Unexpected message type while auth attempt"
        elif len(auth_packet.data) != 0:
            error_msg = "Auth packet contains unexpected data"
        else:
            basic_test_passed = True

        if not basic_test_passed:
            LOGGER.error(error_msg)
            sfk_sock.close()
            return

        appid, token = auth_packet.get_auth_info()
        # check authorization
        auth_check_passed = False
        if not appid or not token:
            LOGGER.error("Appid or Token not supplied")
        elif NEED_AUTH and not authorized_sfk(appid, token):
            LOGGER.error("Bad appid/token pair from just connected sfk: %s %s" % (appid, token))
        else:
            auth_check_passed = True

        if not auth_check_passed:
            sfk_sock.close()
            return

        sfk_id = str(uuid.uuid4())
        LOGGER.info("Sfk with appid %s, sfk_id %s connected" % (str_uuid(appid), sfk_id))
        # waiting for death_event prevents eventlet.serve from closing socket
        death_event = eventlet.event.Event()
        sfk_supervizor = SfkSupervizor(sfk_sock=sfk_sock, 
                                       registrar=self, 
                                       appid=appid,
                                       sfk_id=sfk_id,
                                       sfk_addr=sfk_addr,
                                       death_event=death_event)
        self.remember_sfk(sfk_supervizor, appid, sfk_id)
        self.info.add_sfk_instance(appid, sfk_id, sfk_addr)

        death_event.wait()
        LOGGER.info('Register: death_event from sfk appid {0}; sfk_id {1}'.format(appid, sfk_id))


class Information(object):
    """
    Collect all 'statistical' information about current system state
    """
    def __init__(self):
        self.connect_tree = {}
      #  {appid: # one appid may has many instances with different sfk_id
      #     {sfk_id: 
      #           {"addr": [host, port], 
      #            "connects": {guid: 
      #                         {"addr": [host, port]}
      #                      }
      #           }
      #     }
      #  }

    def sfk_num_connects(self, appid, sfk_id):
        sfk_full_tree = self.connect_tree.get(appid, {})
        sfk_instanse_tree = sfk_full_tree.get(sfk_id, {})
        connects = sfk_instanse_tree.get('connects', {})
        return len(connects)

    def add_client(self, appid, sfk_id, guid, addr):
        connects = self.connect_tree[appid][sfk_id]['connects']
        connects[str_uuid(guid)] = {'addr': addr}

    def drop_client(self, appid, sfk_id, guid):
        connects = self.connect_tree[appid][sfk_id]['connects']
        del connects[str_uuid(guid)]

    def add_sfk_instance(self, appid, sfk_id, addr):
        sfk_full_tree = self.connect_tree.setdefault(appid, {})
        sfk_full_tree[sfk_id] = {'addr': addr, 'connects': {}}

    def drop_sfk_instance(self, appid, sfk_id):
        if len(self.connect_tree[appid]) == 1:
            del self.connect_tree[appid]
        else:   
            del self.connect_tree[appid][sfk_id]

    def status(self):
        return json.dumps(self.connect_tree)



def run(config):
    global CONFIG
    CONFIG = config
    
    registrar = Registrar()

    addr = (config['sfk_server']['host'], 
            int(config['sfk_server']['port']))
    LOGGER.info("Starting sfk-side server on %s:%d" %addr)
    eventlet.spawn_n(eventlet.serve, 
                     eventlet.listen(addr), 
                     registrar.register_sfk) 

    addr = (config['rengine_server']['host'],
            int(config['rengine_server']['port']))
    LOGGER.info("Starting rengine-side server on %s:%d" %addr)
    eventlet.spawn_n(eventlet.serve, 
                     eventlet.listen(addr), 
                     registrar.register_rengine) 

    LOGGER.info("Starting http server")

    run_httpserver(registrar, config,
                          host=config['http_server']['host'],
                          port=config['http_server']['port'],
                          debug=True, # TODO remove in production!!
                          quiet=True,
                          server='eventlet')

#    eventlet.event.Event().wait()


def authorized_sfk(appid, token):
    """ Request Userbase by API """

    import base64
    import requests

    # authorize scp in userbase
    b64_uid = base64.standard_b64encode(CONFIG['scp_userbase']['uid'])
    b64_token = base64.standard_b64encode(CONFIG['scp_userbase']['token'])
    headers = {
               'Authorization' : 'Nptv %s:%s' % (b64_uid, b64_token),
               'Content-Type'  : 'application/json'
              }

    userbase_host = CONFIG['scp_userbase']['host'] if CONFIG['scp_userbase']['host'] else 'userbase.staging.nptv.home'
    url = 'http://%s/v2/applications/%s/auth.json' % (userbase_host, appid)
    
    data = json.dumps({'token' : token})
    try:
        resp = requests.post(url, data=data, headers=headers)
    except Exception as e:
        LOGGER.error('Authorization request fails: %s; appid %s; token %s' % (str(e), appid, token))
        return False


    if int(resp.status_code) == 204:
        LOGGER.info('Authorization passed')
        return True
    else:
        LOGGER.info('Authorization rejected: appid %s; token %s' % (appid, token))
        return False




if __name__ == '__main__':
    run(config)
