import eventlet

from scp.sockwraps import SfkSockWrap, ClientSockWrap
from scp.dockers import SfkDocker, ClientDocker
from scp.logger import LOGGER
from scp.common import str_uuid
from scp.protocols import ScpPacket



class Subsystem(object):
    """ Contains all objects, related to sfk or client """
    def __init__(self, sockwrap, docker, death_event, threads=()):
        self.sockwrap = sockwrap
        self.docker = docker
        self.death_event = death_event
        self.threads = threads
        self.alive = True

    def kill_threads(self):
        for t in self.threads:
            t.kill() 


class SfkSubsystem(Subsystem):
    pass


class ClientSubsystem(Subsystem):
    pass


class SfkSupervizor(object):
    """Supervize family of one sfk-related entities: 
    sfk- and client- sockwrappers, sfk- and client- dockers. 
    Create objects, start and kill green threads of them.
    Has all information about subsystem, make it consistent all time."""

    def __init__(self, sfk_sock=None, 
                       registrar=None, 
                       appid=None,
                       sfk_id=None,
                       sfk_addr=None,
                       death_event=None):
        self.clients = {} # {guid: ClientSubsystem
                          #
                          # To drop client, kill threads of each object,
                          # then delete all objects and then 
                          # update clients info in sfk-docker.
        
        self.alive = True # if smth happened with sfk, subsystem must be killed.
                          # alive indicates
                          # that all incoming connections from 
                          # clients must be rejected
        self.appid = appid
        self.sfk_id = sfk_id
        self.start_sfk(sfk_sock, death_event) 
        self.registrar = registrar
        self.info = self.registrar.info 
        

    def start_sfk(self, sfk_sock, death_event):
        if self.alive == False:
            return

        sockwrap = SfkSockWrap(sock=sfk_sock, 
                               appid=self.appid,
                               sfk_id=self.sfk_id)
        docker = SfkDocker(sfk=sockwrap,
                           appid=self.appid,
                           sfk_id=self.sfk_id)

        sender = eventlet.spawn(sockwrap.sender, 
                                callback=self.kill_all_subsystems) 
        recver = eventlet.spawn(sockwrap.recver, 
                                callback=self.kill_all_subsystems)
        docker_thread = eventlet.spawn(docker.mainloop,
                                callback=self.kill_all_subsystems)

        self.sfk = SfkSubsystem(sockwrap, docker, death_event,
                                threads=(sender, recver, docker_thread))


    def start_client(self, sock=None, guid=None, 
                           addr=None, first_packet=None, death_event=None):
        if self.alive == False:
            return

        sockwrap = ClientSockWrap(sock=sock, addr=addr, guid=guid)
        docker = ClientDocker(client=sockwrap, 
                              sfk=self.sfk.sockwrap, guid=guid, addr=addr)
        sender = eventlet.spawn(sockwrap.sender, 
                                callback=lambda: self.drop_client(guid)) 
        recver = eventlet.spawn(sockwrap.recver, 
                                callback=lambda: self.drop_client(guid))
        docker_thread = eventlet.spawn(docker.mainloop,
                                       callback=lambda: self.drop_client(guid))
        
        self.clients[guid] = ClientSubsystem(sockwrap, docker, death_event,
                                 threads=(sender, recver, docker_thread))
                                            
        self.sfk.docker.add_session(guid, sockwrap)
        if first_packet:
            try:
                docker.send_first(first_packet)
            except Exception as e:
                LOGGER.error("First packet sending fails: " +  str(e))


    def drop_client(self, guid):
        # prevent to call this method from multiple threads
        try:
            if self.clients[guid].alive:
                self.clients[guid].alive = False
            else:
                return
        except KeyError:
            return

        self.clients[guid].kill_threads()
        self.clients[guid].sockwrap.close_socket()

        self.clients[guid].death_event.send()
        self.sfk.docker.del_client(guid)

        
        del self.clients[guid]
        LOGGER.info("Client guid {0} was dropped".format(str_uuid(guid)))
        self.info.drop_client(self.appid, self.sfk_id, guid)

        # send signal to sfk <<session dropped>>
        session_dropped = ScpPacket.make_session_dropped(guid)
        self.sfk.sockwrap.put_packet(session_dropped)


    def kill_all_subsystems(self):
        # prevent to call this method from multiple threads
        if self.alive: 
            self.alive = False
        else:
            return

        LOGGER.info("{0} dropping all subsystems".format(self.appid))
        for guid in self.clients.keys():
            self.drop_client(guid)
        LOGGER.info("{0} kill sfk-related greenthreads".format(self.appid))
        self.sfk.sockwrap.close_socket()
        self.sfk.kill_threads()
        self.sfk.death_event.send()

        LOGGER.info(self.appid + " subsystem disconnected and killed")
        self.registrar.forget_sfk(self.appid, self.sfk_id)
        self.info.drop_sfk_instance(self.appid, self.sfk_id)
