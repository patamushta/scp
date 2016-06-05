# -*- coding: utf-8 -*-

# uri is identifier (same thing)

import os.path

from bottle import run, route, request, abort, HTTPResponse, _hkey

from eventlet.event import Event
from eventlet.timeout import Timeout

from uuid import uuid4

from scp.protocols import ScpPacket
from scp.logger import LOGGER


TIMEOUT = 600 # seconds

class StaticServer(object):
    def __init__(self, registrar, config):
        self.registrar = registrar
        self.config = config

        # routing
        route("/static/<appid>/<token>/<uri:path>")(self.rengine_side)
        route("/upload/<request_id>/<uri:path>", method='POST')(self.sfk_side)

        # {request_id: event} , request_id: str(uuid) - unique for each content request
        self.request_id_events = {}
    
    # routed GET
    def rengine_side(self, appid, token, uri):
        """ Handle rengine (client) GET requests """
        if not self.rengine_authorization_ok(appid, token):
            LOGGER.info('Rengine content request authorization fails')
            abort(401, 'Authorization failed')

        evt = Event()
        request_id = str(uuid4())
        self.request_id_events[request_id] = evt

        headers = ["%s: %s" % (header, val) for (header, val) in request.headers.items()]
        packet = ScpPacket.make_sfkcontent(uri, request_id, headers)
        try:
            self._send(packet, appid)
        except Exception as e:
            abort(500, str(e))

        LOGGER.debug("uri %s expected" % uri)
        timeout = Timeout(TIMEOUT)
        try:
            resp = evt.wait()
        except Timeout:
            del self.request_id_events[request_id]
            abort(504, 'Gateway Timeout')
        finally:
            timeout.cancel()

        LOGGER.debug("uri %s got" % uri)
        
        return resp


    def _send(self, packet, appid):
        try:
            supervizor, _ = self.registrar._get_sfk(appid)
        except Exception as e:
            raise e
        else:
            supervizor.sfk.sockwrap.put_packet(packet)

    # routed POST
    def sfk_side(self, request_id, uri):
        """ Handle POST requests from sfk """
        if not self.sfk_authorization_ok(request_id):
            LOGGER.info('Sfk POST bad request_id')
            abort(401, "Bad request_id")

        body = request.body
        headers = request.headers
        # cut custom headers for scp
        if 'X-SCP-Status' in headers: # headers case-insensitive
            status = headers['X-SCP-Status']
            passed_headers = dict((k, v) for (k, v) in headers.items()
                                         if not k.startswith(_hkey('X-SCP')))
            status_supplied = True
        else:
            status = '500 Internal Server Error'
            body = ''
            passed_headers = {}
            status_supplied = False
            LOGGER.error("X-SCP-Status was not supplied")
            
        resp = HTTPResponse(body, status, **passed_headers)

        evt = self.request_id_events.get(request_id, None)

        if evt is None:
            # если нет такого ожидаемого события, то уже прошел таймаут
            abort(408, '') # Request Timeout
        else:
            evt.send(resp)
            del self.request_id_events[request_id]

        if status_supplied:
            return '' # пустой ответ с кодом 200
        else:
            abort(400, 'X-Scp-Status not supplied')


    def run(self, *args, **kwargs):
        run(*args, **kwargs)


    def rengine_authorization_ok(self, appid, token):
        """ Preventing from GET by evil monkey """
        # TODO this token is not understood yet
        try:
            self.registrar._get_sfk(appid)
        except Exception as e:
            return False
        else:
            return True

    def sfk_authorization_ok(self, request_id):
        """ Preventing from content POST by evil monkey """
        return bool(self.request_id_events.get(request_id, None))
