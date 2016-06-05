from scp.face import Face
from scp.staticserver import StaticServer

from bottle import run

def run_httpserver(registrar, config, *args, **kwargs):
    # create objects for register routes
    face = Face(registrar.info)
    staticserver = StaticServer(registrar, config) 

    run(*args, **kwargs)
