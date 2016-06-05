import uuid
from eventlet.timeout import Timeout

def str_uuid(bytez):
    if len(bytez) == 16:
        return str(uuid.UUID(bytes=bytez))
    else:
        return str(bytez)


def with_timeout(time, exception, reraise=True):
    def decorator(func):
        #@functools.wraps
        def wrapper(*args,**kwargs):
            timeout = Timeout(time, exception)
            try:
                func(*args,**kwargs)
            except exception as e:
                if reraise:
                    raise e
            else:
                timeout.cancel()
        return wrapper
    return decorator
