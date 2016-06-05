from bottle import route, run


class Face(object):
    def __init__(self, info):
        self.info = info
        route("/status.json")(self.status_json)

    #route("/status.json")
    def status_json(self):
        return self.info.status()

    def run(self, *args, **kwargs):
        run(*args, **kwargs)
