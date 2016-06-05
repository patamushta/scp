import os, sys
import os.path as osp
import subprocess as sub
import threading
from time import sleep


glock = threading.Lock()
def threadsafe(func):
    def wrapper(*args, **kwargs):
        glock.acquire()
        func(*args, **kwargs)
        glock.release()
    return wrapper

def colorize(color, string):
    colors = {
        'purple' : '\033[95;40m',
        'blue' : '\033[94;40m',
        'green' : '\033[92;40m',
        'yellow' : '\033[93;40m',
        'red' : '\033[91;40m',
        'endc' : '\033[0m',
    }
    c = colors.get(color, 'endc')
    return c + string + colors['endc']

@threadsafe
def log(s, intro, color):
    print >> sys.stderr, colorize(color, '%s: %s' % (intro, s))

@threadsafe
def logapp(s):
    print >> sys.stderr, colorize('green', 'APP: ' + s)


class Test(object):
    def testrun(self, cmd, log_method):
        app = sub.Popen(cmd, stderr=sub.PIPE)
        self.sub = app
        line = app.stderr.readline()
        while line:
            log_method(line.rstrip())
            line = app.stderr.readline()


class App(Test, threading.Thread):
    def run(self): 
        cmd = ['python', '-u', 'bin/local_run.py', '--config', 'doc/example/conf', '--noauth']
        log_method = logapp
        self.testrun(cmd, log_method)


class SfkModel(Test, threading.Thread):
    def run(self):
        cmd = ['python', '-u', 'tests/sfkmodel.py', '0']
        log_method = lambda s: log(s, 'SFK', 'yellow')
        self.testrun(cmd, log_method)


class RengineModel(Test, threading.Thread):
    def run(self):
        cmd = ['python', '-u', 'tests/clientmodel.py', 'A', '0']
        log_method = lambda s: log(s, 'CLT', 'red')
        self.testrun(cmd, log_method)


if __name__ == '__main__':
    # go to main repo directory, which contains ./tests
    directory = osp.split(osp.abspath(__file__))[0]
    os.chdir(osp.join(directory, '..'))

    try:
        app = App()
        app.start()
        sleep(0.5)

        sfk = SfkModel()
        sfk.start()
        sleep(1)
        rgn = RengineModel()
        rgn.start()

        sfk.join()
        app.join()
        rgn.join()
    finally:
        print 'killing subprocesses'
        app.sub.kill()
        sfk.sub.kill()
        rgn.sub.kill()
