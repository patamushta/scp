import urllib2
import json

resp = urllib2.urlopen('http://localhost:8080/status.json')
print json.dumps(json.loads(resp.read()), indent=4)


