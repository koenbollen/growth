# The growth job will try en update the growth.py node and restart it.

url = "https://github.com/koenbollen/growth/raw/master/growth.py"

from time import sleep
import hashlib
import os
import random
import signal
import subprocess
import sys
import urllib2

with open( sys.argv[0] ) as fp:
    current = fp.read()

try:
    ha = urllib2.urlopen( url )
    update = ha.read()
except IOError, e:
    logging.error( "Failed to update: %r", repr(e) )
    sys.exit()

hash1 = hashlib.sha1( current ).digest()
hash2 = hashlib.sha1( update ).digest()

if hash1 == hash2:
    logging.debug( "No update availible" )
    sys.exit()

if not os.access( sys.argv[0], os.W_OK ):
    logging.error( "Unable to update, can't write file." )
    sys.exit()

logging.warning( "Updating this growth.py node!!" )

# remember state:
argv = list(sys.argv)
argv[0] = os.path.abspath( argv[0] )
pid = os.getpid()

print pid

# Fork into another process:
if os.fork() > 0:
    sys.exit()
os.setsid()

# wait and kill:
sleep( random.randint(5, 10) )
os.kill( pid, signal.SIGTERM )
os.kill( pid, signal.SIGKILL )
for i in xrange(1024):
    try:
        os.close(i)
    except OSError:
        pass

# write update:
with open( argv[0], "w" ) as fp:
    fp.write( update )

# and restart:
sleep( 1 )
subprocess.call( [sys.executable,] + argv )

# vim: expandtab tabstop=4 softtabstop=4 shiftwidth=4 textwidth=79:
