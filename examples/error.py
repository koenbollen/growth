# Cause an error.

from random import random

if random() < 0.5:
    print 42/0
else:
    l = []
    print l[1]

# vim: expandtab tabstop=4 softtabstop=4 shiftwidth=4 textwidth=79:
