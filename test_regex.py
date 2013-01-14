#!/usr/bin/python

import sys
import re

if len(sys.argv) > 2:

    regex = re.compile(sys.argv[1])

    print regex.match(sys.argv[2])
else:
    regex = re.compile(sys.argv[1], re.DEBUG)

    


