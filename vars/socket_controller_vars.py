"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 10/11/2012
    Last Modified: 09/14/2018

    variables to be used by the SocketController class

    BSD 3-Clause License

    Copyright (c) 2012-2016, Andres Andreu, neuroFuzz LLC
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation and/or
    other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors may
    be used to endorse or promote products derived from this software without specific
    prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
    INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
    OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
    OF SUCH DAMAGE.

    *** Take note:
    If you use this for criminal purposes and get caught you are on
    your own and I am not liable. I wrote this for legitimate
    pen-testing and auditing purposes.
    ***

    Be kewl and give credit where it is due if you use this. Also,
    send me feedback as I don't have the bandwidth to test for every
    condition - Dre
"""
import os
import hashlib
import binascii
import datetime
from random import choice, randint

try:
    from string import letters
except ImportError:
    from string import ascii_letters as letter

''' based on https://gist.github.com/3962751 '''
def createTorPassword(secret = ""):
    ind = chr(96)

    # for salt
    rng = os.urandom
    # generate salt and append indicator value so that it
    salt = "%s%s" % (rng(8), ind)

    prefix = '16:'
    c = ord(salt[8])

    EXPBIAS = 6
    count = (16+(c&15)) << ((c>>4) + EXPBIAS)

    d = hashlib.sha1()
    tmp = salt[:8]+secret

    '''
        hash the salty password as many times as the length of
        the password divides into the count value
    '''
    slen = len(tmp)
    while count:
      if count > slen:
        d.update(tmp)
        count -= slen
      else:
        d.update(tmp[:count])
        count = 0
    hashed = d.digest()
    # convert to hex
    salt = binascii.b2a_hex(salt[:8]).upper()
    ind = binascii.b2a_hex(ind)
    torhash = binascii.b2a_hex(hashed).upper()

    return prefix + salt + ind + torhash


def createRandAlpha(length=0):
    return ''.join(choice(letters) for x in xrange(length or randint(10, 30)))

# modifiable variables
########################################################
base_socks_port = 9052
base_control_port = 8120
socketLowerBound = 1
#socketUpperBound = 15
socketUpperBound = 2

datadir = os.getcwd() + '/tordata'
if not os.path.exists(datadir):
    try:
        os.makedirs(datadir)
    except:
        pass

debug = False
selfip = '127.0.0.1'
torfname = 'tor%sfile'
torarguments = {"--RunAsDaemon":'1',
                "--CookieAuthentication":'0',
                "--ControlPort":'%s',
                "--PidFile":'tor%s.pid',
                "--SocksPort":'%s:%s',
                "--DataDirectory":datadir + '/tor%s'
                #"--HashedControlPassword":createTorPassword(secret=createRandAlpha(length=5)),
                #"--SocksPort":'%s PreferSOCKSNoAuth',
                #"--Log":'info file ' + datadir + '/logs/tor_log_' + datetime.datetime.now().strftime('%Y-%m-%d_%H_%M_%S')
                }
########################################################

def getBaseSocksPort():
    return base_socks_port

def getBaseControlPort():
    return base_control_port

def getDataDir():
    return datadir

def getDebug():
    return debug

def getSocketIp():
    return selfip

def getTorFileName():
    return torfname

def getTorArguments():
    return torarguments

def getSocketBounds():
    return(socketLowerBound,socketUpperBound)
