"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 10/11/2012
    Last Modified: 04/25/2018

    Class to spawn off a number of instances of tor and set
    a socket to use this SOCKS5 instance

    BSD 3-Clause License

    Copyright (c) 2012-2018, Andres Andreu, neuroFuzz LLC
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
import sys
try:
    import socks
except ImportError:
    print("{}\n\n".format("Please install socks (sudo pip install PySocks) and try again"))
    sys.exit()

import os
import glob
import time
import socket
import signal
import subprocess
from random import choice
from vars import socket_controller_vars

def clean_slate():
    for fname in glob.glob(socket_controller_vars.getDataDir() + '/tor*/tor*.pid'):

        the_pid = ''

        if os.path.exists(fname):
            with open(fname) as pid_fname:
                the_pid = pid_fname.read()

            if the_pid:
                the_pid = the_pid.strip()
                the_pid = int(the_pid)
                content = ''
                try:
                    with open('/proc/{}/cmdline'.format(the_pid), mode='rb') as fd:
                        content = fd.read().decode().split('\x00')
                except Exception:
                    continue

                if content:
                    joined_content = ' '.join(content)
                    if 'tor' in joined_content and \
                        'ControlPort' in joined_content and \
                        'SocksPort' in joined_content and \
                        'CookieAuthentication' in joined_content:
                        try:
                            os.kill(the_pid, signal.SIGQUIT)
                        except:
                            continue

            os.remove(fname)


class SocketController:
    def __init__(self, tor_executable_path=''):
        self.torpath = tor_executable_path

        self.socks_control_ports = {}
        self.socks_port_list = []
        self.pids = []

        self.base_socks_port = socket_controller_vars.getBaseSocksPort()
        self.base_control_port = socket_controller_vars.getBaseControlPort()
        self.datadir = socket_controller_vars.getDataDir()
        self.torfname = socket_controller_vars.getTorFileName()
        self.torarguments = socket_controller_vars.getTorArguments()

        sbounds = socket_controller_vars.getSocketBounds()
        self.tor_socket_lower_bound = sbounds[0]
        self.tor_socket_upper_bound = sbounds[1]

        self.lastProxUsed = 0
        self.debug = socket_controller_vars.getDebug()
        self.selfip = socket_controller_vars.getSocketIp()
        socket.setdefaulttimeout(10)

    def get_port_list(self):
        return self.socks_port_list

    def set_lower_bound(self, val=""):
        self.tor_socket_lower_bound = val

    def set_upper_bound(self, val=""):
        self.tor_socket_upper_bound = val

    def set_local_ip_addr(self, val=""):
        self.selfip = val

    def setLastUsed(self, val=""):
        self.lastProxUsed = val

    def getLastUsed(self):
        return self.lastProxUsed

    def setDebug(self, val=""):
        self.debug = val

    def get_data_dir(self):
        return self.datadir

    def spawn_sockets(self):
        ''' kick off a pool of tor instances '''
        for i in range(self.tor_socket_lower_bound, self.tor_socket_upper_bound):
            self.spawn_socket(t_instance=i)

    def get_tor_pids(self):
        if self.pids:
            return self.pids

    def set_socks_prox(self):
        '''
        print
        print self.socks_port_list
        print
        '''
        try:
            prot = int(choice(self.socks_port_list))
        except IndexError:
            return None

        s = socks.socksocket()
        if s:
            try:
                s.setproxy(proxytype=socks.PROXY_TYPE_SOCKS5, addr=self.selfip, port=prot)
            except TypeError:
                s.setproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr=self.selfip, port=prot)
            self.setLastUsed(val=prot)
            return (s, self.selfip, prot)

        '''
        if prot != self.getLastUsed():
            if self.debug:
                print "\nSwitching SOCKS prox to ip %s, port: %d" % (self.selfip,prot)
            s = socks.socksocket()
            if s:
                try:
                    s.setproxy(proxytype=socks.PROXY_TYPE_SOCKS5, addr=self.selfip, port=prot)
                except TypeError:
                    s.setproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr=self.selfip, port=prot)
                self.setLastUsed(val=prot)
                return (s, self.selfip, prot)
        '''
        return None


    def spawn_socket(self, t_instance=0):
        '''
            kick off a single indexed tor instance
        '''
        if t_instance >= 0:
            '''
                first create data file
                Simply opening a file in write mode will create it, if it doesn't exist.
                If the file does exist, the act of opening it in write mode will completely
                overwrite its contents
            '''
            fname = self.torfname % str(t_instance)
            try:
                dir_path = self.datadir + '/tor' + str(t_instance)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path)
                #f = open(dir_path + '/' + fname, "w")
                with open (dir_path + '/' + fname, "w") as myfile:
                    pass
            except IOError:
                pass

            runstmt = []
            runstmt.append(self.torpath)

            bsp = str(self.base_socks_port+t_instance)
            bcp = str(self.base_control_port+t_instance)
            self.socks_control_ports[bsp] = bcp
            self.socks_port_list.append(bsp)

            for k in self.torarguments.iterkeys():
                if k == '--ControlPort':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % bcp)
                elif k == '--PidFile':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % str(t_instance))
                elif k == '--SocksPort':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % (self.selfip,bsp))
                elif k == '--DataDirectory':
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k] % str(t_instance))
                else:
                    runstmt.append(k)
                    runstmt.append(self.torarguments[k])

            runstmt.append("--quiet")

            if self.debug:
                print("\n{}\n".format(runstmt))

            '''
                notes:

                tor --RunAsDaemon 1
                    --CookieAuthentication 0
                    --HashedControlPassword 16:3209E94C0EEF6A9660D0645B037E16730B553C627462CD233F33B0F950
                    --ControlPort 8124
                    --PidFile tor4.pid
                    --SocksPort ip:port
                    --DataDirectory tordata/tor4
                    --Log info file /path/tordata/logs/tor_log_2015-07-23_09_41_04'
                    --quiet
            '''
            sp = subprocess.Popen(runstmt)
            '''
                it will take a few seconds for the tor socket to get
                established and then the correct pid to show up in the
                respective .pid file
            '''
            time.sleep(4)
            # set the real pid of the tor sock
            tor_pid_fname = "{}/{}{}/{}{}{}".format(self.datadir, 'tor', str(t_instance), 'tor', str(t_instance), '.pid')
            try:
                with open (tor_pid_fname, "r") as myfile:
                    self.pids.append(int(myfile.read().strip()))
            except:
                for i in range(1,4):
                    try:
                        with open (tor_pid_fname, "r") as myfile:
                            self.pids.append(int(myfile.read().strip()))
                            break
                    except:
                        continue
                    time.sleep(1)


    def kill_sockets(self):
        ''' '''
        the_pids = self.get_tor_pids()
        if len(the_pids) > 0:
            for the_pid in the_pids:
                if the_pid:
                    try:
                        os.kill(the_pid, signal.SIGQUIT)
                    except OSError:
                        pass
