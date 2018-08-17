"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 7/21/2016
    Last Modified: 08/17/2018

    checks for required executables

    BSD 3-Clause License

    Copyright (c) 2016 - 2018, Andres Andreu, neuroFuzz LLC
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
import sys

import nftk_sys_funcs as sys_funcs

def merge_two_dicts(x, y):
    ''' Given two dicts, merge them into a new dict as a shallow copy '''
    z = x.copy()
    z.update(y)
    return z


def check_for_tor():
    ''' '''
    torpath = ''
    torpath = sys_funcs.which(program='tor')
    '''
        gotta make sure tor exists and is an
        executable, otherwise there is no point
        in continuing
    '''
    if torpath:
        if os.path.exists(torpath) and os.access(torpath, os.X_OK):
            return {'tor_path':torpath}
    return {'error_message':'tor executable not found, cannot continue'}


def check_for_proxychains():
    ''' '''
    proxychainspath = ''
    proxychainspath = sys_funcs.which(program='proxychains4')
    '''
        gotta make sure proxychains4 exists and is an
        executable, otherwise there is no point
        in continuing
    '''
    if proxychainspath:
        if os.path.exists(proxychainspath) and os.access(proxychainspath, os.X_OK):
            return {'proxychains_path':proxychainspath}
    return {'error_message':'proxychains4 executable not found, cannot continue'}


def check_for_nmap():
    ''' '''
    nmappath = ''
    nmappath = sys_funcs.which(program='nmap')
    '''
        gotta make sure nmap exists and is an
        executable, otherwise there is no point
        in continuing
    '''
    if nmappath:
        if os.path.exists(nmappath) and os.access(nmappath, os.X_OK):
            return {'nmap_path':nmappath}
    return {'error_message':'nmap executable not found, cannot continue'}





'''
    API

    nmap and tor are required for this to work

'''
def get_required_paths(use_proxychains=False):
    ret = {}

    tor_check = check_for_tor()
    try:
        if tor_check.has_key('error_message'):
            return tor_check
    except AttributeError:
        if 'error_message' in tor_check:
            return tor_check

    ret = merge_two_dicts(x=ret, y=tor_check)

    if use_proxychains:
        proxychains_check = check_for_proxychains()
        if proxychains_check.has_key('error_message'):
            #return proxychains_check
            ''' we can still run without this '''
            proxychains_check = {'proxychains_path':'null'}
            ret = merge_two_dicts(x=ret, y=proxychains_check)
        else:
            ret = merge_two_dicts(x=ret, y=proxychains_check)
    else:
        proxychains_check = {'proxychains_path':'null'}
        ret = merge_two_dicts(x=ret, y=proxychains_check)

    nmap_check = check_for_nmap()
    if nmap_check.has_key('error_message'):
        return nmap_check
    else:
        ret = merge_two_dicts(x=ret, y=nmap_check)

    return ret


# TODO - add function to check for existence of
# proxychains config template, if it doesnt exist
# create it with content
