'''
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 7/21/2016
    Last Modified: 08/18/2018

    neurofuzz security SSH config hardening

    ###### LICENSE ###########
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
    ###### LICENSE ###########


    This prog must be run as root or with sudo since it will write
    the end result file to a privileged dir: /etc/ssh

    This process will write an SSH config file that is based
    on whatever existed on the system. Final output will be to:

        /etc/ssh/neurofuzzsecurity_sshd_config

    so the standard SSH will have to be stopped and a new instance
    will have to be started as such:

        /usr/sbin/sshd -D -f /etc/ssh/neurofuzzsecurity_sshd_config

    This will run the OpenSSH server on port 6446 unless you
    decide to change that.

    If you want to just use this output file as your default
    then just mv

        /etc/ssh/neurofuzzsecurity_sshd_config

    to

        /etc/ssh/sshd_config

    example:

        sudo mv /etc/ssh/neurofuzzsecurity_sshd_config /etc/ssh/sshd_config

    and restart the SSH service as such:

        sudo service ssh restart

    A backup of your current sshd_config file gets put
    in:

        /root/.sshd_config_backups/

    with a timestamp appended to the filename. This location
    is used because this is run as a privileged user

    To run:

        sudo python3 nftk_modify_sshd_config.py

    Notes:

        - Take note that by default we set SSH to listen on port 6446,
        if you want to change this value change it in var SSHD_PORT

        - Prior to running this program and altering the target sshd_config
        file you need to copy the public side of your SSK keys to that
        target machine

'''
import os
import sys
import time
import shutil
import optparse
import subprocess
import platform
import syslog
from pathlib import Path

#################################################################
# populate ALLOWED_USERS as needed
ALLOWED_USERS = []
SSHD_PORT = 6446
#################################################################
def which(program=""):
    ''' find location (path) of executable code '''
    def is_exe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    def ext_candidates(fpath):
        yield fpath
        for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
            yield fpath + ext

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        tarr = os.environ["PATH"].split(os.pathsep)
        tarr.append("/sbin")
        for path in tarr:
            exe_file = os.path.join(path, program)
            for candidate in ext_candidates(exe_file):
                if is_exe(candidate):
                    return candidate
    return None
#################################################################

class ssh_config(object):

    def __init__(self, sshd_config_file=''):
        if sshd_config_file:
            self.sshd_config_file = sshd_config_file
        else:
            self.sshd_config_file = "/etc/ssh/sshd_config"
        self.neurofuzzsecurity_sshd_config_file = "/etc/ssh/neurofuzzsecurity_sshd_config"

        self.backup_original_ssh_config_file()

        self.usedns_exists = False
        self.rhosts_auth_exists = False

        self.platform_string = platform.linux_distribution()[0].lower()

        self.sshd_exe = which(program="sshd")

        self.raw_lines = []
        self.allowed_users = []
        # read in sshd_config data
        self.consume_ssh_config_file()

        # default users that need SSH access
        if len(ALLOWED_USERS) > 0:
            for u in ALLOWED_USERS:
                self.add_allowed_user(uname=u)


    def backup_original_ssh_config_file(self):
        ''' '''
        dest_path = "{}/{}".format(str(Path.home()),".sshd_config_backups")
        if not os.path.exists(dest_path):
            os.makedirs(dest_path)
        '''
        if not os.path.exists(os.path.dirname(dest_path)):
            print("Please make dir: {} - example: {}".format(dest_path, "mkdir ~/.sshd_config_backup"))
            sys.exit()
        '''
        raw_fname = self.sshd_config_file.split("/")[len(self.sshd_config_file.split("/"))-1]
        shutil.copy (self.sshd_config_file, "{}/{}.backup.{}".format(dest_path,raw_fname,str(int(time.time()))))


    def consume_ssh_config_file(self):
        ''' read in ssh config data for us to modify '''
        with open(self.sshd_config_file, "r") as f:
            self.raw_lines = f.readlines()


    def write_ssh_config_file(self):
        ''' '''
        if len(self.raw_lines) > 0:
            with open(self.neurofuzzsecurity_sshd_config_file, "w") as f:
                f.write(self.dump_modified_config())


    def dump_modified_config(self):
        return ''.join(self.raw_lines).strip()


    def harden_ssh_config(self):
        if len(self.raw_lines) > 0:
            for index,item in enumerate(self.raw_lines):
                #print "{} - {}".format(index,item)

                if item.startswith('Port') or item.startswith('#Port'):
                    self.raw_lines[index] = "{} {}\n".format("Port", SSHD_PORT)

                if item.startswith('Protocol') or item.startswith('#Protocol'):
                    self.raw_lines[index] = "{}\n".format("Protocol 2")

                if item.startswith('ServerKeyBits') or item.startswith('#ServerKeyBits'):
                    self.raw_lines[index] = "{}\n".format("ServerKeyBits 2048")

                if item.startswith('PermitRootLogin') or item.startswith('#PermitRootLogin'):
                    self.raw_lines[index] = "{}\n".format("PermitRootLogin no")

                if item.startswith('StrictModes') or item.startswith('#StrictModes'):
                    self.raw_lines[index] = "{}\n".format("StrictModes yes")

                if item.startswith('RSAAuthentication') or item.startswith('#RSAAuthentication'):
                    self.raw_lines[index] = "{}\n".format("RSAAuthentication yes")

                if item.startswith('PubkeyAuthentication') or item.startswith('#PubkeyAuthentication'):
                    self.raw_lines[index] = "{}\n".format("PubkeyAuthentication yes")

                if item.startswith('RhostsRSAAuthentication') or item.startswith('#RhostsRSAAuthentication'):
                    self.raw_lines[index] = "{}\n".format("RhostsRSAAuthentication no")

                if item.startswith('RhostsAuthentication') or item.startswith('#RhostsAuthentication'):
                    self.raw_lines[index] = "{}\n".format("RhostsAuthentication no")
                    self.rhosts_auth_exists = True

                if item.startswith('IgnoreRhosts') or item.startswith('#IgnoreRhosts'):
                    self.raw_lines[index] = "{}\n".format("IgnoreRhosts yes")

                if item.startswith('IgnoreUserKnownHosts') or item.startswith('#IgnoreUserKnownHosts'):
                    self.raw_lines[index] = "{}\n".format("IgnoreUserKnownHosts yes")

                if item.startswith('PasswordAuthentication') or item.startswith('#PasswordAuthentication'):
                    self.raw_lines[index] = "{}\n".format("PasswordAuthentication no")

                if item.startswith('PermitEmptyPasswords') or item.startswith('#PermitEmptyPasswords'):
                    self.raw_lines[index] = "{}\n".format("PermitEmptyPasswords no")

                if item.startswith('UsePAM') or item.startswith('#UsePAM'):
                    self.raw_lines[index] = "{}\n".format("UsePAM yes")

                if item.startswith('ChallengeResponseAuthentication') or item.startswith('#ChallengeResponseAuthentication'):
                    self.raw_lines[index] = "{}\n".format("ChallengeResponseAuthentication no")

                if item.startswith('KerberosAuthentication') or item.startswith('#KerberosAuthentication'):
                    self.raw_lines[index] = "{}\n".format("KerberosAuthentication no")

                if item.startswith('GSSAPIAuthentication') or item.startswith('#GSSAPIAuthentication'):
                    self.raw_lines[index] = "{}\n".format("GSSAPIAuthentication no")

                if item.startswith('AllowTcpForwarding') or item.startswith('#AllowTcpForwarding'):
                    self.raw_lines[index] = "{}\n".format("AllowTcpForwarding no")

                if item.startswith('X11Forwarding') or item.startswith('#X11Forwarding'):
                    self.raw_lines[index] = "{}\n".format("X11Forwarding no")

                if item.startswith('PrintMotd') or item.startswith('#PrintMotd'):
                    self.raw_lines[index] = "{}\n".format("PrintMotd no")

                if item.startswith('GatewayPorts') or item.startswith('#GatewayPorts'):
                    self.raw_lines[index] = "{}\n".format("GatewayPorts no")

                if item.startswith('TCPKeepAlive') or item.startswith('#TCPKeepAlive'):
                    self.raw_lines[index] = "{}\n".format("TCPKeepAlive yes")

                if item.startswith('PermitUserEnvironment') or item.startswith('#PermitUserEnvironment'):
                    self.raw_lines[index] = "{}\n".format("PermitUserEnvironment no")

                if item.startswith('UsePrivilegeSeparation') or item.startswith('#UsePrivilegeSeparation'):
                    self.raw_lines[index] = "{}\n".format("UsePrivilegeSeparation yes")

                if item.startswith('Banner') or item.startswith('#Banner'):
                    self.raw_lines[index] = "{}\n".format("Banner none")

                if item.startswith('UseDNS') or item.startswith('#UseDNS'):
                    self.raw_lines[index] = "{}\n".format("UseDNS no")
                    #USEDNS_EXISTS = True
                    self.usedns_exists = True

                if item.strip().endswith('sftp-server'):
                    '''
                        some use spaces, others use tabs

                        examples:

                        Subsystem sftp /usr/lib/openssh/sftp-server
                        Subsystem    sftp    /usr/libexec/sftp-server
                        Subsystem sftp /usr/lib/sftp-server
                    '''
                    if '\t' in item:
                        tmp_item = item.strip().split('\t')
                    else:
                        tmp_item = item.strip().split()
                    sftp_name = tmp_item[len(tmp_item) - 1]
                    self.raw_lines[index] = "{} {}\n".format("#Subsystem sftp", sftp_name)

            if not self.usedns_exists:
                self.raw_lines.append("{}\n".format("UseDNS no"))

            '''
            # looks like this is deprecated
            if not self.rhosts_auth_exists:
                self.raw_lines.append("{}\n".format("RhostsAuthentication no"))
            '''

            if self.platform_string == 'debian':
                self.raw_lines.append("{}\n".format("DebianBanner no"))

            self.raw_lines.append("\n{}\n".format("KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"))
            self.raw_lines.append("\n{}\n".format("Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"))
            self.raw_lines.append("\n{}\n".format("MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"))

            if len(self.allowed_users) > 0:
                # add default users
                # AllowUsers name1,name2
                self.raw_lines.append("\n{} {}".format("AllowUsers", ' '.join(self.allowed_users)))


    def add_allowed_user(self, uname):
        if uname and uname not in self.allowed_users:
            self.allowed_users.append(uname)


    def validate_sshd_config(self):
        ret = True
        proc = subprocess.Popen([self.sshd_exe, '-t', '-f', self.neurofuzzsecurity_sshd_config_file],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE
                                )
        out,err = proc.communicate()
        '''
        if out:
            print("OUT: {}".format(out))
        '''
        if err:
            #print("ERR: {}".format(err))
            ret = False

        return ret


'''
    API
'''
def neurofuzzsecurity_generate_hardened_ssh_config():
    '''
        returns True if the newly generated SSHD config is validated
        successfully, otherwise returns False
    '''

    sshdcfg = ssh_config()
    sshdcfg.harden_ssh_config()
    sshdcfg.write_ssh_config_file()

    return sshdcfg.validate_sshd_config()



if __name__ == "__main__":

    print(neurofuzzsecurity_generate_hardened_ssh_config())


'''
Research @ https://stribika.github.io/2015/01/04/secure-secure-shell.html

Notes:

###############################################################################
Key Exchange Algo's

OpenSSH supports 8 key exchange protocols:

    curve25519-sha256: ECDH over Curve25519 with SHA2
    diffie-hellman-group1-sha1: 1024 bit DH with SHA1
    diffie-hellman-group14-sha1: 2048 bit DH with SHA1
    diffie-hellman-group-exchange-sha1: Custom DH with SHA1
    diffie-hellman-group-exchange-sha256: Custom DH with SHA2
    ecdh-sha2-nistp256: ECDH over NIST P-256 with SHA2
    ecdh-sha2-nistp384: ECDH over NIST P-384 with SHA2
    ecdh-sha2-nistp521: ECDH over NIST P-521 with SHA2

We have to look at 3 things here:

    1. ECDH curve choice: This eliminates 6-8 because NIST curves suck. They leak secrets through timing side channels and off-curve inputs. Also, NIST is considered harmful and cannot be trusted.
    2. Bit size of the DH modulus: This eliminates 2 because the NSA has supercomputers and possibly unknown attacks. 1024 bits simply don't offer sufficient security margin.
    3. Security of the hash function: This eliminates 2-4 because SHA1 is broken. We don't have to wait for a second preimage attack that takes 10 minutes on a cellphone to disable it right now.

We are left with 1 and 5. 1 is better and it's perfectly OK to only support that but for interoperability (with Eclipse, WinSCP), 5 can be included.

Hence we add:

    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
###############################################################################
Data encryption:

Symmetric ciphers are used to encrypt the data after the initial key exchange and authentication is complete.

Here we have quite a few algorithms:

    3des-cbc
    aes128-cbc
    aes192-cbc
    aes256-cbc
    aes128-ctr
    aes192-ctr
    aes256-ctr
    aes128-gcm@openssh.com
    aes256-gcm@openssh.com
    arcfour
    arcfour128
    arcfour256
    blowfish-cbc
    cast128-cbc
    chacha20-poly1305@openssh.com

We have to consider the following:

    1. Security of the cipher algorithm: This eliminates 1 and 10-12 - both DES and RC4 are broken. Again, no need to wait for them to become even weaker, disable them now.
    2. Key size: At least 128 bits, the more the better.
    3. Block size: Does not apply to stream ciphers. At least 128 bits. This eliminates 13 and 14 because those have a 64 bit block size.
    4. Cipher mode: The recommended approach here is to prefer AE modes and optionally allow CTR for compatibility. CTR with Encrypt-then-MAC is provably secure.

Chacha20-poly1305 is preferred over AES-GCM because the SSH protocol does not encrypt message sizes when GCM (or EtM) is in use. This allows some traffic analysis even without decrypting the data.

Hence we add:

    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
###############################################################################
Message Authentication Codes

Encryption provides confidentiality, message authentication code provides integrity. We need both. If an AE cipher mode is selected, then extra MACs are not used, the integrity is already given. If CTR is selected, then we need a MAC to calculate and attach a tag to every message.

There are multiple ways to combine ciphers and MACs - not all of these are useful. The 3 most common:

    Encrypt-then-MAC: encrypt the message, then attach the MAC of the ciphertext.
    MAC-then-encrypt: attach the MAC of the plaintext, then encrypt everything.
    Encrypt-and-MAC: encrypt the message, then attach the MAC of the plaintext.

Only Encrypt-then-MAC should be used, period. Using MAC-then-encrypt have lead to many attacks on TLS while Encrypt-and-MAC have lead to not quite that many attacks on SSH. The reason for this is that the more you fiddle with an attacker provided message, the more chance the attacker has to gain information through side channels. In case of Encrypt-then-MAC, the MAC is verified and if incorrect, discarded. Boom, one step, no timing channels. In case of MAC-then-encrypt, first the attacker provided message has to be decrypted and only then can you verify it. Decryption failure (due to invalid CBC padding for example) may take less time than verification failure. Encrypt-and-MAC also has to be decrypted first, leading to the same kind of potential side channels. It's even worse because no one said that a MAC's output can't leak what its input was. SSH by default, uses this method.

Here are the available MAC choices:

    hmac-md5
    hmac-md5-96
    hmac-sha1
    hmac-sha1-96
    hmac-sha2-256
    hmac-sha2-512
    umac-64
    umac-128
    hmac-md5-etm@openssh.com
    hmac-md5-96-etm@openssh.com
    hmac-sha1-etm@openssh.com
    hmac-sha1-96-etm@openssh.com
    hmac-sha2-256-etm@openssh.com
    hmac-sha2-512-etm@openssh.com
    umac-64-etm@openssh.com
    umac-128-etm@openssh.com

The selection considerations:

    1. Security of the hash algorithm: No MD5 and SHA1. Yes, I know that HMAC-SHA1 does not need collision resistance but why wait? Disable weak crypto today.
    2. Encrypt-then-MAC: I am not aware of a security proof for CTR-and-HMAC but I also don't think CTR decryption can fail. Since there are no downgrade attacks, you can add them to the end of the list. You can also do this on a host by host basis so you know which ones are less safe.
    3. Tag size: At least 128 bits. This eliminates umac-64-etm.
    4. Key size: At least 128 bits. This doesn't eliminate anything at this point.

Hence we add:

    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

'''
