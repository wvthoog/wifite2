#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os
import socket

#IP = socket.gethostbyname(socket.gethostname())
#IP = '192.168.2.118'
IP = Configuration.tcp_hashcat_hostname
PORT = Configuration.tcp_hashcat_port
ADDR = (IP, PORT)
FORMAT = "utf-8"
SIZE = 1024
PASSWORD = Configuration.tcp_hashcat_password

hccapx_autoremove = False  # change this to True if you want the hccapx files to be automatically removed


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'

    @staticmethod
    def should_use_force():
        command = ['hashcat', '-I']
        stderr = Process(command).stderr()
        return 'No devices found/left' or 'Unstable OpenCL driver detected!' in stderr

    @staticmethod
    def crack_handshake(handshake, show_command=False):
        # Generate hccapx
        hccapx_file = HcxPcapngTool.generate_hccapx_file(
                handshake, show_command=show_command)

        key = None
        # Crack hccapx
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                # '--quiet',
                '-m', '22000',
                hccapx_file,
                Configuration.wordlist
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            process = Process(command)
            stdout, stderr = process.get_output()
            if ':' not in stdout:
                continue
            else:
                key = stdout.split(':', 5)[-1].strip()
                break

        if os.path.exists(hccapx_file) and hccapx_autoremove is True:
            os.remove(hccapx_file)

        print(key)
        return key

    @staticmethod
    def crack_tcp_handshake(handshake, show_command=False):
        # Generate hccapx
        hccapx_file = HcxPcapngTool.generate_hccapx_file(
                handshake, show_command=show_command)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            client.connect(ADDR)
        except ConnectionError:
            Color.pl('{!} {R}Could not connect to {O}%s{W}' % IP)
            return

        welcome_msg = client.recv(SIZE).decode(FORMAT)
        client.send(PASSWORD.encode(FORMAT))

        if client.recv(SIZE).decode(FORMAT) == 'Password success':
            #print('Password success')
            Color.pl('{+} {C}Logged in {O}successfully{W}')
            pass
        else:
            #print('Password failed')
            Color.pl('{!} {R}Login failed, {O}check password{W}')
            client.close()
            return

        with open(hccapx_file, "r") as f:
            handshake = f.read()

        send_data = f"UPLOAD[CMD]{handshake}"
        client.send(send_data.encode(FORMAT))

        while True:
            data = client.recv(SIZE).decode(FORMAT)
            cmd, msg = data.split("[CMD]")

            if cmd == "OK":
                #print(f"{msg}")
                Color.pl('{+} {C}%s{W}' % msg)
            elif cmd == 'CRACKING':
                msg_percentage, msg_time_left, msg_kbps, msg_keys = msg.split('[MSG]')
                # print(
                #     f'Cracking WPA Handshake: {msg_percentage} ETA: {msg_time_left} @ {msg_kbps} (current keys: {msg_keys})')

                status = '\r{+} {C}Cracking WPA Handshake: %s%%{W}' % msg_percentage
                status += ' ETA: {C}%s{W}' % msg_time_left
                status += ' @ {C}%s{W}' % msg_kbps
                status += ' (current keys: {C}%s{W})' % msg_keys
                Color.clear_entire_line()
                Color.p(status)

            elif cmd == 'CRACKED':
                if msg != 'None':
                    #print(f'{msg}')
                    #Color.pl('{+} Password is: {C}%s{W}' % msg)
                    key = msg
                    client.send('LOGOUT'.encode(FORMAT))
                    return key
                else:
                    #print('Not cracked')
                    Color.pl('{!} {R} Failed to crack hash{W}')
                    client.send('LOGOUT'.encode(FORMAT))
                    break
            elif cmd == 'ABORTED':
                pass
            elif cmd == 'DONE':
                pass

        #print("Disconnected from the server.")
        Color.pl('{+} {C}Disconnected from [O}%s{W}' % IP)
        client.close()

    @staticmethod
    def crack_pmkid(pmkid_file, verbose=False):
        '''
        Cracks a given pmkid_file using the PMKID/WPA2 attack (-m 16800)
        Returns:
            Key (str) if found; `None` if not found.
        '''

        # Run hashcat once normally, then with --show if it failed
        # To catch cases where the password is already in the pot file.
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',      # Only output the password if found.
                '-m', '16800',  # WPA-PMKID-PBKDF2
                '-a', '0',      # Wordlist attack-mode
                pmkid_file,
                Configuration.wordlist
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if verbose and additional_arg == []:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

            # TODO: Check status of hashcat (%); it's impossible with --quiet

            hashcat_proc = Process(command)
            hashcat_proc.wait()
            stdout = hashcat_proc.stdout()

            if ':' not in stdout:
                # Failed
                continue
            else:
                # Cracked
                key = stdout.strip().split(':', 1)[1]
                return key


class HcxDumpTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'apt install hcxdumptool'

    def __init__(self, target, pcapng_file):
        # Create filterlist
        filterlist = Configuration.temp('pmkid.filterlist')
        with open(filterlist, 'w') as filter_handle:
            filter_handle.write(target.bssid.replace(':', ''))

        if os.path.exists(pcapng_file):
            os.remove(pcapng_file)

        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '--filterlist_ap', filterlist,
            '--filtermode', '2',
            '-c', str(target.channel),
            '-o', pcapng_file
        ]

        self.proc = Process(command)

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        self.proc.interrupt()


class HcxPcapngTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxpcapngtool'
    dependency_url = 'apt install hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.pmkid_file = Configuration.temp('pmkid-%s.16800' % self.bssid)

    @staticmethod
    def generate_hccapx_file(handshake, show_command=False):
        hccapx_file = Configuration.temp('generated.hccapx')
        if os.path.exists(hccapx_file):
            os.remove(hccapx_file)

        command = [
            'hcxpcapngtool',
            '-o', hccapx_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(hccapx_file):
            raise ValueError('Failed to generate .hccapx file, output: \n%s\n%s' % (
                stdout, stderr))

        return hccapx_file

    @staticmethod
    def generate_john_file(handshake, show_command=False):
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)

        command = [
            'hcxpcapngtool',
            '--john', john_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file, output: \n%s\n%s' % (
                stdout, stderr))

        return john_file

    def get_pmkid_hash(self, pcapng_file):
        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)

        command = [
            'hcxpcapngtool',
            '-z', self.pmkid_file,
            pcapng_file
        ]
        hcxpcap_proc = Process(command)
        hcxpcap_proc.wait()

        if not os.path.exists(self.pmkid_file):
            return None

        with open(self.pmkid_file, 'r') as f:
            output = f.read()
            # Each line looks like:
            # hash*bssid*station*essid

        # Note: The dumptool will record *anything* it finds, ignoring the filterlist.
        # Check that we got the right target (filter by BSSID)
        matching_pmkid_hash = None
        for line in output.split('\n'):
            fields = line.split('*')
            if len(fields) >= 3 and fields[1].lower() == self.bssid:
                # Found it
                matching_pmkid_hash = line
                break

        os.remove(self.pmkid_file)
        return matching_pmkid_hash
