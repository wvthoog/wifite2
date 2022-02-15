import os
import socket
import sys
import threading
from pyhashcat import Hashcat
from datetime import datetime
from time import sleep
from wifite.util.color import Color

IP = ''
PORT = 4000
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
HANDSHAKE_DATA_PATH = "hs"
PASSWORD = 'mypass123'


def print_banner():
    Color.pl('')
    Color.pl(r' {G}             :=++****++-:             {W}')
    Color.pl(r' {G}         -*%@@@@%%##%%@@@@%*-         {W}')
    Color.pl(r' {G}      :*@@@#=:.        .:=#@@@*:      {W}')
    Color.pl(r' {G}    .#@@%-                  -%@@#.    {W}')
    Color.pl(r' {G}   =@@%-       -*#=     =**.  -@@@=   {W}')
    Color.pl(r' {G}  =@@#      :*@@#:   .*@@#.    +@@@=  {W}')
    Color.pl(r' {G} :@@#     -%@@#:   .*@@%-    :%@@@@@: {W}')
    Color.pl(r' {G} #@@:   -%@@%-    +@@@=     *@@@=:@@# {W}')
    Color.pl(r' {G} @@@  :%@@@+    -%@@%.    -@@@@:  @@@ {W}')
    Color.pl(r' {G} @@% +@@@@-   -#@@@%    :#@@@#.   %@@ {W}')
    Color.pl(r' {G} #@@#@@@@#::+%@@@@@- .=%@@@@-    .@@# {W}')
    Color.pl(r' {G} :@@@@@@@@@@@%@@@@@@@@@@@@+      #@@: {W}')
    Color.pl(r' {G}  +@@@@@@@%= .@@@@@@@@@@+       *@@+  {W}')
    Color.pl(r' {G}   +@@@%=:    :%@@@@%+:       :%@@+   {W}')
    Color.pl(r' {G}    :%@@#-       .          -#@@%:    {W}{C}Wifte & Hascat over TCP{W}')
    Color.pl(r' {G}      -#@@@*=.          .=*@@@#-      {W}{D}a Hashcat backend server for Wifite{W}')
    Color.pl(r' {G}        .=#@@@@@%#**#%@@@@@#=.        {W}{D}created by {O}wvthoog{W}')
    Color.pl(r' {G}            :-+**####**+-:            {C}{D}https://wvthoog.nl{W}')
    Color.pl('')

def cracking(conn, handshake, dictionary):
    hc = Hashcat()
    hc.reset()
    hc.hash = handshake.name
    hc.dict1 = dictionary
    hc.quiet = True
    hc.potfile_disable = True
    hc.hwmon_disable = True
    recent_file_name = datetime.now().strftime('out/%d-%m-%Y-%H-%M-%S') + '.out'
    open(recent_file_name, 'x')
    hc.outfile = recent_file_name
    hc.outfile_format = 2  # plain text
    Color.pl('{!} {C}Writing to {R}%s{W}' % hc.outfile)
    hc.attack_mode = 0
    hc.hash_mode = 22000
    hc.workload_profile = 2

    Color.pl('{+} {C}Running hashcat')
    if hc.hashcat_session_execute() >= 0:
        for devs in range(hc.status_get_device_info_cnt()):
            if hc.status_get_skipped_dev(devs) == False:
                active_devs = devs
                # print('Active device:', active_devs)
            else:
                inactive_devs = devs
                # print('Skipped devices:', inactive_devs)

        while True:
            # send info about cracking process back to client
            sleep(1)

            # print('Cracking WPA Hanshake:', str(round(hc.status_get_progress_finished_percent(), 2)) + '%'
            #       , 'ETA:', str(hc.status_get_time_estimated_relative())
            #       , '@', str(hc.status_get_speed_sec_all()), '(current keys:',
            #       str(hc.status_get_guess_candidates_dev(active_dev)) + ')')

            msg_percentage = str(round(hc.status_get_progress_finished_percent(), 2))
            msg_time_left = str(hc.status_get_time_estimated_relative())
            msg_kbps = str(hc.status_get_speed_sec_all())
            msg_keys = str(hc.status_get_guess_candidates_dev(active_devs))

            status = '\r{!} {C}Hascat running {W}%s' % msg_percentage + '% {C}done'
            Color.clear_entire_line()
            Color.p(status)

            # print('[+] Cracking WPA Handshake:', msg_percentage + '%', 'ETA:', msg_time_left
            #       , '@', msg_kbps, '(current keys:', msg_keys + ')')

            conn.send(f'CRACKING[CMD]{msg_percentage}[MSG]{msg_time_left}[MSG]{msg_kbps}[MSG]{msg_keys}'.encode(FORMAT))

            if hc.status_get_status_string() == "Cracked":
                break
            if hc.status_get_status_string() == "Aborted":
                break
            if hc.status_get_status_string() == "Exhausted":
                break

        sleep(2)

        with open(hc.outfile, 'r') as f:
            cracked = [i.strip() for i in f.readlines()]

            if len(cracked) > 0:
                for c in cracked:
                    # salt, ahash, bhash, ssid, plain = c.split(hc.separator.decode('utf-8'))
                    plain = c.split(hc.separator.decode('utf-8'))
                    Color.pl('\n{!} {C}Hash {G}cracked: {W}%s' % plain[0])
                return plain[0]
            else:
                Color.pl('\n{!} {C}Hash {R}NOT cracked{W}')
                return None

    else:
        print("STATUS: ", hc.status_get_status_string())


def handle_client(conn, addr):
    Color.pl('{!} {C}Client {R}%s{O}' % addr[0] + ' connected')
    conn.send("Welcome to the hash cracking server".encode(FORMAT))

    if conn.recv(SIZE).decode(FORMAT) == PASSWORD:
        Color.pl('{+} {C}Password {G}success')
        conn.send('Password success'.encode(FORMAT))
    else:
        Color.pl('{!} {C}Password {R}failed')
        conn.send('Password failed'.encode(FORMAT))
        conn.close()
        return

    while True:
        data = conn.recv(SIZE).decode(FORMAT)
        data = data.split("[CMD]")
        cmd = data[0]

        if cmd == "UPLOAD":
            Color.pl('{!} {C}File received')
            handshake = data[1]
            filepath = os.path.join(HANDSHAKE_DATA_PATH, 'handshake.hccapx')
            with open(filepath, "w") as handshake_file:
                handshake_file.write(handshake)

            send_data = "OK[CMD]File uploaded successfully"
            conn.send(send_data.encode(FORMAT))

            cracked = cracking(conn, handshake_file, 'rockyou.txt')
            if cracked != None:
                conn.send(f'CRACKED[CMD]{cracked}'.encode(FORMAT))
            else:
                conn.send('CRACKED[CMD]None'.encode(FORMAT))

        elif cmd == "LOGOUT":
            break

    Color.pl('{!} {C}Client {R}%s{O}' % addr[0] + ' disconnected')
    conn.close()


def main():
    print_banner()
    Color.pl('{+} {C}Server is starting{W}')
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    Color.pl('{+} {C}Server is listening on IP: {R}%s{O}' % IP + ' and port: {R}%s{W}' % PORT)

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        Color.pl('{+} {C}Total connections: {R}%s{O}' % str(threading.activeCount() - 1))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
