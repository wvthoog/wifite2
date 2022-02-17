[![Android Supported](https://img.shields.io/badge/Android-Supported-green.svg)](#)
[![GitHub license](https://img.shields.io/github/license/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/blob/master/LICENSE)


Wifite and Hashcat over TCP
======

This repo is a fork of [`wifite`](https://github.com/kimocoder/wifite2/) from kimocoder which uses a backend Hashcat 
server to crack captured 4-way handhakes.

Build and install Pyhashcat and Hashcat
--------------------
Install the Pyhashcat library together with Hashcat version 6.1.1

```sh
$ git clone https://github.com/f0cker/pyhashcat.git
$ cd pyhashcat/pyhashcat
$ wget https://github.com/hashcat/hashcat/archive/refs/tags/v6.1.1.zip
$ unzip v6.1.1.zip && mv hashcat-6.1.1 hashcat
$ cd hashcat
$ sudo make install_library
$ sudo make install
$ cd ..
$ python3 setup.py build_ext -R /usr/local/lib
$ sudo python3 setup.py install
```

Install dependencies
--------------------
Install the dependencies needed for Wifite to run

```sh
$ sudo apt install aircrack-ng tshark hcxtools hcxdumptool reaver bully cowpatty macchanger -y
```

pytest-flake8

```sh
$ pip3 install -r requirements.txt
```

Clone Wifite
----------
```sh
$ git clone https://github.com/wvthoog/wifite2.git
$ cd wifite2
```

Server side (Kali)
--------------
Run the file Server.py on the server side on a host which has a Nvidia GPU and the CUDA toolkit installed

```sh
$ python3 Server.py --ip 192.168.1.5 --port 4000 --password testing123 --wordlist rockyou.txt
```

```sh
$ usage: Server.py [-h] --ip IP --port PORT --password PASSWORD --wordlist WORDLIST

optional arguments:
  -h, --help           show this help message and exit
  --ip IP              IP address of the server
  --port PORT          Listening port of the server
  --password PASSWORD  Set the password for the server
  --wordlist WORDLIST  Wordlist to used for cracking
```

Starting up Server.py script on the server side
![Server side process](https://imgur.com/iPwKfwW.gif)

Android side (Nethunter)
--------------
Run the file Server.py on the 

```sh
python3 Wifite.py --wpa --tcp-hashcat --hostname 192.168.1.5 --port 5000 --password testing123 --no-wps --no-pmkid
```

```sh
$ usage: Wifite.py [-h] --wpa --ip IP --port PORT --password PASSWORD --wordlist WORDLIST --no-wps --no-pmkid

optional arguments:
  --wpa                Target WPA enabled networks
  --ip IP              IP address of the server
  --port PORT          Listening port of the server
  --password PASSWORD  Password for the server
  --no-wps             Don't use WPS against the target
  --no-pmkid           Don't use PMKID against the target
```


Launching Wifite with Hashcat over TCP connecting to the server
![Android side process](https://imgur.com/bXzvuw7.gif)


