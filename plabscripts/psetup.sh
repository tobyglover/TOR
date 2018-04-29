#!/bin/bash
#commands="cd nodedistro;cd YumFix;sudo cp fedora-updates.txt /etc/yum.repos.d/fedora-updates.repo;sudo cp fedora.txt /etc/yum.repos.d/fedora.repo;sudo yum update yum"
#commands="sudo yum install -y gcc openssl-devel bzip2-devel make zlib-devel libtool perl-core;"
#commands="cd nodedistro/OpenSslFix;tar xzf openssl-1.1.0h.tar.gz;"
#commands="cd nodedistro/OpenSslFix/openssl-1.1.0h;./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared zlib"
#commands="cd nodedistro/OpenSslFix/openssl-1.1.0h;sudo make;sudo make install"
#commands="cd nodedistro/OpenSslFix/;sudo cp openssl.sh /etc/profile.d/openssl.sh;sudo cp openssl-1.1.0h.conf /etc/ld.so.conf.d/openssl-1.1.0h.conf;sudo ldconfig -v"
#commands="cd nodedistro;tar xzf Python-2.7.14.tgz"
#commands="cd nodedistro/OpenSslFix;sudo cp Setup.dist ../Python-2.7.14/Modules/;sudo cp Setup.dist ../Python-2.7.14/Modules/Setup"
#commands="cd nodedistro/Python-2.7.14/;sudo ./configure --enable-optimizations;"
#commands="cd nodedistro/Python-2.7.14/;sudo make altinstall"
#commands="cd nodedistro;sudo mv /usr/local/bin/python2.7 /usr/local/bin/python2.7old;sudo cp binary.txt /usr/local/bin/python2.7"
#commands="cd nodedistro;sudo python2.7 get-pip.py"
#commands="sudo python2.7 -m ensurepip"
commands="cd tor4;ls;sudo ./setup.sh"
#commands="sudo yum install -y sqlite-devel;cd nodedistro;sudo mv /usr/local/bin/python2.7 /usr/local/bin/python2.7old;sudo cp binary.txt /usr/local/bin/python2.7"
#commands="sudo mv /usr/local/bin/python2.7 /usr/local/bin/python2.7old;sudo cp nodedistro/binary.txt /usr/local/bin/python2.7"

parallel-ssh -h scpnodes -t 0 -i -l tufts_dogar_comp112 -x "-t -t" $commands