#! /bin/bash
make distclean
./bootstrap.sh
make V=0 PLATFORM=vpp TAG=vpp install-deb
dpkg -i ./*.deb
