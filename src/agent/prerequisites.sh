#!/bin/bash
# prerequisites
sudo apt install libpcap-dev libmysqlclient-dev libmysqld-dev cmake libtool mysql-server
# mysql++
cd ~
wget https://tangentsoft.net/mysql++/releases/mysql++-3.2.2.tar.gz
tar -xvf mysql++-3.2.2.tar.gz
rm mysql++-3.2.2.tar.gz
cd mysql++-3.2.2
rm ltmain.sh
if [ -f /usr/share/libtool/build-aux/ltmain.sh ] 
then
    ln -s /usr/share/libtool/build-aux/ltmain.sh ./ltmain.sh
elif [ -f /usr/share/libtool/config/ltmain.sh ]
then
    ln -s /usr/share/libtool/config/ltmain.sh ./ltmain.sh
else
    echo "[ERROR] Cannot create symlink to ltmain.sh!"
fi

# build mysql++ - depends if it is 32b or 64b OS
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
  # 64-bit
  ./configure --with-mysql-lib=/usr/lib/x86_64-linux-gnu
else
  # 32-bit
  ./configure --with-mysql-lib=/usr/lib
fi

make -j4
sudo make install

# treba v subore /usr/local/include/mysql++/common.h:133:28 zmenit include <mysql_version.h> na include <mysql/mysql_version.h>
# treba v subore /usr/local/include/mysql++/common.h:191:20: zmenit include <mysql_version.h> na include <mysql/mysql_version.h>
