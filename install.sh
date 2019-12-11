#!/bin/bash

#Default third-party file versions for:
#BerkeleyDB, Libsodium, MBedTLS, OpenSSL, QRencode, XAMPP

DBV='18.1.32'
LSV='1.0.18'
MBV='2.16.3'
OSV='1.1.1d'
QRV='4.0.2'
XAV='7.3.11-0'

DOWNLOADS=~/Downloads
DESKTOP=~/Desktop
EDITOR="sudo gnome-terminal -- nano -c"

function pause(){
   read -p "$*"
}
 
if [ $# -eq 1 ] && [ $1 == --default ]; then
echo 'Using default file versions:'
else
if [ $# -eq 1 ] && [ $1 == --clean-ssp ]; then
echo 'Preparing for re-building ssp-api (third party files are not deleted):'
mkdir ~tmp~
mv *.*z ~tmp~
sudo rm -r SSP-API-Demo
sudo rm -r SSP-API-Source
mv ~tmp~/*.*z .
rmdir ~tmp~
sudo rm -r ~/Desktop/SSP-API-Demo
sudo rm /usr/local/lib/libsspapi.*
tar -xf SSP-API-Linux-*.tar.xz
sudo chmod +x install.sh
exit
else
if [ $# -eq 1 ] && [ $1 == --clean-all ]; then
echo 'Preparing for re-installation (downloads are not deleted):'
mkdir ~tmp~
mv *.*z ~tmp~
sudo rm -r Blowfish-Source
sudo rm -r Lodepng-Source
sudo rm -r PHP-EXT-Source
sudo rm -r SSP-API-Demo
sudo rm -r SSP-API-Source
sudo rm -r db-*
sudo rm -r libsodium-*
sudo rm -r mbedtls-*
sudo rm -r openssl-*
sudo rm -r qrencode-*
mv ~tmp~/*.*z .
rmdir ~tmp~
sudo rm -r ~/Desktop/SSP-API-Demo
sudo rm /usr/local/lib/lib*
tar -xf SSP-API-Linux-*.tar.xz
sudo chmod +x install.sh
exit
else
if [ $# -eq 6 ]; then
DBV=$1
LSV=$2
MBV=$3
OSV=$4
QRV=$5
XAV=$6
else
echo
echo 'Read install.html for installation instructions'
echo
echo 'To install the file versions available at the last revision of this script enter:'
echo ./install.sh --default
echo
echo 'The defaults are:'
echo db-${DBV}.tar.gz
echo libsodium-${LSV}-stable.tar.gz 
echo mbedtls-${MBV}-apache.tgz
echo openssl-${OSV}.tar.gz
echo qrencode-${QRV}.tar.gz
echo xampp-linux-x64-${XAV}-installer.run
echo
echo 'The websites to check for the latest versions are:'
echo https://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads
echo https://download.libsodium.org/libsodium/releases
echo https://tls.mbed.org/download
echo https://www.openssl.org/source
echo https://fukuchi.org/works/qrencode
echo https://www.apachefriends.org
echo
echo 'To install newer versions, edit this file or specify all version numbers as parameters, for example:'
echo ./install.sh  ${DBV}  ${LSV}  ${MBV}  ${OSV}  ${QRV}  ${XAV}
echo 
echo 'The Berkeley database requires registration and manual download of the installation file'
echo
exit
fi
fi
fi
fi

# Downloaded file names
DBZ=db-$DBV.tar.gz
LSZ=libsodium-$LSV-stable.tar.gz
MBZ=mbedtls-$MBV-apache.tgz
OSZ=openssl-$OSV.tar.gz
QRZ=qrencode-$QRV.tar.gz
XAZ=xampp-linux-x64-$XAV-installer.run

# Folder names
DB=db-$DBV
LS=libsodium-stable
MB=mbedtls-$MBV
OS=openssl-$OSV
QR=qrencode-$QRV
XA=$XAZ

echo 'File versions being sought:'
echo
echo  $DBZ
echo  $LSZ
echo  $MBZ
echo  $QRZ
echo  $XAZ
echo 

echo 'Installing gcc and make'
echo
if [ ! -e /usr/bin/gcc ]; then sudo apt install gcc; fi
if [ ! -e /usr/bin/make ]; then sudo apt install make; fi
if [ ! -e /bin/netstat ]; then sudo apt install net-tools; fi
if [ ! -e /usr/share/autoconf ]; then sudo apt install autoconf; fi
echo

echo 'Downloading and extracting Files:'
echo
#OPT=--no-check-certificates
OPT=--ca-directory=/etc/ssl/certs
if [ ! -e ${DBZ} ]; then echo Berkeley Database has not been downloaded; exit; fi
if [ -e ${DBZ} ] && [ ! -e ${DB} ]; then tar xvzf ${DBZ}; fi

if [ ! -e ${LSZ} ]; then wget ${OPT} https://download.libsodium.org/libsodium/releases/${LSZ}; fi
if [ ! -e ${LSZ} ]; then echo ${LSZ} has not been downloaded; exit; fi
if [ -e ${LSZ} ] && [ ! -e ${LS} ]; then tar xvzf ${LSZ}; fi

if [ ! -e ${MBZ} ]; then wget ${OPT} https://tls.mbed.org/download/${MBZ}; fi
if [ ! -e ${MBZ} ]; then echo ${MBZ} has not been downloaded; exit; fi
if [ -e ${MBZ} ] && [ ! -e ${MB} ]; then tar xvzf ${MBZ}; fi

if [ ! -e ${OSZ} ]; then wget ${OPT} https://www.openssl.org/source/${OSZ}; fi
if [ ! -e ${OSZ} ]; then echo ${OSZ} has not been downloaded; exit; fi
if [ -e ${OSZ} ] && [ ! -e ${OS} ]; then tar xvzf ${OSZ}; fi

if [ ! -e ${QRZ} ]; then wget ${OPT} https://fukuchi.org/works/qrencode/${QRZ}; fi
if [ ! -e ${QRZ} ]; then echo ${QRZ} has not been downloaded; exit; fi
if [ -e ${QRZ} ] && [ ! -e ${QR} ]; then tar xvzf ${QRZ}; fi

if [ ! -e ${XAZ} ]; then wget ${OPT} https://www.apachefriends.org/xampp-files/${XAV/%-*/}/xampp-linux-x64-${XAV}-installer.run; fi
if [ ! -e ${XAZ} ]; then echo ${XAZ} has not been downloaded; exit; fi

echo Compiling and installing files:
echo
echo ${DB}
if [ ! -e /usr/local/lib/libdb.so ]; then
cd ${DOWNLOADS}/${DB}/build_unix
../dist/configure
make
sudo make install
sudo find /usr/local/Berkeley* -name libdb*.so -exec cp -P {} /usr/local/lib \;
sudo find /usr/local/Berkeley* -name db.h -exec cp {} /usr/local/include \;
echo
fi

echo ${LS}
if [ ! -e /usr/local/lib/libsodium.so ]; then
cd ${DOWNLOADS}/${LS}
./configure --disable-dependency-tracking
make
#make check
sudo make install
echo
fi

echo ${MB}
if [ ! -e /usr/local/lib/libmbed.so ]; then
echo
cd ${DOWNLOADS}/${MB}
make no_test CFLAGS='-O2 -fPIC -DMBEDTLS_THREADING_PTHREAD -DMBEDTLS_THREADING_C'
sudo make install
cd /usr/local/lib
sudo gcc -shared -o libmbed.so -Wl,-whole-archive -lmbedcrypto -lmbedtls -lmbedx509 -Wl,-no-whole-archive
echo
fi

echo ${OS}
if [ ! -e /usr/local/lib/libssl.so ]; then
echo
cd ${DOWNLOADS}/${OS}
./config
make
#make test
sudo make install
echo
fi

echo ${QR}
if [ ! -e /usr/local/lib/libqrencode.so ]; then
cd ${DOWNLOADS}/${QR}
./configure --without-tools
make
sudo make install
echo
fi

echo ${XA}
cd ${DOWNLOADS}
if [ ! -x ${XAZ} ]; then
echo
echo '*****************************************************'
echo 'Install XAMPP using its Setup Wizard'
echo 'Uncheck "Launch XAMPP" when Setup has finished'
echo '*****************************************************'
echo
chmod +x ${XAZ}
sudo ./${XAZ}
fi
echo

echo Blowfish Library
if [ ! -e /usr/local/lib/libblowfish.so ]; then
cd ${DOWNLOADS}/Blowfish-Source
make
echo
fi

echo Lodepng Library
if [ ! -e /usr/local/lib/liblodepng.so ]; then
cd ${DOWNLOADS}/Lodepng-Source
make
echo
fi

echo SSP-API Library
if [ ! -e /usr/local/lib/libsspapi.so ]; then
cd ${DOWNLOADS}/SSP-API-Source
make
echo
fi

echo PHP Extension
if [ ! -e ${DOWNLOADS}/PHP-EXT-Source/modules/sspphp.so ]; then
echo
cd ${DOWNLOADS}/PHP-EXT-Source
/opt/lampp/bin/phpize
./configure --enable-sspphp --with-php-config=/opt/lampp/bin/php-config
sudo make install
echo 
echo '*****************************************************'
echo 'Editing /opt/lampp/etc/php.ini...'
echo 'Locate the section on Dynamic Extensions (~ line 925)'
echo 'Add the line: extension=sspphp.so'
echo 'Save the file (^O <Enter>) and close the editor (^X)'
echo '*****************************************************'
echo
sudo $EDITOR /opt/lampp/etc/php.ini
pause 'Press <Enter> to continue...'
echo
fi

echo SSP-API-Demo
cd ${DOWNLOADS}
if [ ! -d ${DESKTOP}/SSP-API-Demo ]; then
mkdir ${DESKTOP}/SSP-API-Demo
if [ ! -d ${DESKTOP}/SSP-API-Demo ]; then
echo 'Unable to create folder ${DESKTOP}/SSP-API-Demo'; exit; fi

cp ${DOWNLOADS}/SSP-API-Source/ssphttp ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Source/sspfunc ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Demo/.sspapi.cfg ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Demo/ssp.server.crt ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Demo/ssp.server.key ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Demo/DebugFilter.txt ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Demo/rx.sh ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Demo/rh.sh ${DESKTOP}/SSP-API-Demo
cp ${DOWNLOADS}/SSP-API-Demo/rf.sh ${DESKTOP}/SSP-API-Demo
chmod +x ${DESKTOP}/SSP-API-Demo/rh.sh
chmod +x ${DESKTOP}/SSP-API-Demo/rf.sh
chmod +x ${DESKTOP}/SSP-API-Demo/rx.sh
fi

if [ ! -e /opt/lampp/etc/ssl.crt/server.crt.old ]; then
sudo mv /opt/lampp/etc/ssl.crt/server.crt /opt/lampp/etc/ssl.crt/server.crt.old
sudo ln -s ${DOWNLOADS}/SSP-API-Demo/web.server.crt /opt/lampp/etc/ssl.crt/server.crt
fi

if [ ! -e /opt/lampp/etc/ssl.key/server.key.old ]; then
sudo mv /opt/lampp/etc/ssl.key/server.key /opt/lampp/etc/ssl.key/server.key.old
sudo ln -s ${DOWNLOADS}/SSP-API-Demo/web.server.key /opt/lampp/etc/ssl.key/server.key
fi

if [ ! -e /opt/lampp/htdocs/sqrl ]; then
sudo mkdir /opt/lampp/htdocs/sqrl
sudo ln -s ${DOWNLOADS}/SSP-API-Demo/sqrl.index.php /opt/lampp/htdocs/sqrl/index.php
fi

if [ ! -e /opt/lampp/htdocs/auth ]; then
sudo mkdir /opt/lampp/htdocs/auth
sudo ln -s ${DOWNLOADS}/SSP-API-Demo/auth.index.php /opt/lampp/htdocs/auth/index.php
fi

if [ ! -e /opt/lampp/htdocs/test ]; then
sudo mkdir /opt/lampp/htdocs/test
sudo ln -s ${DOWNLOADS}/SSP-API-Demo/test.index.php /opt/lampp/htdocs/test/index.php
sudo cp ${DOWNLOADS}/SSP-API-Demo/.sspapi.cfg /opt/lampp/htdocs/test
sudo cp ${DOWNLOADS}/SSP-API-Demo/DebugFilter.txt /opt/lampp/htdocs/test
sudo chmod a+w -R /opt/lampp/htdocs/test
fi

echo

# Customize with the server ip address
echo '****************************************************'
echo 'Running hostname.-I ...'
echo 'Make a note of your ip address'
echo '****************************************************'
echo
hostname -I
echo
pause 'Press <Enter> to continue...'
echo
echo '****************************************************'
echo 'Editing /etc/hosts...'
echo 'Add these two lines using your ip address'
echo '  <ip address> ssp.server'
echo '  <ip address> web.server'
echo 'Save the file (^O <Enter>) and close the editor (^X)'
echo '****************************************************'
echo
sudo ${EDITOR} /etc/hosts
pause 'Press <Enter> to continue...'
echo
echo '****************************************************'
echo 'Editing '${DESKTOP}'/SSP-API-Demo/.sspapi.cfg...'
echo 'For ListenIP=<ssp-server-ip>'
echo '  Replace <ssp-server-ip> with your ip address'
echo 'For PrivateAccessIp=<web-server-ip>'
echo '  Replace <web-server-ip> with your ip address'
echo 'Save the file (^O <Enter>) and close the editor (^X)'
echo '****************************************************'
echo
${EDITOR} ${DESKTOP}/SSP-API-Demo/.sspapi.cfg
pause 'Press <Enter> to continue...'
echo
sudo ldconfig
echo 'Done.  Continue at step 14 in install.html'

