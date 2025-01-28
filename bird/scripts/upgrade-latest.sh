#!/bin/sh
set -e

# AS400671 uses the latest version of Bird 3.0.1
# ... the latest version from the official debian apt repo is pretty old
# ... and there are many updates on the latest version containing RPKI stability fixes and minor bugfixes

BIRD_VERSION="v3.0.1"

# backup first!
mkdir -p ./backup/bird
echo "Backing up previous configurations..."
cp -rp /etc/bird/ ./backup/
cp -rp /etc/bird/envvars ./backup/envvars # Not needed probably
cp -rp /lib/systemd/system/bird.service ./backup/
cp -rp /usr/lib/bird/prepare-environment ./backup

echo "Downloading..."
wget https://gitlab.nic.cz/labs/bird/-/archive/${BIRD_VERSION}/bird-${BIRD_VERSION}.tar.gz

echo "Unpacking..."
tar xvf bird-${BIRD_VERSION}.tar.gz

echo "Installing dependencies..."
apt -y install gcc g++ automake make m4 binutils flex bison libncurses5-dev libncursesw5-dev libreadline-dev libssh-dev libssh-gcrypt-4
apt -y remove bird2
rm -rf /etc/systemd/system/bird.service

echo "Building bird..."
cd bird-${BIRD_VERSION}
mkdir -p /usr/lib/bird /run/bird /etc/bird
autoreconf
./configure --prefix=/usr --sysconfdir=/etc/bird --runstatedir=/run/bird
make
make install

echo "Restore backups..."
cd ..
rm -rf /etc/bird/
cp -rp ./backup/bird/ /etc/
cp -rp ./backup/prepare-environment /usr/lib/bird/prepare-environment
cp -rp ./backup/bird.service /lib/systemd/system/bird.service
chmod +x /usr/lib/bird/prepare-environment

if id "bird" &>/dev/null; then
    echo "User bird is available. Looks good!"
else
    useradd -r -s /usr/sbin/nologin -g bird bird
    echo "Added user bird!"
fi

# start..?
echo "Starting bird..."
systemctl daemon-reload
systemctl enable bird
systemctl status bird
systemctl start bird
sleep 2
systemctl status bird

# force upgrade
birdc -r show proto
systemctl restart bird
sleep 10
birdc -r show proto
