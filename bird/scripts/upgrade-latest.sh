#!/bin/sh
set -eu

# AS400671 uses the latest version of BIRD 3
# because distro packages may lag behind current BIRD 3 releases.

BIRD_VERSION="v3.3.0"
BIRD_COMMIT="10682b7befc59ddf5bf357bfb412ec63270141d2"
BIRD_REPO="https://gitlab.nic.cz/labs/bird.git"


# Backup first!
BACKUP_DIR="/root/bird_backup_${BIRD_VERSION}_$(date +%F)"
WORKDIR="." # /srv/
BUILD_DIR="${WORKDIR}/bird-${BIRD_VERSION}"


# Backup files first
echo "Backing up previous configuration..."
mkdir -p "$BACKUP_DIR"
[ -d /etc/bird ] && cp -a /etc/bird "$BACKUP_DIR/bird"
[ -f /etc/bird/envvars ] && cp -a /etc/bird/envvars "$BACKUP_DIR/envvars" # Not needed probably, depends on your setups
[ -f /usr/lib/bird/prepare-environment ] && cp -a /usr/lib/bird/prepare-environment "$BACKUP_DIR/prepare-environment"
[ -f /lib/systemd/system/bird.service ] && cp -a /lib/systemd/system/bird.service "$BACKUP_DIR/bird.service"


# Install necessary tools for build
echo "Installing dependencies..."
apt update
apt install -y \
    git dpkg-dev gcc g++ automake make m4 binutils flex bison \
    libncurses5-dev libncursesw5-dev libreadline-dev \
    libssh-dev libssh-gcrypt-4


# Download and verify checksum
echo "Downloading bird ${BIRD_VERSION}..."
mkdir -p "{$WORKDIR}"
rm -rf "${BUILD_DIR}"
git clone "$BIRD_REPO" -b "$BIRD_VERSION" --depth 1 "$BUILD_DIR"

echo "Verifying..."
DOWNLOAD_COMMIT="$(git -C bird-$BIRD_VERSION rev-parse HEAD)"
if [ "$DOWNLOAD_COMMIT" != "$BIRD_COMMIT" ]; then
    echo "ERROR: BIRD $BIRD_VERSION commit mismatch!"
    echo "Downloaded: $DOWNLOAD_COMMIT"
    echo "Verified:   $BIRD_COMMIT"
    echo "Make sure to check https://gitlab.nic.cz/labs/bird/-/commits/$BIRD_VERSION for extra verification."
    exit 1
fi
echo "Verified commit."

echo "Removing unused bird2 (if applicable)"
apt -y remove bird2
rm -rf /etc/systemd/system/bird.service


echo "Building bird..."
cd "${BUILD_DIR}"
mkdir -p /usr/lib/bird /run/bird /etc/bird
export DEB_BUILD_MAINT_OPTIONS="hardening=+all"
eval "$(dpkg-buildflags --export=sh)"
autoreconf
./configure --prefix=/usr --sysconfdir=/etc/bird --runstatedir=/run/bird
make -j"$(nproc)"

echo "Ensuring bird user/group exists..."
if ! getent group bird >/dev/null 2>&1; then
    groupadd -r bird
fi
if ! id bird >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -g bird bird
fi

echo "Installing bird..."
make install

echo "Restoring config/service files..."
rm -rf /etc/bird

if [ -d "$BACKUP_DIR/bird" ]; then
    cp -a "$BACKUP_DIR/bird" /etc/bird
fi

if [ -f "$BACKUP_DIR/prepare-environment" ]; then
    mkdir -p /usr/lib/bird
    cp -a "$BACKUP_DIR/prepare-environment" /usr/lib/bird/prepare-environment
    chmod +x /usr/lib/bird/prepare-environment
fi

if [ -f "$BACKUP_DIR/bird.service" ]; then
    cp -a "$BACKUP_DIR/bird.service" /lib/systemd/system/bird.service
fi

# start..?
mkdir -p /run/bird
chown bird:bird /run/bird || true

echo "Testing bird config..."
bird -p -c /etc/bird/bird.conf

echo "Starting bird..."
systemctl daemon-reload
systemctl enable bird
systemctl status bird
systemctl start bird
sleep 2
systemctl status bird

# force upgrade in case of failure
birdc -r show proto
systemctl restart bird
sleep 10
birdc -r show proto

echo "Upgrade complete."
echo "Backup stored at: $BACKUP_DIR"
