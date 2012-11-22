#!/bin/sh

set -e
set -x

ARCH=amd64
RELEASE=lucid
VERSION=20100211
UEC_TGZ=$RELEASE-server-uec-$ARCH.tar.gz
URL=http://uec-images.ubuntu.com/${RELEASE}/${VERSION}

TIMESTAMP=$(date +%Y%m%d%H%M%S)
BUCKET="${RELEASE}-${VERSION}-${ARCH}-${TIMESTAMP}"
[ ! -e $UEC_TGZ ] &&  wget $URL/$UEC_TGZ # This may take a bit
uec-publish-tarball ${UEC_TGZ} ${BUCKET} ${ARCH}
