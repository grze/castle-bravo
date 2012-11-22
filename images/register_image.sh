#!/bin/sh

set -e
set -x

ARCH=amd64
RELEASE=lucid
VERSION=current
UEC_TGZ=$RELEASE-server-uec-$ARCH.tar.gz
UEC_IMG=$RELEASE-server-uec-$ARCH
URL=http://uec-images.ubuntu.com/${RELEASE}/${VERSION}
TYPE=c1.medium

TIMESTAMP=$(date +%Y%m%d%H%M%S)
BUCKET_KERNEL="k-$TIMESTAMP"
BUCKET_INITRD="r-$TIMESTAMP"
BUCKET_IMAGE="i-$TIMESTAMP"
[ $ARCH = "amd64" ] && IARCH=x86_64 || IARCH=i386
UEC_KERNEL=$UEC_IMG-vmlinuz-virtual
UEC_INITRD=$UEC_IMG-initrd-virtual
[ ! -e $UEC_TGZ ] &&  wget $URL/$UEC_TGZ # This may take a bit
[ ! -e $UEC_IMG.img ] && tar -S -xzf $UEC_TGZ
euca-bundle-image -i $UEC_KERNEL -r $IARCH --kernel true
euca-upload-bundle -b $BUCKET_KERNEL -m /tmp/$UEC_KERNEL.manifest.xml
EKI=$(euca-register $BUCKET_KERNEL/$UEC_KERNEL.manifest.xml | grep "^IMAGE" | awk '{print $2}') && echo $EKI
euca-bundle-image -i $UEC_INITRD -r $IARCH --ramdisk true
euca-upload-bundle -b $BUCKET_INITRD -m /tmp/$UEC_INITRD.manifest.xml
ERI=$(euca-register $BUCKET_INITRD/$UEC_INITRD.manifest.xml | grep "^IMAGE" | awk '{print $2}') && echo $ERI
euca-bundle-image -i $UEC_IMG.img -r $IARCH --kernel $EKI --ramdisk $ERI # This will take a long time (~10m)
euca-upload-bundle -b $BUCKET_IMAGE -m /tmp/$UEC_IMG.img.manifest.xml
EMI=$(euca-register $BUCKET_IMAGE/$UEC_IMG.img.manifest.xml | grep "^IMAGE" | awk '{print $2}') && echo $EMI

