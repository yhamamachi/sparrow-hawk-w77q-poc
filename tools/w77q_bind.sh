#!/bin/sh
# usage: w77q_bind.sh bind|unbind   (needs root; module w77q_raw.ko loaded for "bind")
DEV=${W77Q_SPI_DEV:-spi0.0}
S=/sys/bus/spi
HERE=$(cd "$(dirname "$0")" && pwd)
case "$1" in
bind)
  lsmod | grep -q "^w77q_raw" || insmod "${W77Q_KO:-$HERE/../kmod/w77q_raw.ko}"
  [ "$(cat $S/devices/$DEV/driver_override 2>/dev/null)" = "w77q-raw" ] && [ -e $S/drivers/w77q-raw/$DEV ] && exit 0
  echo w77q-raw > $S/devices/$DEV/driver_override
  [ -e $S/drivers/spi-nor/$DEV ] && echo $DEV > $S/drivers/spi-nor/unbind
  echo $DEV > $S/drivers/w77q-raw/bind ;;
unbind)
  echo $DEV > $S/drivers/w77q-raw/unbind
  echo spi-nor > $S/devices/$DEV/driver_override
  echo $DEV > $S/drivers/spi-nor/bind ;;
*) echo "usage: $0 bind|unbind"; exit 1;;
esac
