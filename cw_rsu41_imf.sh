#!/bin/sh
# ddk 20210720
#set -x

#define DOT3_WSMP_PSID_4BYTE_MAX     0xEFFFFFFF
#define DOT3_WSMP_PSID_4BYTE_MIN     0xE0000000
#define DOT3_WSMP_PSID_3BYTE_MAX     0xDFFFFF
#define DOT3_WSMP_PSID_3BYTE_MIN     0xC00000
#define DOT3_WSMP_PSID_2BYTE_MAX     0xBFFF
#define DOT3_WSMP_PSID_2BYTE_MIN     0x8000
#define DOT3_WSMP_PSID_1BYTE_MAX     0x7F
#define DOT3_WSMP_PSID_1BYTE_MIN     0x00

#SUT_IPV6_ADDR="[::1]"
SUT_IPV4_ADDR="127.0.0.1"
#SUT_IPV4_ADDR="192.168.1.124"

IM_FWD_FILE="cw_IMF_data.txt"
if [ -e $IM_FWD_FILE ]; then
  while true; do 
  #cat $IM_FWD_FILE | socat -t0 stdin UDP6-DATAGRAM:$SUT_IPV6_ADDR:1516
  cat $IM_FWD_FILE | socat -t0 stdin UDP4-DATAGRAM:$SUT_IPV4_ADDR:1516
  echo "Broadcasting!"
  sleep 0.1
  done  
fi

