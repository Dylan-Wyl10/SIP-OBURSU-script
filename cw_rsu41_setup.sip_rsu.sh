# ddk 20210720

##############################################################################
# User defined variables
##############################################################################
#set -x
SUT_IPV4_ADDR=""
SUT_IPV4_MASK=""
SUT_IPV4_BCAST=""
SUT_IPV4_GW="" 
SUT_IPV4_NS=""
ACT_SVCS_PORT="    Port = 1516;"

ID="rsu"
PW="rsuadmin"
MIB_DIR="/home/duser/vm_share/fw_Release/docs/RSU/mibs/"
HOSTNAME=$(cat /etc/hostname)

#192.168.1.98=0xC0.0xA8.0x01.0x62
#FW_DSRC_ADDR1="0x000000000000000000000000C0A80162"
#10.12.6.3=0x0A.0x0C.0x06.0x03
#10.224.71.17 = 0x0A.0xE0.0x47.0x11
FW_DSRC_ADDR1="0x0000000000000000000000000AE04711"
FW_DSRC_PORT1="10002"
#141.211.144.5 = 0x8D.0xD3.0x90.0x05
FW_DSRC_ADDR2="0x0000000000000000000000008DD39005"
FW_DSRC_PORT2="3344"
FW_DSRC_RSSI1="-100"
FW_DSRC_STRT1="07E501010000"
FW_DSRC_STOP1="07E901010000"

FW_DSRC_PSID_BSM="0x20"
FW_DSRC_PSID_MAP="0x8001"
FW_DSRC_PSID_SPAT="0x8002"
FW_DSRC_PSID_RSM="0x8003"
FW_DSRC_PSID_SRM="0x8004"
FW_DSRC_PSID_SSM="0x8005"


STRT1="07E501010000"
STOP1="07E901010000"
STRT2="07E501010000"
STOP2="07E901010000"

##############################################################################
# Setting Environment
##############################################################################

_detect_host()
{
  if [ "$HOSTNAME" == "MKx-SDK" ]; then
    export DIR="$MIB_DIR"
    export IP="udp:$SUT_IPV4_ADDR:161"
  elif [[ $HOSTNAME =~ MK5 ]]; then
    export DIR="/mnt/rw/rsu1609/snmp/mibs/"
    export IP="udp:127.0.0.1:161"
    #export IP="udp6:[::1]:161"
    CHAN="172"
    TX_MODE="1"
  elif [[ $HOSTNAME =~ MK6C ]]; then
    export DIR="/mnt/rw/rsu1609/snmp/mibs/"
    #export IP="udp:127.0.0.1:161"
    export IP="udp6:[::1]:161"
    CHAN="183"
    TX_MODE="1"
  else
    echo "Host not recognized"
    exit 0
  fi
  export RW_AUTH_ARGS="-Le -t10 -r3 -v3 -lauthPriv -M $DIR -m RSU-MIB -u $ID -A $PW -X $PW -aSHA -xAES $IP"
}

##############################################################################
# Local setup (file manipulation and settings)
##############################################################################

_set_static_ipv4_eth0()
{
  read -n1 -p "Assign static ip $SUT_IPV4_ADDR?  Then press y" set_static_ip
  if [ "$set_static_ip" = "y" ]; then
    fw_setenv static_ip_addr  $SUT_IPV4_ADDR
    fw_setenv static_ip_mask  $SUT_IPV4_MASK
    fw_setenv static_ip_bcast $SUT_IPV4_BCAST
    fw_setenv static_ip_gw    $SUT_IPV4_GW
    fw_setenv static_ip_ns    $SUT_IPV4_NS

    sync
    echo ""
    echo "Rebooting, to enable static addressing"
    reboot
  else echo ""
    echo "No change in IPv4 address:"
    ifconfig eth0 | egrep 'inet|Link'
  fi
}

_setup_coredump()
{
  echo "Setting up coredump"
  sed  -i '/  "start")/ a \ \ \ \ ulimit -c unlimited' /opt/cohda/application/rsu1609/rc.rsu1609
  sync
}

_edit_stack_conf()
{
if [[ $HOSTNAME =~ MK5 ]]; then
  echo "ChannelMode                = 4"     >> /mnt/rw/rsu1609/conf/stack.conf
  echo "WSMP_ChannelNumber         = $CHAN" >> /mnt/rw/rsu1609/conf/stack.conf
  echo "ContinuousChanNum          = $CHAN" >> /mnt/rw/rsu1609/conf/stack.conf
  echo "ForcedSerChanNum           = $CHAN" >> /mnt/rw/rsu1609/conf/stack.conf
  echo "ForcedControlChanNum       = $CHAN" >> /mnt/rw/rsu1609/conf/stack.conf
  echo "WSATxEnable                = 0"     >> /mnt/rw/rsu1609/conf/stack.conf 
fi
  echo "Cohda_PCAP_LoggingDisabled = 0"     >> /mnt/rw/rsu1609/conf/stack.conf
  echo "Cohda_DebugLevel           = 4"     >> /mnt/rw/rsu1609/conf/stack.conf
  echo "SecurityEnable             = 0"     >> /mnt/rw/rsu1609/conf/stack.conf
  echo "SendUnsecuredDot2Header    = 1"     >> /mnt/rw/rsu1609/conf/stack.conf
  echo "Cohda_Crypto_AeroLogging     = all" >> /mnt/rw/rsu1609/conf/stack.conf
  echo "Cohda_Crypto_TestCountryCode = 840" >> /mnt/rw/rsu1609/conf/stack.conf

<<'SKIP0'
  echo "BSMEnabled                 = 1"     >> /mnt/rw/rsu1609/conf/stack.conf
  echo "BSMUnsecurePSID            = 0x20"  >> /mnt/rw/rsu1609/conf/stack.conf
  echo "Cohda_VS.VehLength         = 314"   >> /mnt/rw/rsu1609/conf/stack.conf
  echo "Cohda_VS.VehWidth          = 159"   >> /mnt/rw/rsu1609/conf/stack.conf
  echo "HeadingUseDefault          = 1"     >> /mnt/rw/rsu1609/conf/stack.conf 
  echo "RandMAC                    = 0"     >> /mnt/rw/rsu1609/conf/stack.conf
SKIP0
}

_edit_rsu_cfg()
{
  echo "" 
  #sed -i "57s/.*/$ACT_SVCS_PORT/" /mnt/rw/rsu1609/conf/rsu.cfg
  #sed -i -e '/IPV6NDPBridge/s/false/true/' /mnt/rw/rsu1609/conf/rsu.cfg
}

_manually_manipulate_rsu_files()
{
if [[ $HOSTNAME =~ MK* ]]; then
  echo
  echo "Performing manual setup that cannot be accomplished via SNMP"

  #_set_static_ipv4_eth0

  echo "stopping application(s)"
  /opt/cohda/application/rc.local stop &>/dev/null 
  #/mnt/rw/rc.local stop &>/dev/null 

  dmesg -c &>/dev/null 
  net-snmp-config --create-snmpv3-user -A $PW -X $PW -a SHA -x AES $ID

  _edit_stack_conf
  #_edit_rsu_cfg
  rm -rf /mnt/rw/rsu1609/conf/user.conf 
  #_setup_coredump
  sync

  echo "starting application(s)"
  /opt/cohda/application/rc.local start &>/dev/null 
  #/mnt/rw/rc.local start &2/dev/null 

  echo
  _detect_rsu1609_running
fi
}


##############################################################################
# Helper Functions
##############################################################################

_detect_rsu1609_running()
{
  sleep 1
  RSU_NUM_PROCS=$(ps -A | egrep 'rsu1609|rsu-monitor' | wc -l)
  until [ "$RSU_NUM_PROCS" = "2" ]; do
    echo "Waiting for 'rsu1609', 'rsu-monitor'..."
    sleep 1
    RSU_NUM_PROCS=$(ps -A | egrep 'rsu1609|rsu-monitor' | wc -l)
    done
  echo "rsu1609 successfully started!"
}

_set_standby()
{
  snmpset $RW_AUTH_ARGS rsuMode.0 i 2
  sleep 1
  until snmpget $RW_AUTH_ARGS rsuMode.0 | grep -q 'standby(2)'; do
  echo "Waiting for confirmation..."
  sleep 1
  done
}

_set_operate()
{
  snmpset $RW_AUTH_ARGS rsuMode.0 i 4
  sleep 1
  until snmpget $RW_AUTH_ARGS rsuMode.0 | grep -q 'operate(4)'; do
  echo "Waiting for confirmation..."
  sleep 1
  done
}

_enable_pcap_logging()
{
#RSU-MIB::rsuIfaceName.1 = STRING: cw-mon-tx
#RSU-MIB::rsuIfaceName.2 = STRING: cw-mon-txa
#RSU-MIB::rsuIfaceName.3 = STRING: cw-mon-rxa
#RSU-MIB::rsuIfaceName.4 = STRING: cw-mon-txb
#RSU-MIB::rsuIfaceName.5 = STRING: cw-mon-rxb

snmpset $RW_AUTH_ARGS \
rsuIfaceGenerate.1 i  1 \
rsuIfaceGenerate.2 i  1 \
rsuIfaceGenerate.3 i  1 \
rsuIfaceGenerate.4 i  1 \
rsuIfaceGenerate.5 i  1 \
rsuIfaceMaxFileSize.1 i 40 \
rsuIfaceMaxFileSize.2 i 40 \
rsuIfaceMaxFileSize.3 i 40 \
rsuIfaceMaxFileSize.4 i 40 \
rsuIfaceMaxFileSize.5 i 40 
}

##############################################################################
# WSMFwdRx_* table
##############################################################################
_destroy_WSMFwdRx_Table()
{
echo
echo "SNMP: Destroy rsuDsrcFwd table"
snmpset $RW_AUTH_ARGS \
rsuDsrcFwdStatus.1 i 6
}

#BSM
_set_WSMFwdRx1()
{
echo
echo "SNMP: Set WSMFwd_Rx_*" 
snmpset $RW_AUTH_ARGS \
rsuDsrcFwdPsid.1 x $FW_DSRC_PSID_BSM \
rsuDsrcFwdDestIpAddr.1 x $FW_DSRC_ADDR1 \
rsuDsrcFwdDestPort.1 i $FW_DSRC_PORT1 \
rsuDsrcFwdProtocol.1 i 2 \
rsuDsrcFwdRssi.1 i $FW_DSRC_RSSI1 \
rsuDsrcFwdMsgInterval.1 i 2 \
rsuDsrcFwdDeliveryStart.1 x $FW_DSRC_STRT1 \
rsuDsrcFwdDeliveryStop.1 x $FW_DSRC_STOP1 \
rsuDsrcFwdEnable.1 i 1 \
rsuDsrcFwdStatus.1 i 4
}

#MAP
_set_WSMFwdRx2()
{
echo
echo "SNMP: Set WSMFwd_Rx_*" 
snmpset $RW_AUTH_ARGS \
rsuDsrcFwdPsid.2 x $FW_DSRC_PSID_MAP \
rsuDsrcFwdDestIpAddr.2 x $FW_DSRC_ADDR1 \
rsuDsrcFwdDestPort.2 i $FW_DSRC_PORT1 \
rsuDsrcFwdProtocol.2 i 2 \
rsuDsrcFwdRssi.2 i $FW_DSRC_RSSI1 \
rsuDsrcFwdMsgInterval.2 i 2 \
rsuDsrcFwdDeliveryStart.2 x $FW_DSRC_STRT1 \
rsuDsrcFwdDeliveryStop.2 x $FW_DSRC_STOP1 \
rsuDsrcFwdEnable.2 i 1 \
rsuDsrcFwdStatus.2 i 4
}

#SPAT
_set_WSMFwdRx3()
{
echo
echo "SNMP: Set WSMFwd_Rx_*" 
snmpset $RW_AUTH_ARGS \
rsuDsrcFwdPsid.3 x $FW_DSRC_PSID_SPAT \
rsuDsrcFwdDestIpAddr.3 x $FW_DSRC_ADDR1 \
rsuDsrcFwdDestPort.3 i $FW_DSRC_PORT1 \
rsuDsrcFwdProtocol.3 i 2 \
rsuDsrcFwdRssi.3 i $FW_DSRC_RSSI1 \
rsuDsrcFwdMsgInterval.3 i 2 \
rsuDsrcFwdDeliveryStart.3 x $FW_DSRC_STRT1 \
rsuDsrcFwdDeliveryStop.3 x $FW_DSRC_STOP1 \
rsuDsrcFwdEnable.3 i 1 \
rsuDsrcFwdStatus.3 i 4
}

#Mcity edge device
_set_WSMFwdRx4()
{
echo
echo "SNMP: Set WSMFwd_Rx_*" 
snmpset $RW_AUTH_ARGS \
rsuDsrcFwdPsid.4 x $FW_DSRC_PSID_BSM \
rsuDsrcFwdDestIpAddr.4 x $FW_DSRC_ADDR2 \
rsuDsrcFwdDestPort.4 i $FW_DSRC_PORT2 \
rsuDsrcFwdProtocol.4 i 2 \
rsuDsrcFwdRssi.4 i $FW_DSRC_RSSI1 \
rsuDsrcFwdMsgInterval.4 i 2 \
rsuDsrcFwdDeliveryStart.4 x $FW_DSRC_STRT1 \
rsuDsrcFwdDeliveryStop.4 x $FW_DSRC_STOP1 \
rsuDsrcFwdEnable.4 i 1 \
rsuDsrcFwdStatus.4 i 4
}

#SRM
_set_WSMFwdRx5()
{
echo
echo "SNMP: Set WSMFwd_Rx_*" 
snmpset $RW_AUTH_ARGS \
rsuDsrcFwdPsid.5 x $FW_DSRC_PSID_SRM \
rsuDsrcFwdDestIpAddr.5 x $FW_DSRC_ADDR1 \
rsuDsrcFwdDestPort.5 i $FW_DSRC_PORT1 \
rsuDsrcFwdProtocol.5 i 2 \
rsuDsrcFwdRssi.5 i $FW_DSRC_RSSI1 \
rsuDsrcFwdMsgInterval.5 i 2 \
rsuDsrcFwdDeliveryStart.5 x $FW_DSRC_STRT1 \
rsuDsrcFwdDeliveryStop.5 x $FW_DSRC_STOP1 \
rsuDsrcFwdEnable.5 i 1 \
rsuDsrcFwdStatus.5 i 4
}

#SSM
_set_WSMFwdRx6()
{
echo
echo "SNMP: Set WSMFwd_Rx_*" 
snmpset $RW_AUTH_ARGS \
rsuDsrcFwdPsid.6 x $FW_DSRC_PSID_SSM \
rsuDsrcFwdDestIpAddr.6 x $FW_DSRC_ADDR1 \
rsuDsrcFwdDestPort.6 i $FW_DSRC_PORT1 \
rsuDsrcFwdProtocol.6 i 2 \
rsuDsrcFwdRssi.6 i $FW_DSRC_RSSI1 \
rsuDsrcFwdMsgInterval.6 i 2 \
rsuDsrcFwdDeliveryStart.6 x $FW_DSRC_STRT1 \
rsuDsrcFwdDeliveryStop.6 x $FW_DSRC_STOP1 \
rsuDsrcFwdEnable.6 i 1 \
rsuDsrcFwdStatus.6 i 4
}

##############################################################################
# Immediate Forward IMF 
##############################################################################
#SPAT PSID 8002, DSRCmsgID 19
#MAP  PSID 8002, DSRCmsgID 18
#TIM  PSID 8003, DSRCmsgID 31

_destroy_IMF()
{
echo
echo "SNMP: Destroy IMF Table"
snmpset $RW_AUTH_ARGS \
rsuIFMStatus.1 i 6
}

#BSM
_set_IMF1()
{
echo
echo "SNMP: Set IMF table entry"
snmpset $RW_AUTH_ARGS \
rsuIFMPsid.1 x 20 \
rsuIFMDsrcMsgId.1 i 31 \
rsuIFMTxMode.1 i $TX_MODE \
rsuIFMTxChannel.1 i $CHAN \
rsuIFMEnable.1 i 1 \
rsuIFMStatus.1 i 4
}

#MAP
_set_IMF2()
{
echo
echo "SNMP: Set IMF table entry"
snmpset $RW_AUTH_ARGS \
rsuIFMPsid.2 x 8001 \
rsuIFMDsrcMsgId.2 i 31 \
rsuIFMTxMode.2 i $TX_MODE \
rsuIFMTxChannel.2 i $CHAN \
rsuIFMEnable.2 i 1 \
rsuIFMStatus.2 i 4
}

#SPaT
_set_IMF3()
{
echo
echo "SNMP: Set IMF table entry"
snmpset $RW_AUTH_ARGS \
rsuIFMPsid.3 x 8002 \
rsuIFMDsrcMsgId.3 i 31 \
rsuIFMTxMode.3 i $TX_MODE \
rsuIFMTxChannel.3 i $CHAN \
rsuIFMEnable.3 i 1 \
rsuIFMStatus.3 i 4
}

#RSM
_set_IMF4()
{
echo
echo "SNMP: Set IMF table entry"
snmpset $RW_AUTH_ARGS \
rsuIFMPsid.4 x 8003 \
rsuIFMDsrcMsgId.4 i 31 \
rsuIFMTxMode.4 i $TX_MODE \
rsuIFMTxChannel.4 i $CHAN \
rsuIFMEnable.4 i 1 \
rsuIFMStatus.4 i 4
}

#SRM
_set_IMF5()
{
echo
echo "SNMP: Set IMF table entry"
snmpset $RW_AUTH_ARGS \
rsuIFMPsid.5 x 8004 \
rsuIFMDsrcMsgId.5 i 31 \
rsuIFMTxMode.5 i $TX_MODE \
rsuIFMTxChannel.5 i $CHAN \
rsuIFMEnable.5 i 1 \
rsuIFMStatus.5 i 4
}

#SSM
_set_IMF6()
{
echo
echo "SNMP: Set IMF table entry"
snmpset $RW_AUTH_ARGS \
rsuIFMPsid.6 x 8005 \
rsuIFMDsrcMsgId.6 i 31 \
rsuIFMTxMode.6 i $TX_MODE \
rsuIFMTxChannel.6 i $CHAN \
rsuIFMEnable.6 i 1 \
rsuIFMStatus.6 i 4
}


##############################################################################
# Store-and-Forward table 
##############################################################################
#define DOT3_WSMP_PSID_4BYTE_MAX     0xEFFFFFFF
#define DOT3_WSMP_PSID_4BYTE_MIN     0xE0000000
#define DOT3_WSMP_PSID_3BYTE_MAX     0xDFFFFF
#define DOT3_WSMP_PSID_3BYTE_MIN     0xC00000
#define DOT3_WSMP_PSID_2BYTE_MAX     0xBFFF
#define DOT3_WSMP_PSID_2BYTE_MIN     0x8000
#define DOT3_WSMP_PSID_1BYTE_MAX     0x7F
#define DOT3_WSMP_PSID_1BYTE_MIN     0x00

#SPAT PSID 8002, DSRCmsgID 19
#MAP  PSID 8002, DSRCmsgID 18
#TIM  PSID 8003, DSRCmsgID 31

_destroy_StoreAndForward()
{
echo
echo "SNMP: Destroy StoreAndForward Table"
snmpset $RW_AUTH_ARGS \
rsuSRMStatus.2 i 6 \
rsuSRMStatus.1 i 6
}


##############################################################################
# Main
##############################################################################

echo
_detect_host
_manually_manipulate_rsu_files

_set_standby
_destroy_WSMFwdRx_Table
_set_WSMFwdRx1
#_set_WSMFwdRx2
_set_WSMFwdRx3
#_set_WSMFwdRx4
#_set_WSMFwdRx5
#_set_WSMFwdRx6
_set_operate

_set_standby
_set_IMF1
_set_IMF2
_set_IMF3
_set_IMF4
_set_IMF5
_set_IMF6
_set_operate

_set_standby
_destroy_StoreAndForward
_set_operate

_set_standby
_enable_pcap_logging
_set_operate

echo
echo "SNMP: 'Walk' the entries"
#snmpwalk $RW_AUTH_ARGS iso.0.15628.4
set -x
snmpwalk $RW_AUTH_ARGS iso.0.15628

exit 0
