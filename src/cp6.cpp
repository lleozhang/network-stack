#include "ip.h"
#include "packetio.h"
#include "device.h"
#include <pcap/pcap.h>
extern map <uint,int> router;//map dst_add to device number
extern map <uint,string> routing_tb;//map dst_add to mac_add to be sent 
extern map <uint,uint> dis;
extern map <pair<uint,uint>,int> mask_tb;
extern map <pair<uint,uint>,string> mask_mac;
extern unordered_map <uint,int> pack_rec;
int main()
{
    addalldevs();
    struct in_addr src_ip1,mask_ad1;
    src_ip1.s_addr=0x0a640100,mask_ad1.s_addr=0xffffff00;
    uint8_t *mac=new uint8_t[10];
    setRoutingTable(src_ip1,mask_ad1,mac,findDevicebyid(1).c_str());
    struct in_addr src_ip2,mask_ad2;
    src_ip2.s_addr=0x0a640100,mask_ad2.s_addr=0xffffffff;
    setRoutingTable(src_ip2,mask_ad2,mac,findDevicebyid(2).c_str());
    printf("%d\n",find_maskip(0x0a640100));//shoule be 2
    return 0;
}