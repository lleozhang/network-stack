#include "ip.h"
#include "packetio.h"
#include "device.h"
#include <string>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <map>
#include <thread>
#include <utility>
#include <queue>
using namespace std;
mutex g_lock;
map <pair<string,uint>,int> router;//map dst_add to device number
map <pair<string,uint>,string> routing_tb;//map dst_add to mac_add to be sent 
map <pair<string,uint>,uint> routing_tab;//map dstinfo to ip_add to be sent
map <pair<string,uint>,uint> dis;
map <pair<uint,uint>,int> mask_tb;
map <pair<uint,uint>,string> mask_mac;
map <uint,int> pack_rec;
map <uint,string> dst_info;
queue <pair<pair<string,int>,int> >packet;
/* *
* @brief Send an IP packet to specified host .
*
* @param src Source IP address .
* @param dest Destination IP address .
* @param proto Value of ‘ protocol ‘ field in IP header .
* @param buf pointer to IP payload
* @param len Length of IP payload
* @return 0 on success , -1 on error .
*/

int sendIPPacket (const struct in_addr src , const struct in_addr dest ,int proto , 
const void * buf , int len, const int dev_id,const uint identi) 
{
   
    //printf("Sending with type=%d and identi:%u\n",proto,identi);
    if(len>(1<<15))
    {
        fprintf(stderr, "sendIPPacket:packet too large!\n");
        return -1;
    }
    const uint fr=src.s_addr;
    const uint ed=dest.s_addr;
    uint8_t *s=new uint8_t[len+50];
    if(proto==6)
    {
        fprintf(stderr,"sendIPPacket:ipv6 is not supported!\n");
        delete []s;
        return -1;
    }
    else if(proto==4)
        s[0]=0x45;
    else
    {
        fprintf(stderr,"sendIPpacket:no such protocol!\n");
        delete []s;
        return -1;
    }
    s[1]=0;
    s[3]=(len+20)&0xff;
    s[2]=((len+20)>>8)&0xff;
    s[4]=(identi>>8)&0xff;
    s[5]=identi&0xff;
    s[6]=(1<<7);
    s[7]=0;
    s[8]=0xff;
    s[9]=16;
    s[10]=s[11]=0;
    for(int i=0;i<4;i++)s[12+i]=(fr>>(32-(i+1)*8))&0xff;
    for(int i=0;i<4;i++)s[16+i]=(ed>>(32-(i+1)*8))&0xff;
    memcpy(s+20,buf,len);
    char *dst_mac=new char[7];
    int fl=0;
    if(ed==0)
    {
        for(int i=0;i<6;i++)dst_mac[i]=0xff;
        fl=sendFrame(s,len+20,0x800,dst_mac,dev_id);
    }else
    {
        fl=sendFrame(s,len+20,0x800,routing_tb[make_pair(dst_info[ed],ed)].c_str(),dev_id);
    }
    if(fl==-1)
    {
        fprintf(stderr,"sendIPPacket:send failed!\n");
        g_lock.unlock();
        delete []dst_mac;
        delete []s;
        return -1;
    }
    delete []dst_mac;
    delete []s;
    return 0;
}

IPPacketReceiveCallback ipcallback=NULL;

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback ) 
{
    if(!callback)
    {
        fprintf(stderr,"setIPcallback:no such callback!\n");
        return -1;
    }
    ipcallback=callback;
    return 0;
}

int receiveippacket(int dev_id)
{
    if(!ipcallback)
        return -1;
    receiveframe(dev_id);
    return 0;
}

uint getipbystr(const char* s)
{
    uint ret=0;
    for(int i=0;i<4;i++)
        ret|=(((uint)(uint8_t)(s[i]))<<(32-(i+1)*8));
    return ret;
}

string getstrbyip(unsigned ip)
{
    char *s=new char[5];
    string ret="";
    for(int i=0;i<4;i++)
    {
        s[i]=(ip>>(32-(i+1)*8))&0xff;
        ret+=s[i];
    }
    delete []s;
    return ret;
}


int setRoutingTable ( const struct in_addr dest ,
const struct in_addr mask ,
const void * nextHopMAC , const char * device ) 
{
    /*uint mask_add=mask.s_addr,dst=dest.s_addr;
    mask_tb.insert(make_pair(make_pair(dst,mask_add),findDevice(device)));
    string mac_add="";
    for(int i=0;i<6;i++)mac_add+=((char *)nextHopMAC)[i];
    mask_mac.insert(make_pair(make_pair(dst,mask_add),mac_add));*/
}

int find_maskip(uint ip)
{
    /*if(router.find(ip)!=router.end())
    {
        return router[ip];
    }else
    {
        int dev_id=0,max_length=0;
        for(auto it=mask_tb.begin();it!=mask_tb.end();it++)
        {
            uint ori_ip=it->first.first,mask_ad=it->first.second;
            int now_length=0;
            while((mask_ad&(1<<now_length))==0)now_length++;
            if(32-now_length<=max_length)continue;
            if((ip>>now_length)==(ori_ip>>now_length))
            {
                max_length=32-now_length;
                dev_id=it->second;
            }
        }
        return dev_id;
    }*/
}