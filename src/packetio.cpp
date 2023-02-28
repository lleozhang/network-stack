/* *
* @file packetio . h
* @brief Library supporting sending / receiving Ethernet II frames .
*/
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "device.h"
#include "ip.h"
#include "packetio.h"
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <string>
#include <iostream>
#include <cstring>
#include <thread>
#include <cstdio>
#include <queue>
#include <assert.h>
using namespace std;

/* *
* @brief Encapsulate some data into an Ethernet II frame and send it .
*
* @param buf Pointer to the payload .
* @param len Length of the payload .
* @param ethtype EtherType field value of this frame .
* @param destmac MAC address of the destination .
* @param id ID of the device ( returned by ‘ addDevice ‘) to send on .
* @return 0 on success , -1 on error .
* @see addDevice
*/
frameReceiveCallback call_back=NULL;
static void pcap_callback(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
    g_lock.lock();
    uint id=*argument;
    int len=packet_header->len;
    string buf="";
    for(int i=0;i<len;i++)buf+=packet_content[i];
    assert(buf.length()==len);
    packet.push(make_pair(make_pair(buf,len),id));
    g_lock.unlock();
}

pcap_t* deviceactivate(int id)
{
    string name=findDevicebyid(id);

    if(name.length()==0)
    {
        fprintf(stderr,"deviceactivate:no such device!\n");
        return NULL;
    }
    char* ERRBUF=new char(MAX_ERRBUF);
    pcap_t* device = pcap_create(name.c_str(), ERRBUF);

    if(!device)
    {
        fprintf(stderr,"id=%d,deviceactivate:%s\n",id,ERRBUF);
        delete []ERRBUF;
        return NULL;
    }
    int ttemp=0;
    ttemp = pcap_set_timeout(device, -1);
    int fl=pcap_activate(device);
    
    if(fl<0)
    {
        fprintf(stderr,"deviceactivate:activate failed!\n");
        delete []ERRBUF;
        return NULL;
    }
    delete []ERRBUF;
    return device;
}


int sendFrame (const void * buf , int len ,int ethtype , const void * destmac , int id ) 
{
    
    if(id2mac.find(id)==id2mac.end())
    {
        fprintf(stderr,"sendframe: no such device!\n");
        return -1;
    }
    MAC_add fr_mac=id2mac[id];
    pcap_t* fr_device=deviceactivate(id);
    if(!fr_device)
    {
        fprintf(stderr,"sendFrame:device activate failed!\n");
        
        return -1;
    }
    if(len+14>=MAX_SIZE)
    {
        fprintf(stderr,"sendFrame:packet too long!\n");
        pcap_close(fr_device);
        return -1;
    }
    uint8_t* pack=new uint8_t[len+14];
    memset(pack,0,sizeof(pack));
    for(int i=0;i<6;i++)
    {
        pack[i+6]=fr_mac.mac[i];
        pack[i]=((uint8_t*)destmac)[i];
    }
    pack[12]=(ethtype>>8)&(0xFF);
    pack[13]=(ethtype)&0xFF;
    
    memcpy(pack+14,buf,len);
    int attem=pcap_sendpacket(fr_device, pack, len+14);
    if(attem==-1)
    {
        fprintf(stderr,"sendFrame:packet not sent!\n");
        pcap_close(fr_device);
        delete []pack;
        return -1;
    }
    delete []pack;
    pcap_close(fr_device);
    return 0;

}

int receiveframe(int id)
{
    pcap_t* des_device=deviceactivate(id);
    pcap_pkthdr* pkt_header=new pcap_pkthdr;
    u_char* temp=new u_char;
    (*temp)=(uint)(id);
    pcap_loop(des_device,-1,pcap_callback,temp);
    pcap_close(des_device);
    delete pkt_header;
    delete temp;
}

int setFrameReceiveCallback (frameReceiveCallback callback )
{
    if(!callback)
    {
        fprintf(stderr,"setframecallback:no such function!\n");
        return -1;
    }
    call_back=callback;
    return 0;
}
