#include <algorithm>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pcap/pcap.h>
#include "device.h"
#include "ip.h"
#include "packetio.h"
#include <unordered_map>
#include <string>
#include <iostream>
int total_device=0;//count device

unordered_map <string, int> name2id;
unordered_map <int, string> id2name;
unordered_map <uint,int> ip2id;
unordered_map <int,uint> id2ip;
map <MAC_add,int> mac2id;
map <int,MAC_add> id2mac;



int getdevicenumber()
{
    return total_device;
}

int addDevice(const char * device)
{
    if(!device)
        return -1;
    if(strlen(device)>=MAX_LENGTH)
        return -1;
    string device_name=device;
    if(name2id.find(device_name)!=name2id.end())
    {
        return name2id[device_name];
    }else 
    {
        char errbuf[MAX_ERRBUF];//存放错误信息的缓冲
        pcap_if_t *it;

        int tmp=pcap_findalldevs(&it,errbuf);
        if(tmp==-1)
        {
            return -1;
        }
        bool flag=0;
        while(it)
        {
            if(strcmp(it->name,device)==0)
            {
                flag=1;
                break;
            }
            it=it->next;
        }
        if(!flag)
            return -1;
        
        total_device++;
        if(total_device<0)
        {
            total_device-=1;
            return -1;//overflow
        }
        MAC_add dev_mac=getMACadd(device);
        uint dev_ip=getipadd(device);

        name2id[device_name]=total_device;
        id2name[total_device]=device_name;
        id2ip[total_device]=dev_ip;
        ip2id[dev_ip]=total_device;
        mac2id[dev_mac]=total_device;
        id2mac[total_device]=dev_mac;
        return total_device;
    }
}

int findDevice (const char * device) 
{
    if(!device)
    {
        return -1;
    }
    string device_name=device;
    if(name2id.find(device_name)!=name2id.end())
    {
        return name2id[device_name];
    }else 
    {
        return -1;
    }
}

string findDevicebyid(int id)
{
    if(id2name.find(id)==id2name.end())
    {
        fprintf(stderr,"findDevicebyid: no such device!\n");
        return "";
    }
    return id2name[id];
}

int addalldevs()
{
    struct ifaddrs *ifaddr=NULL;
    struct ifaddrs *ifa = NULL;
    int i = 0;
    if (getifaddrs(&ifaddr) == -1)
    {
         perror("getifaddrs"); 
    }
    else
    {
         for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
         {
                
             if( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_INET))
             {
                  printf("%s\n",ifa->ifa_name);
                  int tl=addDevice(ifa->ifa_name);
                  struct sockaddr_in *s = (struct sockaddr_in*)ifa->ifa_addr;
                  uint ret=0;
                    for(int i=0;i<4;i++)
                    {
                        ret+=(((s->sin_addr).s_addr>>(32-(i+1)*8))&0xff)<<(i*8);
                    }
                  if(tl==-1)
                  {
                      fprintf(stderr,"addalldevs:device add error!\n");
                        exit(-1);
                  }
             }
         }
         freeifaddrs(ifaddr);
    }
    return total_device;
}

MAC_add getMACadd(const char* device)
{
    struct ifaddrs *ifaddr=NULL;
    struct ifaddrs *ifa = NULL;
    int i = 0;
    if (getifaddrs(&ifaddr) == -1)
    {
         perror("getifaddrs"); 
    }
    else
    {
         for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
         {
             if( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) )
             {
                  struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                  if(strcmp(ifa->ifa_name,device)==0)
                  {
                        MAC_add ret;
                        for(int i=0;i<6;i++)ret.mac[i]=(uint8_t)s->sll_addr[i];
                        return ret;
                  }
             }
         }
         freeifaddrs(ifaddr);
    }
    fprintf(stderr,"getMACadd:mac not found!\n");
    exit(-1);
}


uint getipadd(const char* device)
{
    struct ifaddrs *ifaddr=NULL;
    struct ifaddrs *ifa = NULL;
    int i = 0;
    if (getifaddrs(&ifaddr) == -1)
    {
         perror("getifaddrs"); 
    }
    else
    {
         for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
         {
                
             if( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_INET) )
             {
                  sockaddr_in *s = (sockaddr_in*)ifa->ifa_addr;
                  if(strcmp(ifa->ifa_name,device)==0)
                  {
                        uint ret=0;
                        for(int i=0;i<4;i++)
                        {
                            ret+=(((uint)((s->sin_addr).s_addr)>>(32-(i+1)*8))&0xff)<<(i*8);
                        }
                        return ret;
                  }
             }
         }
         freeifaddrs(ifaddr);
    }
    fprintf(stderr,"getipadd:ip not found!\n");
    exit(-1);
}