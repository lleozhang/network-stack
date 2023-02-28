#include <cstdio>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include <queue>
#include <stack>
#include <ctime>
#include <unistd.h>
#include <pthread.h>
#include <thread>
#include <mutex>
#include "device.h"
#include "packetio.h"
#include "ip.h"
#include <pcap/pcap.h>
using namespace std;
static const unsigned srcip=0x0a640101,dstip=0x0a640302;
extern map <uint,int> router;//map dst_add to device number
extern map <uint,string> routing_tb;//map dst_add to mac_add to be sent 
extern map <uint,uint> dis;
extern map <pair<uint,uint>,int> mask_tb;
extern map <pair<uint,uint>,string> mask_mac;
extern unordered_map <uint,int> pack_rec;
int frame_callback(const void* buf,int len,int id)
{
    g_lock.lock();
    
    uint8_t *s=new uint8_t[len*2+50];
    memcpy(s,buf,len);
    MAC_add my_mac=getdevicemac(id);
    bool flag=0;
    for(int i=0;i<6;i++)
    {
        if(s[i+6]!=my_mac.mac[i])
        {
            flag=1;
            break;
        }
    }
    if(!flag)
    {
        delete []s;
        g_lock.unlock();
        return 1;
    }
    for(int i=0;i<6;i++)
    {
        if(s[i]!=my_mac.mac[i]&&s[i]!=0xff)
        {
            printf("frame:%d %x %x\n",i,s[i],my_mac.mac[i]);
            fprintf(stderr,"frame callback:bad direction!\n");
            delete []s;
            g_lock.unlock();
            return -1;
        }
    }
    delete []s;
    g_lock.unlock();
    return 0;
}
void initail_router_send(uint dstip)
{
    uint identi=((uint)rand()%0xff00)+(uint)0xff;
    g_lock.lock();
    for(int i=1;i<=getdevicenumber();i++)
    {
        uint8_t *buf=new uint8_t[10];
        struct in_addr src,dst;
        src.s_addr=getipadd(findDevicebyid(i).c_str());
        dst.s_addr=dstip;
        buf[0]=0;
        if(dstip==0)
        {
            dis[src.s_addr]=0,router[src.s_addr]=0;
            for(int j=1;j<=getdevicenumber();j++)
            {
                MAC_add my_mac=getdevicemac(j);
                for(int k=0;k<6;k++)buf[k+1]=my_mac.mac[k];
                int fl=sendIPPacket(src,dst,0,buf,7,j,router,routing_tb,identi);
                if(fl==-1)
                {
                    fprintf(stderr,"initail_router_send:broadcasting failed!\n");
                    exit(-1);
                }
            }
        }else
        {
            MAC_add my_mac=getdevicemac(i);
            for(int j=0;j<6;j++)buf[j+1]=my_mac.mac[j];
            int fl=sendIPPacket(src,dst,0,buf,7,i,router,routing_tb,identi);
            if(fl==-1)
            {
                fprintf(stderr,"initail_router_send:broadcasting failed!\n");
                exit(-1);
            }
        }
    }
    g_lock.unlock();
}



void flooding_send(uint dstip)
{
    g_lock.lock();
    dis[dstip]=0x3f3f3f3f;
    g_lock.unlock();
    initail_router_send(dstip);
}

int ip_callback(const void *buf,int len,int id)
{
    g_lock.lock();
    uint8_t *s=new uint8_t[len*2];
    memcpy(s,buf,len);
   /* printf("IPrec:");
    for(int i=0;i<len;i++)printf("%x ",s[i]);
    printf("%d\n",len);*/
    uint identi=(s[4+14]<<8)+s[5+14];
    if(s[14]==0x05)
    {
        unsigned fr_ip=getipbystr((const char*)(s+26));
        unsigned ed_ip=getipbystr((const char*)(s+30));
        if(ed_ip==0)
        {
           // printf("here!\n");
            unsigned d=s[34]+1;
            string src_mac="";
            for(int i=0;i<6;i++)src_mac+=(char)(s[i+35]);
            if(router.find(fr_ip)==router.end()||dis[fr_ip]>d)
            {
                router[fr_ip]=id;
                dis[fr_ip]=d;
                routing_tb[fr_ip]=src_mac;
                /*int temp=s[34];
                s[34]=0;
                for(int i=1;i<=getdevicenumber();i++)
                {
                    struct in_addr src,dst;
                    src.s_addr=getipadd(findDevicebyid(i).c_str());
                    dst.s_addr=0x0;
                    MAC_add my_mac=getdevicemac(i);
                    for(int j=0;j<6;j++)
                        s[j+35]=my_mac.mac[j];
                    
                    int fl=sendIPPacket(src,dst,0,s+34,len-34,i,router,routing_tb,0);
                    if(fl==-1)
                    {
                        fprintf(stderr, "ipcallback:copying failed!\n");
                        delete []s;
                        g_lock.unlock();
                        return -1;
                    }
                }
                s[34]=temp;*/
            }
            else
            {
                printf("no resending because dis[%x]=%u\n",fr_ip,dis[fr_ip]);
                delete []s;
                g_lock.unlock();
                return 0;
            }
            s[34]++;
            for(int i=1;i<=getdevicenumber();i++)
            {
                struct in_addr src,dst;
                src.s_addr=fr_ip;
                dst.s_addr=0x0;
                MAC_add my_mac=getdevicemac(i);
                for(int j=0;j<6;j++)
                    s[j+35]=my_mac.mac[j];
                
                int fl=sendIPPacket(src,dst,0,s+34,len-34,i,router,routing_tb,identi);
                if(fl==-1)
                {
                    fprintf(stderr, "ipcallback:copying failed!\n");
                    delete []s;
                    g_lock.unlock();
                    return -1;
                }
            }
            delete []s;
            g_lock.unlock();
        }else
        {
            for(int i=1;i<=getdevicenumber();i++)
            {
                unsigned my_ip=getipadd(findDevicebyid(i).c_str());
                if(my_ip==ed_ip)
                {
                    printf("You found me!\n");
                    g_lock.unlock();
                    sleep(20);
                    initail_router_send(0x0);
                    g_lock.lock();
                    delete []s;
                    g_lock.unlock();
                    return 0;
                }
            }
            if(dis.find(ed_ip)==dis.end()||dis[ed_ip]!=identi)
            {
                dis[ed_ip]=identi;
                for(int i=1;i<=getdevicenumber();i++)
                {
                    struct in_addr src,dst;
                    src.s_addr=fr_ip,dst.s_addr=ed_ip;
                    int fl=sendIPPacket(src,dst,0,s+34,len-34,i,router,routing_tb,identi);
                    if(fl==-1)
                    {
                        fprintf(stderr, "ipcallback:copying failed!\n");
                        delete []s;
                        g_lock.unlock();
                        return -1;
                    }
                }
            }
            delete []s;
            g_lock.unlock();
            return 0;
        }
    }else//sending
    {
        unsigned src_ip=getipbystr((const char *)s+26);
        unsigned dst_ip=getipbystr((const char *)s+30);
        for(int i=1;i<=getdevicenumber();i++)
        {
            unsigned my_ip=getipadd(findDevicebyid(i).c_str());
            if(my_ip==dst_ip)
            {
                string pack="";
                for(int j=34;j<len;j++)pack+=s[j];
                cout<<pack<<endl;
                if(pack=="ACK")
                {
                    if(pack_rec.find(identi)==pack_rec.end()||pack_rec[identi]!=0)
                    {
                        fprintf(stderr,"ipcallback:no such packet!\n");
                        delete []s;
                        g_lock.unlock();
                        return -1;
                    }
                    pack_rec[identi]=1;
                    delete []s;
                    g_lock.unlock();
                    return 0;
                }else
                {
                    string ack="ACK";
                    struct in_addr src,dst;
                    src.s_addr=dst_ip,dst.s_addr=src_ip;
                    int fl=sendIPPacket(src,dst,4,ack.c_str(),3,i,router,routing_tb,identi);
                    if(fl==-1)
                    {
                        printf("IPcallback:start flooding send on device %s with dstip=%x\n",findDevicebyid(i).c_str(),src_ip);
                        g_lock.unlock();
                        flooding_send(src_ip);
                        sleep(240);
                        g_lock.lock();
                        printf("IPcallback:end flooding send on device %s with dstip=%x\n",findDevicebyid(i).c_str(),src_ip);
                        fl=sendIPPacket(src,dst,4,ack.c_str(),3,i,router,routing_tb,identi);
                        if(fl==-1)
                        {
                            fprintf(stderr,"ipcallback:ACK failed!\n");
                            delete []s;
                            g_lock.unlock();
                            return -1;
                        }
                    }
                    delete []s;
                    g_lock.unlock();
                    return 0;
                }
            }
        }
        struct in_addr src,dst;
        src.s_addr=src_ip,dst.s_addr=dst_ip;
        int fl=sendIPPacket(src,dst,4,s+34,len-34,id,router,routing_tb,identi);
        if(fl==-1)
        {
            printf("IPcallback:start flooding send on device %s with dstip=%x\n",findDevicebyid(id).c_str(),src_ip);
            g_lock.unlock();
            flooding_send(dst_ip);
            sleep(240);
            g_lock.lock();
            printf("IPcallback:end flooding send on device %s with dstip=%x\n",findDevicebyid(id).c_str(),src_ip);
            fl=sendIPPacket(src,dst,4,s+34,len-34,id,router,routing_tb,identi);
            if(fl==-1)
            {
                fprintf(stderr,"ipcallback:resending failed!\n");
                delete []s;
                g_lock.unlock();
                return -1;
            }
        }
        delete []s;
        g_lock.unlock();
        return 0;
    }
    return 0;
}



void router_rec(const int dev_id,frameReceiveCallback frame_callback,IPPacketReceiveCallback ip_callback)
{
    setFrameReceiveCallback(frame_callback);
    setIPPacketReceiveCallback(ip_callback);
    while(1)
        receiveippacket(dev_id);
}

int arqsend(const char *buf,int len,uint srcip,uint dstip)
{  
    g_lock.lock();
    uint identi=(uint)rand()%0xffff;
    int cnt=0;
    while(pack_rec.find(identi)!=pack_rec.end()&&pack_rec[identi]==0)
    {
        cnt++;
        identi=(uint)rand()%0xffff;
        if(cnt>50000)
        {
            fprintf(stderr,"arqsend:too many packets sent!\n");
            g_lock.unlock();
            return -1;
        }
    }
    struct in_addr src,dst;
    int dev_id;
    bool flag=0;
    for(int i=1;i<=getdevicenumber();i++)
    {
        if(getipadd(findDevicebyid(i).c_str())==srcip)
        {
            flag=1;
            dev_id=i;
            src.s_addr=srcip,dst.s_addr=dstip;
            printf("%u\n",identi);
            pack_rec[identi]=0;
            int fl=sendIPPacket(src,dst,4,buf,len,i,router,routing_tb,identi);
            break;
        }
    }
    if(!flag)
    {
        g_lock.unlock();
        return 0;
    }
    int timeout=600;
    g_lock.unlock();
    sleep(timeout);
    g_lock.lock();
    if(pack_rec[identi]==1)
    {
        printf("packet %u successfully sent and received!\n",identi);
        g_lock.unlock();
        return 0;
    }
    else
    {
        //fprintf(stderr,"arqsend:arqsend failed!timeout!\n");
        pack_rec[identi]=1;
        dis[dstip]=0x3f3f3f3f;
        printf("arqsend:start flooding send on device %u with dstip %x\n",dev_id,dstip);
        g_lock.unlock();
        flooding_send(dstip);
        sleep(240);
        g_lock.lock();
        printf("arqsend:end flooding send on device %u with dstip %x\n",dev_id,dstip);
        if(router.find(dstip)==router.end()||dis[dstip]==0x3f3f3f3f)
        {
            fprintf(stderr,"arqsend failed:not connected!\n");
            g_lock.unlock();
            return -1;
        }else
        {
            g_lock.unlock();
            return arqsend(buf,len,srcip,dstip);
        }
        g_lock.unlock();
        return -1;
    }
        
    g_lock.unlock();
    return 0;
}
int main()
{
    srand(time(NULL));
    addalldevs();
    thread t[getdevicenumber()*5+10];
    for(int i=1;i<=getdevicenumber();i++)
    {
        t[i]=thread(router_rec,i,frame_callback,ip_callback);
    }
    sleep(30);
    t[1+getdevicenumber()]=thread(initail_router_send,0x0);
    t[1+getdevicenumber()].join();
    sleep(90);
    for(auto it=dis.begin();it!=dis.end();it++)
    {
        printf("%x %d\n",it->first,it->second);
    }
    for(int i=1;i<=getdevicenumber();i++)
    {
        t[i].join();
    }
    return 0;
}