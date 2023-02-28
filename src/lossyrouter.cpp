#include "router.h"
#include "ip.h"
#include "packetio.h"
#include "device.h"
#include "socket.h"
#include <cstdio>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include <queue>
#include <stack>
#include <vector>
#include <pcap/pcap.h>
#include <ctime>
#include <unistd.h>
#include <pthread.h>
#include <thread>
#include <mutex>
#include <string>
#include <set>
#define LOSSYLINK
using namespace std;
thread t[MAXTHREAD];
static int thread_num=0;
string dev_name;
uint dev_ip;
static map<pair<string,uint>,clock_t> neighbor;
static map<pair<string,uint>,int> pack_num;
static map<uint,string> neighbor_info;

int manage_router(const uint8_t *s,uint fr_ip,uint ed_ip,int len,int id)
{
    int pos=20;
    int identi=(s[4]<<8)+s[5];
    string src_mac="";
    while(pos<26)
    {
        src_mac+=s[pos];
        pos++;
    }
    string tp_ip="";
    while(s[pos]!=' '&&pos<len)
    {
        tp_ip+=s[pos];
        pos++;
    }
    uint src_ip=getipbystr(tp_ip.c_str());
    pos++;
    if(neighbor_info.find(src_ip)!=neighbor_info.end())
    {
        if(pack_num[make_pair(neighbor_info[src_ip],src_ip)]>=identi)
        {
            return 1;
        }
    }
    map <pair<string,uint>,uint> M;
    while(pos<len)
    {
        string tb_name="";
        while(s[pos]!=' ')
        {
            tb_name+=s[pos];
            pos++;
        }
        pos++;
        string temp_ip="";
        while(s[pos]!=' ')
        {
            temp_ip+=s[pos];
            pos++;
        }
        uint tb_ip=getipbystr(temp_ip.c_str());
        pos++;
        uint d=(uint)atoi((const char *)s+pos)+1;
        while(s[pos]!=' ')
            pos++;
        pos++;
        string tmp_ip="";
        while(s[pos]!=' ')
        {
            tmp_ip+=s[pos];
            pos++;
        }
        pos++;
        uint inter_ip=getipbystr(tmp_ip.c_str());
        pair<string,uint> tb_item=make_pair(tb_name,tb_ip);
        if(tb_ip==src_ip)
        {
            neighbor[tb_item]=clock();
            neighbor_info[src_ip]=dev_name;
            pack_num[tb_item]=identi;
        }
        M[tb_item]=d;
        if(dis.find(tb_item)==dis.end()||dis[tb_item]>d)
        {
            if(dis[tb_item]==0x3f3f3f3f)
            {
                if(tb_ip==src_ip||inter_ip!=dev_ip)
                {
                    dis[tb_item]=d;
                    router[tb_item]=id;
                    routing_tb[tb_item]=src_mac;
                    routing_tab[tb_item]=src_ip;
                    dst_info[tb_ip]=tb_name;
                }
            }else
            {
                dis[tb_item]=d;
                router[tb_item]=id;
                routing_tb[tb_item]=src_mac;
                routing_tab[tb_item]=src_ip;
                dst_info[tb_ip]=tb_name;
                cout<<dev_name<<":"<<tb_item.first<<" "<<d<<endl;
            }
        }
    }
    vector <pair<string,uint> >v;
    for(auto it=routing_tab.begin();it!=routing_tab.end();it++)
    {
        if(it->second==src_ip)
        {
            if(M.find(it->first)==M.end())
            {
                printf("dst %s can't arrive!\n",it->first.first.c_str());
                dis.erase(it->first);
                router.erase(it->first);
                dst_info.erase(it->first.second);
                routing_tb.erase(it->first);
                v.push_back(it->first);

            }
        }
    }
    for(auto it=v.begin();it!=v.end();it++)
        routing_tab.erase(*it);
    return 1;
}

int transmit_packet(const uint8_t *s,uint fr_ip,uint ed_ip,int len,int id)
{
    #ifdef LOSSYLINK
        if(len>40)
        {
            printf("LOSSY LINK!\n");
            int loss=0xffff/2;
            int t=rand()%0xffff;
            if(t>loss)
            {
                printf("packet loss!\n");
                return 0;
            }
            if(dst_info.find(ed_ip)==dst_info.end())
            {
                return -1;
            }
        }
    #endif
    pair<string,uint> tb_item=make_pair(dst_info[ed_ip],ed_ip);
    if(dis.find(tb_item)==dis.end()||dis[tb_item]==0x3f3f3f3f)
        return -1;
    struct in_addr src,dst;
    src.s_addr=fr_ip,dst.s_addr=ed_ip;
    int identi=(s[4]<<8)+s[5];
    
    int fl=sendIPPacket(src,dst,4,s+20,len-20,router[tb_item],identi);
    return fl;
}

int ip_callback(const void *buf,int len,int id)
{
    uint fr_ip=getipbystr((const char*)buf+12),ed_ip=getipbystr((const char *)buf+16);
    if(ed_ip==0)
    {
        int fl=manage_router((const uint8_t*)buf,fr_ip,ed_ip,len,id);
        if(fl==-1)
        {
            fprintf(stderr,"ip_callback:router management error!\n");
            return -1;
        }
    }else
    {   
        if(ed_ip==dev_ip)
        {
            /*if(len>40)
            {
                ((char*)buf)[len]=0;
                printf("packet successfully received:%s\n",(char *)buf+40);
            }*/
            manage_packet((const uint8_t*)buf+20,len-20,fr_ip);
            return 0;
        }
        int fl=transmit_packet((const uint8_t*)buf,fr_ip,ed_ip,len,id);
        if(fl==-1)
        {
            fprintf(stderr,"ip_callback:transmit packet error!\n");
            return -1;
        }
    }
    return 0;
}

int frame_callback(const void* buf,int len,int id)
{
    MAC_add my_mac=id2mac[getdevicenumber()];
    MAC_add own_mac=id2mac[id];
    bool flag=0;
    for(int i=0;i<6;i++)
    {
        if(((uint8_t*)buf)[i+6]!=own_mac.mac[i])
        {
            flag=1;
            break;
        }
    }
    if(!flag)
    {
        return 1;
    }
    for(int i=0;i<6;i++)
    {
        if(((uint8_t*)buf)[i]!=my_mac.mac[i]&&((uint8_t*)buf)[i]!=0xff)
        {
            fprintf(stderr,"framecallback:not for me!\n");
            return -1;
        }
    }
    return 0;
}

void router_rec(const int dev_id)
{
    setFrameReceiveCallback(frame_callback);
    setIPPacketReceiveCallback(ip_callback);
    receiveippacket(dev_id);
}

void setdevinfo()
{
    dev_name=id2name[1];
    dev_ip=id2ip[1];
    dis[make_pair(dev_name,dev_ip)]=0;
    router[make_pair(dev_name,dev_ip)]=1;
    string my_mac="";
    for(int i=0;i<6;i++)my_mac+=id2mac[1].mac[i];
    routing_tb[make_pair(dev_name,dev_ip)]=my_mac;
}

void autosend()
{
    g_lock.lock();
    int dev_num=getdevicenumber();
    int identi=0;
    string buf="";
    MAC_add src_mac=id2mac[dev_num];
    g_lock.unlock();
    while(1)
    {
        g_lock.lock();
        buf.clear();
        for(int i=0;i<6;i++)buf+=(char)src_mac.mac[i];
        buf+=getstrbyip(dev_ip)+" ";
        for(auto it=dis.begin(),rit=routing_tab.begin();it!=dis.end();it++)
        {
            if(it->second==0x3f3f3f3f)
                continue;
            buf+=it->first.first+" "+getstrbyip(it->first.second)+" ";
            buf+=to_string(it->second)+" "+getstrbyip(rit->second)+" ";
        }
        for(int i=1;i<=dev_num;i++)
        {
            struct in_addr src,dst;
            src.s_addr=id2ip[i],dst.s_addr=0;
            sendIPPacket(src,dst,4,buf.c_str(),buf.length(),i,identi);
        }
        identi++;
        g_lock.unlock();
        sleep(2);
    }
}

void manage_neighbors()
{
    clock_t ed;
    vector <pair<string,uint> >V;
    double t;
    while(1)
    {
        g_lock.lock();
        ed=clock();
        V.clear();
        for(auto it=neighbor.begin();it!=neighbor.end();it++)
        {
            t=(ed-it->second)/CLOCKS_PER_SEC;
            if(t>=30.0)
            {
                fprintf(stderr,"neighbor %s went down!\n",it->first.first.c_str());
                V.push_back(it->first);
                pack_num.erase(it->first);
                vector <pair<string,uint> > v;
                for(auto rit=routing_tab.begin();rit!=routing_tab.end();rit++)
                {
                    if(rit->second==it->first.second)
                    {
                        dis[rit->first]=0x3f3f3f3f;
                        router.erase(rit->first);
                        routing_tb.erase(rit->first);
                        dst_info.erase(rit->first.second);
                        v.push_back(it->first);
                    }
                }
                for(auto rit=v.begin();rit!=v.end();rit++)
                    routing_tab.erase(*rit);
            }
        }
        for(auto it=V.begin();it!=V.end();it++)
        {
            neighbor.erase(*it);
            neighbor_info.erase((*it).second);
        }
        g_lock.unlock();
        usleep(500000);
    }
}

void packet_handler()
{
    uint8_t *tempbuf=new uint8_t[MAX_LENGTH];
    string buf;
    int len,id,fl;
    pair<pair<string,int>, int>pack;
    while(1)
    {
        g_lock.lock();
        while(!packet.empty())
        {
            pack=packet.front();
            packet.pop();
            buf=pack.first.first;
            len=pack.first.second;
            id=pack.second;
            for(int i=0;i<len;i++)
            {
                tempbuf[i]=buf[i];
            }
            fl=frame_callback(tempbuf,len,id);
            if(fl==0)
            {
                ip_callback(tempbuf+14,len-14,id);
            }
        }   
        g_lock.unlock();
        usleep(50000);
    }
}

int start_host()
{
    int dev_num=addalldevs();
    setdevinfo();
    for(int i=1;i<=dev_num;i++)
    {
        t[thread_num]=thread(router_rec,i);
        t[thread_num].detach();
        thread_num++;
    }
    t[thread_num]=thread(autosend);
    t[thread_num].detach();
    thread_num++;
    t[thread_num]=thread(manage_neighbors);
    t[thread_num].detach();
    thread_num++;
    t[thread_num]=thread(packet_handler);
    t[thread_num].detach();
    thread_num++;
    return 1;
}

int start_router()
{
    int dev_num=addalldevs();
    setdevinfo();
    for(int i=1;i<=dev_num;i++)
    {
        t[thread_num]=thread(router_rec,i);
        //t[thread_num].detach();
        thread_num++;
    }
    t[thread_num]=thread(autosend);
    //t[thread_num].detach();
    thread_num++;
    t[thread_num]=thread(manage_neighbors);
    //t[thread_num].detach();
    thread_num++;
    t[thread_num]=thread(packet_handler);
    //t[thread_num].detach();
    thread_num++;
    return 1;
}

void end_router()
{
    for(int i=0;i<thread_num;i++)
    {
        t[i].join();
    }
}