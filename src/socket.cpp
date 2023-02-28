#include "socket.h"
#include "ip.h"
#include "packetio.h"
#include "device.h"
#include "router.h"
#include <map>
#include <algorithm>
#include <iostream>
#include <queue>
#include <stack>
#include <deque>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
using namespace std;
static const uint closed_seq = 0x80000000;
static int socket_id = 10001;
static int window_size = 4000;
map<int, pair<uint, ushort> > sock_bind;
map<pair<uint, ushort>, int> sock_rbind;
map<int, pair<uint, ushort> > sock_conn;
map<pair<uint, ushort>, int> sock_rconn;
map<pair<uint, ushort>, int> sock_rpos;
map<int, pair<uint, ushort> > sock_pos;
static map<int, int> sock_state;
static bool n_init = 0;
queue<string> connect_buf[10000 + MAX_CONNE];
queue<string> closed_buf[10000 + MAX_CONNE];
deque <int> pack_size[10000+MAX_CONNE];
map <int, int> last_ack_rcv;
map <int,int> last_seq_rcv;
map <int,int> last_ack_sen;
map <int,int> last_seq_sen;
map <int,int> ack_to_send;
map <int,int> seq_sent[10000+MAX_CONNE];
map <int,int> seq_rcv[10000+MAX_CONNE];
priority_queue <Packet> read_buf[10000+MAX_CONNE];
map <int,int> last_pac_read;

int __wrap_socket(int domain, int type, int protocol)
{
    g_lock.lock();
    if (domain != AF_INET)
    {
        fprintf(stderr, "socket:wrong domain!\n");
        g_lock.unlock();
        return -1;
    }
    if (type != SOCK_STREAM)
    {
        fprintf(stderr, "socket:type error!\n");
        g_lock.unlock();
        return -1;
    }
    if (protocol != 0)
    {
        fprintf(stderr, "socket:wrong protocol!\n");
        g_lock.unlock();
        return -1;
    }
    if(socket_id>=10000+MAX_CONNE)
    {
        fprintf(stderr,"wrap socket:too many sockets opened!\n");
        g_lock.unlock();
        return -1;
    }
    if (!n_init)
    {
        n_init = 1;
        start_host();
    }
    sock_state[socket_id] = CLOSED;
    int ret = socket_id;
    socket_id++;
    g_lock.unlock();
    return ret;
}

int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len)
{
    ushort port = (address->sa_data[0] << 8) + address->sa_data[1];
    uint src_ip = dev_ip;
    g_lock.lock();
    if (socket >= socket_id)
    {
        fprintf(stderr, "bind:no such socket!\n");
        g_lock.unlock();
        return -1;
    }
    if (sock_bind.find(socket) != sock_bind.end())
    {
        fprintf(stderr, "bind:socket busy!\n");
        g_lock.unlock();
        return -1;
    }
    sock_bind[socket] = make_pair(src_ip, port);
    sock_rbind[make_pair(src_ip, port)] = socket;
    g_lock.unlock();
    return 0;
}

int __wrap_listen(int socket, int backlog)
{
    g_lock.lock();
    if (sock_bind.find(socket) == sock_bind.end())
    {
        fprintf(stderr, "listen:socket not bind!\n");
        g_lock.unlock();
        return -1;
    }
    sock_state[socket] = LISTEN;
    g_lock.unlock();
    return 1;
}

int __wrap_connect(int socket, const struct sockaddr *address,
                   socklen_t address_len)
{
    sleep(5);
    g_lock.lock();
    pair<uint, ushort> address_item = getpairbyadd(address);
    if (sock_state.find(socket) == sock_state.end() || sock_state[socket] != CLOSED)
    {
        fprintf(stderr, "wrap connect:socket invalid!\n");
        g_lock.unlock();
        return -1;
    }
    else if (sock_rconn.find(address_item) != sock_rconn.end())
    {
        fprintf(stderr, "wrap_connect:too many connections!\n");
        g_lock.unlock();
        return -1;
    }
    ushort default_port = rand() % 0xffff;
    pair<uint, ushort> add_item = make_pair(dev_ip, default_port);
    sock_pos[socket] = add_item;
    sock_rpos[add_item] = socket;
    sock_state[socket] = SYNSENT;
    sock_conn[socket] = address_item;
    sock_rconn[address_item] = socket;
    uint8_t *buf = new uint8_t[20];
    ushort dst_port = (address->sa_data[0] << 8) | address->sa_data[1];
    fillheader((char *)buf, default_port, dst_port, 0, 0, 1, 0, 0);
    while (1)
    {
        struct in_addr src, dst;
        src.s_addr = dev_ip, dst.s_addr = getipbystr(address->sa_data + 2);
        pair<string, uint> tb_item = make_pair("", 0);
        if (dst_info.find(dst.s_addr) != dst_info.end())
        {
            tb_item = make_pair(dst_info[dst.s_addr], dst.s_addr);
            ////printf("connection request sent!\n");
            int fl = sendIPPacket(src, dst, 4, buf, 20, router[tb_item], 0);
            if (fl == -1)
            {
                fprintf(stderr, "wrap connect:ip packet send failed!\n");
            }
        }else
        {
            fprintf(stderr,"wrap connect:dst not connected:%x",dst.s_addr);
            g_lock.unlock();
            return -1;
        }
        int cnt=0;
        while (sock_state[socket] != ESTABLISHED)
        {
            g_lock.unlock();
            usleep(50000);
            g_lock.lock();
            cnt++;
            if(cnt>1000)
            {
                sock_state[socket] = CLOSED;
                sock_conn.erase(socket);
                sock_rconn.erase(address_item);
                fprintf(stderr, "wrap connect:connect failed:timed out!\n");
                g_lock.unlock();
                return -1;
            }
        }
        last_seq_sen[socket]=2;
        last_ack_sen[socket]=1;
        last_seq_rcv[socket]=2;
        last_ack_rcv[socket]=1;
        last_pac_read[socket]=2;
        ////printf("connection successful!\n");
        delete[] buf;
        g_lock.unlock();
        return 0;
    }
}

int __wrap_accept(int socket, struct sockaddr *address,
                  socklen_t *address_len)
{
    g_lock.lock();
    while (1)
    {
        while (connect_buf[socket].empty())
        {
            g_lock.unlock();
            usleep(10000);
            g_lock.lock();
        }
        string buf = connect_buf[socket].front();
        connect_buf[socket].pop();
        uint fr_ip = getipbystr(buf.c_str());
        ushort fr_port = (((uint)buf[4]&0xff) << 8) | (uint8_t)buf[5];
        pair<uint, ushort> cq = make_pair(fr_ip, fr_port);

        if (buf[14 + 4] == (1 << 1))
        { // SYN
            if (sock_rconn.find(cq) == sock_rconn.end())
            {
                // not connected,ACK+SYN
                struct in_addr src, dst;
                src.s_addr = dev_ip, dst.s_addr = fr_ip;
                uint8_t *nbuf = new uint8_t[20];
                ushort my_port = sock_bind[socket].second;
                fillheader((char *)nbuf, my_port, fr_port, 0, 1, 1, 1, 0);
                ////printf("connection request aceepted!\n");
                pair<string, uint> tb_item = check_connected(fr_ip);
                if (tb_item.second != -1)
                {
                    ////printf("sending SEQ+ACK!%x %x\n", fr_ip, dev_ip);
                    sendIPPacket(src, dst, 4, nbuf, 20, router[tb_item], 0);
                    int fd = socket_id++;
                    sock_state[fd] = SYNRCVD;
                    sock_rconn[cq] = fd;
                    sock_conn[fd] = cq;
                    sock_pos[fd] = sock_bind[socket];
                    sock_rpos[sock_bind[socket]] = fd;
                }
            }
        }
        int cnt=0;
        while(sock_rconn.find(cq) == sock_rconn.end() || sock_state[sock_rconn[cq]] != ESTABLISHED)
        {
            g_lock.unlock();
            usleep(50000);
            g_lock.lock();
            cnt++;
            if(cnt>50000)
            {
                g_lock.unlock();
                return -1;
            }
        }
        ////printf("connection established!\n");
        int t = sock_rconn[cq];
        last_seq_sen[t]=2;
        last_ack_sen[t]=1;
        last_seq_rcv[t]=2;
        last_ack_rcv[t]=1;
        last_pac_read[t]=2;
        g_lock.unlock();
        return t;
    }
}

int __wrap_close(int fildes)
{
    sleep(5);
    g_lock.lock();
    if (fildes < 10000)
    {
        g_lock.unlock();
        return __real_close(fildes);
    }
    char *buf = new char[20];
    uint my_ip = sock_pos[fildes].first;
    ushort my_port = sock_pos[fildes].second;
    if(sock_conn.find(fildes)==sock_conn.end())
    {
        fprintf(stderr,"wrap close:connection not established!\n");
        delete []buf;
        g_lock.unlock();
        return -1;
    }
    uint dst_ip = sock_conn[fildes].first;
    ushort dst_port = sock_conn[fildes].second;
    fillheader(buf, my_port, dst_port, CLOSESEQ, 0, 0, 0, 1);
    struct in_addr src, dst;
    src.s_addr = my_ip, dst.s_addr = dst_ip;
    pair<string, uint> tb_item = check_connected(dst_ip);
    if (tb_item.second == -1)
    {
        fprintf(stderr, "wrap close:not connected!\n");
        delete[] buf;
        g_lock.unlock();
        return -1;
    }
    if (sock_state[fildes] == ESTABLISHED)
    {
        //主动关闭
        ////printf("active close!\n");
        sock_state[fildes] = FINWAIT1;
        sendIPPacket(src, dst, 4, buf, 20, router[tb_item], 0);
    }
    else if (sock_state[fildes] == CLOSEWAIT)
    {
        //被动关闭
        ////printf("passive close!\n");
        sock_state[fildes] = LASTACK;
        sendIPPacket(src, dst, 4, buf, 20, router[tb_item], 0);
    }
    int cnt=0;
    while(sock_state[fildes]!=CLOSED&&sock_state[fildes]!=TIMEWAIT)
    {
        g_lock.unlock();
        usleep(500000);
        g_lock.lock();
        cnt++;
        if(cnt>100)
        {
            fprintf(stderr,"wrap close:close failed!\n");
            g_lock.unlock();
            return -1;
        }
    }
    if (sock_state[fildes] == CLOSED)
    {
        ////printf("closed successful!\n");
        g_lock.unlock();
        return 0;
    }
    else if (sock_state[fildes] == TIMEWAIT)
    {
        g_lock.unlock();
        sleep(5);
        g_lock.lock();
        ////printf("closed successful!\n");
        sock_state[fildes] = CLOSED;
        pair<uint, ushort> item = sock_pos[fildes];
        sock_rpos.erase(item), sock_pos.erase(fildes);
        item = sock_conn[fildes];
        sock_conn.erase(fildes), sock_rconn.erase(item);
        g_lock.unlock();
        return 0;
    }
}

ssize_t __wrap_read ( int fildes , void * buf , size_t nbyte )
{
    if(fildes<=10000)
    {
        return __real_read(fildes,buf,nbyte);
    }
    g_lock.lock();
    int cnt=0;
    while(read_buf[fildes].empty()||read_buf[fildes].top().seq!=last_pac_read[fildes])
    {
        g_lock.unlock();
        usleep(50000);
        g_lock.lock();
        /*if(cnt%100==0)
        {
            if(read_buf[fildes].empty())
            {
                //printf("damn!\n");
            }else
                //printf("%d %d\n",read_buf[fildes].top().seq,last_pac_read[fildes]);
        }*/
        cnt++;
        if(cnt>100)
        {
            g_lock.unlock();
            return 0;
        }
    }
    if(sock_state.find(fildes)==sock_state.end()||sock_state[fildes]!=ESTABLISHED)
    {
        fprintf(stderr,"wrap read:invalid socket!\n");
        g_lock.unlock();
        return -1;
    }
    int bs=0;
    while(bs<nbyte&&!read_buf[fildes].empty())
    {
        /*if(read_buf[fildes].size()==pack_size[fildes].front()&&ack_to_send[fildes]!=-1)
        {
            char *ret=new char[20];
            ushort src_port=sock_conn[fildes].second,dst_port=sock_pos[fildes].second;
            uint src_ip=sock_conn[fildes].first;
            fillheader(ret,dst_port,src_port,ack_to_send[fildes]-1,ack_to_send[fildes],0,1,0);
            pair<string,int>tb_item=check_connected(src_ip);
            if(tb_item.second==-1)
            {
                delete []ret;
                fprintf(stderr,"wrap write:ack not sent because not connected!\n");
                return -1;
            }
            struct in_addr src,dst;
            src.s_addr=dev_ip,dst.s_addr=src_ip;
            ////printf("ack=%d sent!\n",ack_to_send[fildes]);
            sendIPPacket(src,dst,4,ret,20,router[tb_item],0);
            ack_to_send[fildes]=-1;
        }*/
        Packet temp=read_buf[fildes].top();
        read_buf[fildes].pop();
        while(bs<nbyte&&temp.read_pos<temp.siz)
            ((char*)buf)[bs++]=temp.buf[temp.read_pos++];
        if(temp.read_pos!=temp.siz)
        {
            read_buf[fildes].push(temp);
        }else
        {
            //printf("seq=%d read!\n",temp.seq);
            last_pac_read[fildes]=temp.seq+temp.siz;
        }
        /*int cnt=0;
        if(bs<nbyte&&!read_buf[fildes].empty())
        {
            while(read_buf[fildes].empty()||read_buf[fildes].top().seq!=last_pac_read[fildes])
            {
                g_lock.unlock();
                usleep(50000);
                g_lock.lock();
                cnt++;
                if(cnt>100)
                {
                    g_lock.unlock();
                    return bs;
                }
            }
        }*/
        /*int t=pack_size[fildes].front();
        pack_size[fildes].pop_front();
        t--;
        if(t)
            pack_size[fildes].push_front(t);*/

    }
    g_lock.unlock();
    return bs;
}

ssize_t __wrap_write ( int fildes , const void * buf , size_t nbyte )
{
    if(fildes<=10000)
    {
        fprintf(stderr,"wrap_write:fall back!\n");
        return __real_write(fildes,buf,nbyte);
    }
    g_lock.lock();
    if(sock_state.find(fildes)==sock_state.end()||sock_state[fildes]!=ESTABLISHED)
    {
        fprintf(stderr,"wrap write:socket connection not established!\n");
        g_lock.unlock();
        return -1;
    }
    char *nbuf=new char[nbyte];
    memcpy(nbuf,buf,nbyte);
    thread t=thread(Send,fildes,nbuf,nbyte);
    t.detach();
    g_lock.unlock();
    return nbyte;
}

void Send(int fildes, const char *buf, size_t nbyte)    
{
    g_lock.lock();
    uint size_sent=0;
    uint dst_ip=sock_conn[fildes].first;
    ushort dst_port=sock_conn[fildes].second;
    uint src_ip=dev_ip;
    ushort src_port=sock_pos[fildes].second;
    struct in_addr src,dst;
    src.s_addr=src_ip,dst.s_addr=dst_ip;
    int bs=nbyte;
    map <int,int> seq_size;
    int temp=last_seq_sen[fildes],las=last_seq_sen[fildes];
    last_seq_sen[fildes]=las+nbyte;
    while(bs>0)
    {
        char *pack=new char[MAX_LENGTH*2];
        fillheader(pack,src_port,dst_port,temp,0,0,0,0);
        seq_sent[fildes][temp]=0;
        memcpy(pack+20,buf+temp-las,min(900,bs));
        pair<string,uint>tb_item=check_connected(dst_ip);
        if(tb_item.second==-1)
        {
            fprintf(stderr,"wrap write:dst can't reach while sending\n");
            delete []pack;
            g_lock.unlock();
            return;
        }
        //printf("wrap write:sending seq=%d\n",temp);
        seq_size[temp]=min(900,bs);
        sendIPPacket(src,dst,4,pack,20+min(900,bs),router[tb_item],0);
        int cnt=0;
        while(seq_sent[fildes][temp]!=1)
        {
            g_lock.unlock();
            usleep(50000);
            g_lock.lock();
            cnt++;
            if(cnt%100==0)
            {
                sendIPPacket(src,dst,4,pack,20+min(900,bs),router[tb_item],0);
            }
        }
        temp+=min(900,bs);
        bs-=900;
        delete []pack;
    }
    
    /*int cnt=0;
    vector<int> v;
    while(1)
    {    
        g_lock.unlock();
        usleep(500000);
        g_lock.lock();
        cnt++;
        v.clear();
        ////printf("%d\n",cnt);
        for(auto it=seq_sent[fildes].begin();it!=seq_sent[fildes].end();it++)
        {
            if(it->first<las||it->first>temp)
                continue;
            if(it->second!=1)
            {
                v.push_back(it->first);
            }
        }
        if(v.size()==0)
            break;
        else
        {
            if(cnt%10==0)
            {
                pair<string,uint>tb_item=check_connected(dst_ip);
                if(tb_item.second==-1)
                {
                    fprintf(stderr,"wrap write:dst can't reach while sending\n");
                    g_lock.unlock();
                    return;
                } 
                //printf("resending:\n");
                for(auto it=v.begin();it!=v.end();it++)
                {
                    char *pack=new char[MAX_LENGTH*2];
                    fillheader(pack,src_port,dst_port,*it,0,0,0,0);
                    memcpy(pack+20,buf+(*it)-las,seq_size[*it]);
                    sendIPPacket(src,dst,4,pack,20+min(900,bs),router[tb_item],0);
                    g_lock.unlock();
                    usleep(100000);
                    g_lock.lock();
                }
            }
        }
    }*/
    //printf("seq=%d sent success!\n",temp);
    g_lock.unlock();
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res)
{
    if (!service)
    {
        fprintf(stderr, "getaddrinfo:invalid port number!\n");
        return -1;
    }
    if (!hints)
    {
        fprintf(stderr, "getaddrinfo:invalid hints!\n");
        return -1;
    }
    if (!node)
    {
        fprintf(stderr,"getaddrinfo:invalid node!\n");
        return -1;
    }
    (*res)->ai_family=AF_INET;
    (*res)->ai_socktype=SOCK_STREAM;
    (*res)->ai_protocol=0;
    (*res)->ai_canonname=NULL;
    (*res)->ai_addrlen=20;
    (*res)->ai_addr->sa_family=AF_INET;
    memcpy((*res)->ai_addr->sa_data,service,2);
    memcpy((*res)->ai_addr->sa_data+2,node,4);
    (*res)->ai_next=NULL;
    return 0;
}

void fillheader(char *buf, uint src_port, uint dst_port, uint seq, uint ack, bool SYN, bool ACK, bool FIN)
{
    buf[0] = (src_port >> 8) & 0xff;
    buf[1] = src_port & 0xff;
    buf[2] = (dst_port >> 8) & 0xff;
    buf[3] = dst_port & 0xff;
    for (int i = 0; i < 4; i++)
    {
        buf[i + 4] = (seq >> (32 - (i + 1) * 8)) & 0xff;
        buf[i + 8] = (ack >> (32 - (i + 1) * 8)) & 0xff;
    }
    buf[12] = 0x5;
    buf[13] = 0;
    buf[14] = 0;
    if (SYN)
        buf[14] |= (1 << 1); // SYN=1
    if (ACK)
        buf[14] |= (1 << 4);
    if (FIN)
        buf[14] |= 1;
    buf[15] = window_size;
    buf[16] = buf[17] = 0; // check sum
    buf[18] = buf[19] = 0;
}

void manage_packet(const uint8_t *s, int len, uint src_ip)
{
    ushort src_port = (s[0] << 8) + s[1];
    ushort dst_port = (s[2] << 8) + s[3];
    string nbuf = getstrbyip(src_ip);
    for (int i = 0; i < len; i++)
        nbuf += (char)s[i];
    uint seq = getipbystr((const char *)s + 4), ack = getipbystr((const char *)s + 8);
    if (s[14] == (1 << 1))
    { // SYN
        if (sock_rbind.find(make_pair(dev_ip, dst_port)) == sock_rbind.end())
        {
            return;
        }
        int socket = sock_rbind[make_pair(dev_ip, dst_port)];
        connect_buf[socket].push(nbuf);
    }
    else if (s[14] == ((1 << 1) | (1 << 4)))
    { // SYN+ACK
        if (sock_rpos.find(make_pair(dev_ip, dst_port)) == sock_rpos.end())
        {
            ////printf("???\n");
            return;
        }
        int socket = sock_rpos[make_pair(dev_ip, dst_port)];
        if(sock_state[socket]==SYNSENT)
        {
            char *buf=new char[20];
            fillheader(buf,dst_port,src_port,1,1,0,1,0);
            sock_state[socket]=ESTABLISHED;
            struct in_addr src,dst;
            src.s_addr=dev_ip,dst.s_addr=src_ip;
            pair<string,uint> tb_item=check_connected(src_ip);
            if(tb_item.second!=-1)
                sendIPPacket(src,dst,4,buf,20,router[tb_item],0);
        }
            
    }
    else if (s[14] == 1)
    { // FIN
        if (sock_rconn.find(make_pair(src_ip, src_port)) == sock_rconn.end())
        {
            return;
        }
        int socket = sock_rconn[make_pair(src_ip, src_port)];
        char *buf = new char[20];
        if (sock_state[socket] == ESTABLISHED)
        {
            ////printf("close request received!\n");
            sock_state[socket] = CLOSEWAIT;
            fillheader(buf, dst_port, src_port, CLOSESEQ, CLOSESEQ + 1, 0, 1, 0);
            struct in_addr src, dst;
            src.s_addr = dev_ip, dst.s_addr = src_ip;
            pair<string, uint> tb_item = check_connected(src_ip);
            if (tb_item.second != -1)
                sendIPPacket(src, dst, 4, buf, 20, router[tb_item], 0);
        }
        else if (sock_state[socket] == FINWAIT2)
        {
            ////printf("other side close request received!\n");
            sock_state[socket] = TIMEWAIT;
            fillheader(buf, dst_port, src_port, CLOSESEQ, CLOSESEQ + 1, 0, 1, 0);
            struct in_addr src, dst;
            src.s_addr = dev_ip, dst.s_addr = src_ip;
            pair<string, uint> tb_item = check_connected(src_ip);
            if (tb_item.second != -1)
                sendIPPacket(src, dst, 4, buf, 20, router[tb_item], 0);
        }
        else if (sock_state[socket] == FINWAIT1)
        {
            ////printf("double closing!\n");
            sock_state[socket] = CLOSING;
            fillheader(buf, dst_port, src_port, CLOSESEQ, CLOSESEQ + 1, 0, 1, 0);
            struct in_addr src, dst;
            src.s_addr = dev_ip, dst.s_addr = src_ip;
            pair<string, uint> tb_item = check_connected(src_ip);
            if (tb_item.second != -1)
                sendIPPacket(src, dst, 4, buf, 20, router[tb_item], 0);
        }
    }
    else if (s[14] == (1 << 4))
    { // ACK
        int socket = 0;
        if (sock_rconn.find(make_pair(src_ip, src_port)) != sock_rconn.end())
        {
            socket = sock_rconn[make_pair(src_ip, src_port)];
        }else if (sock_rpos.find(make_pair(dev_ip, dst_port)) != sock_rpos.end())
        {
            socket = sock_rpos[make_pair(dev_ip, dst_port)];
        }else
        {
            return;
        }
        if(ack==1)
        {
            if(sock_state[socket]==SYNRCVD)
                sock_state[socket]=ESTABLISHED;
            return;
        }
        //printf("ack=%u received!\n",ack);
        char *buf = new char[20];
        if (seq == 0 && ack == 1)
        {
            fillheader(buf, dst_port, src_port, 1, 1, 0, 1, 0);
            pair<string, uint> tb_item = check_connected(src_ip);
            struct in_addr src, dst;
            src.s_addr = dev_ip, dst.s_addr = src_ip;
            if (tb_item.second != -1)
                sendIPPacket(src, dst, 4, buf, 20, router[tb_item], 0);
        }
        else if (seq == CLOSESEQ && ack == CLOSESEQ + 1)
        {
            if (sock_state[socket] == FINWAIT1)
            {
                ////printf("close ack received\n");
                sock_state[socket] = FINWAIT2;
            }
            else if (sock_state[socket] == CLOSING)
            {
                ////printf("start timewaiting!\n");
                sock_state[socket] = TIMEWAIT;
            }
            else if (sock_state[socket] == LASTACK)
            {
                ////printf("last ack received!\n");
                sock_state[socket] = CLOSED;
                pair<uint, ushort> item = sock_pos[socket];
                sock_rpos.erase(item), sock_pos.erase(socket);
                item = sock_conn[socket];
                sock_conn.erase(socket), sock_rconn.erase(item);
            }
        }else
        {
            if(seq_sent[socket].find(seq)==seq_sent[socket].end())
            {
                return;
            }
            seq_sent[socket][seq]=1;
        }
    }else
    {   //normal packet
        int socket = 0;
        if (sock_rconn.find(make_pair(src_ip, src_port)) != sock_rconn.end())
        {
            socket = sock_rconn[make_pair(src_ip, src_port)];
        }else if (sock_rpos.find(make_pair(dev_ip, dst_port)) != sock_rpos.end())
        {
            socket = sock_rpos[make_pair(dev_ip, dst_port)];
        }else
        {
            return;
        }
        if(seq_rcv[socket].find(seq)!=seq_rcv[socket].end())
        {
            return;
        }else
        {
            ////printf("packet received!\n");
            seq_rcv[socket][seq]=1;
        }
        //printf("seq=%d in packet!\n",seq);
        read_buf[socket].push(Packet(seq,(char*)s+20,len-20));
        char *buf=new char[20];
        fillheader(buf,dst_port,src_port,seq,seq+1,0,1,0);
        pair<string,uint> tb_item=check_connected(src_ip);
        if(tb_item.second==-1)
        {
            fprintf(stderr,"ack for seq=%d not sent because not connected!\n",seq);
        }
        struct in_addr src,dst;
        src.s_addr=dev_ip,dst.s_addr=src_ip;
        //printf("ack for seq=%d sent\n",seq);
        sendIPPacket(src,dst,4,buf,20,router[tb_item],0);
       // pack_size[socket].push_back(len-20);
    }
}

pair<string, uint> check_connected(uint dst_ip)
{
    if (dst_info.find(dst_ip) == dst_info.end())
    {
        return make_pair("", -1);
    }
    return make_pair(dst_info[dst_ip], dst_ip);
}

pair<uint, ushort> getpairbyadd(const struct sockaddr *address)
{
    string tempip = "";
    for (int i = 0; i < 4; i++)
        tempip += address->sa_data[i + 2];
    uint dstip = getipbystr(tempip.c_str());
    ushort dstport = ((uint)(address->sa_data[0]) << 8) + address->sa_data[1];
    pair<uint, ushort> address_item = make_pair(dstip, dstport);
    return address_item;
}