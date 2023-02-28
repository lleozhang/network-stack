/* *
* @file socket . h
* @brief POSIX - compatible socket library supporting TCP protocol on
IPv4 .
*/
#ifndef __SOCKET_H_
#define __SOCKET_H_
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
#include <unistd.h>
#include <algorithm>
#include <queue>
#include <deque>
#include <map>
#pragma once
#define MAX_CONNE 1024
#define CLOSED 0
#define LISTEN 1
#define SYNRCVD 2
#define SYNSENT 3
#define ESTABLISHED 4
#define FINWAIT1 5
#define FINWAIT2 6
#define TIMEWAIT 7
#define CLOSING 8
#define CLOSEWAIT 9
#define LASTACK 10
#define CLOSESEQ 0x80000000u
typedef unsigned short ushort;
using namespace std;

class Packet
{
    public:
        int seq;
        int siz;
        char *buf;
        int read_pos;
        friend bool operator < (Packet a,Packet b)
        {
            return a.seq>b.seq;
        }
        Packet(int Seq,char *Buf,int len)
        {
            seq=Seq;
            read_pos=0;
            siz=len;
            buf=new char[len];
            for(int i=0;i<len;i++)buf[i]=Buf[i];
        }
        /*~Packet()
        {
            delete []buf;
        }*/
};

extern queue <string> connect_buf[10000+MAX_CONNE];
extern queue <string> closed_buf[10000+MAX_CONNE];
extern map <int, pair<uint,ushort> > sock_bind;
extern map <pair<uint,ushort>, int> sock_rbind;
extern map <int, pair<uint,ushort> > sock_conn;
extern map <pair<uint,ushort>, int> sock_rconn;
extern map <pair<uint,ushort>, int> sock_rpos;
extern map <int, pair<uint,ushort> > sock_pos;
extern map <int, int> last_ack_rcv;
extern map <int,int> last_seq_rcv;
extern map <int,int> last_ack_sen;
extern map <int,int> last_seq_sen;
extern map <int,int> ack_to_send;
extern deque <int> pack_size[10000+MAX_CONNE];
extern map <int,int> seq_sent[10000+MAX_CONNE];
extern map <int,int> seq_rcv[10000+MAX_CONNE];
extern priority_queue <Packet> read_buf[10000+MAX_CONNE];
extern map <int,int> last_pac_read;




extern "C"
{

int __wrap_socket ( int domain , int type , int protocol ) ;
/* *
* @see [ POSIX .1 -2017: bind ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / bind . html )
*/
int __wrap_bind ( int socket , const struct sockaddr * address ,
socklen_t address_len ) ;
/* *
* @see [ POSIX .1 -2017: listen ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / listen . html )
*/
int __wrap_listen ( int socket , int backlog ) ;
/* *
9* @see [ POSIX .1 -2017: connect ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / connect . html )
*/
int __wrap_connect ( int socket , const struct sockaddr * address ,
socklen_t address_len ) ;
/* *
* @see [ POSIX .1 -2017: accept ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / accept . html )
*/
int __wrap_accept ( int socket , struct sockaddr * address ,
socklen_t * address_len ) ;
/* *
* @see [ POSIX .1 -2017: read ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / read . html )
*/
ssize_t __wrap_read ( int fildes , void * buf , size_t nbyte ) ;
/* *
* @see [ POSIX .1 -2017: write ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / write . html )
*/
ssize_t __wrap_write ( int fildes , const void * buf , size_t nbyte ) ;
/* *
* @see [ POSIX .1 -2017: close ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / close . html )
*/
int __wrap_close ( int fildes ) ;
/* *
* @see [ POSIX .1 -2017: getaddrinfo ]( http :// pubs . opengroup . org /
onlinepubs /
* 9699919799/ functions / getaddrinfo . html )
*/
int _wrap_getaddrinfo ( const char * node , const char * service ,
const struct addrinfo * hints ,
struct addrinfo ** res ) ;

ssize_t __real_read ( int fildes , void * buf , size_t nbyte ) ;
/* *
* @see [ POSIX .1 -2017: write ]( http :// pubs . opengroup . org / onlinepubs /
* 9699919799/ functions / write . html )
*/
ssize_t __real_write ( int fildes , const void * buf , size_t nbyte ) ;

int __real_close(int fildes);

}
void fillheader(char *buf,uint src_port,uint dst_port,uint seq,uint ack,bool SYN,bool ACK,bool FIN);

pair<uint,ushort> getpairbyadd(const struct sockaddr * address);

void manage_packet(const uint8_t* s,int len,uint src_ip);

pair<string,uint> check_connected(uint dst_ip);

void Send ( int fildes , const char * buf , size_t nbyte ) ;

#endif