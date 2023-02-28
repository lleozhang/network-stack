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
#include "router.h"
#include "socket.h"
#include <pcap/pcap.h>
using namespace std;
static const unsigned srcip=0x0a640101,dstip=0x0a640302;

int main()
{
    srand(time(NULL));
    int sl=__wrap_socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr address;
    address.sa_data[0]=0,address.sa_data[1]=20;
    string dst_ip=getstrbyip(srcip);
    for(int i=0;i<4;i++)address.sa_data[i+2]=dst_ip[i];
    __wrap_bind(sl,&address,sizeof(address));
    __wrap_listen(sl,1024);
    socklen_t len;
    int fd=__wrap_accept(sl,&address,&len);
    char *buf="test packet";
    printf("sending:\n");
    __wrap_write(fd,buf,11);
    sleep(20);
    printf("closing:\n");
    __wrap_close(fd);
    //end_router();
    return 0;
}