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
    string dst_ip=getstrbyip(dstip);
    for(int i=0;i<4;i++)address.sa_data[i+2]=dst_ip[i];
    __wrap_connect(sl,&address,sizeof(address));
    printf("connected!\n");
    char *buf=new char[20];
    __wrap_read(sl,buf,11);
    printf("%s\n",buf);
    __wrap_close(sl);
    //end_router();
    return 0;
}