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
#include <pcap/pcap.h>
using namespace std;
static const unsigned srcip=0x0a640101,dstip=0x0a640302;

int main()
{
    srand(time(NULL));
    int t=start_router();
    if(!t)
    {
        fprintf(stderr,"router start failed!\n");
        exit(-1);
    }else
    {
        fprintf(stdout,"router successfully started!\n");
    }
    sleep(10);
    struct in_addr src,dst;
    src.s_addr=srcip,dst.s_addr=dstip;
    char *buf="test packet";
    g_lock.lock();
    int fl=sendIPPacket(src,dst,4,buf,strlen(buf),1,1);
    printf("packet sent!\n");
    g_lock.unlock();
    end_router();
    return 0;
}