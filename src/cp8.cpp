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
#define LOSSYLINK
using namespace std;


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
    end_router();
    return 0;
}
