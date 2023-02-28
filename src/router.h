#include "ip.h"
#include "packetio.h"
#include "device.h"
#include <thread>
using namespace std;
#define MAXTHREAD 20
extern thread t[MAXTHREAD];
extern string dev_name;
extern uint dev_ip;
int start_router();
int start_host();
int frame_callback(const void* buf,int len,int id);
int ip_callback(const void *buf,int len,int id);
void setdevinfo();
void manage_neighbors();
int manage_router(const uint8_t *s,uint fr_ip,uint ed_ip,int len,int id);
int transmit_packet(const uint8_t *s,uint fr_ip,uint ed_ip,int len,int id);
void end_router();
void manage_packet(const uint8_t* s,int len);