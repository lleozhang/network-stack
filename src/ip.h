/* *
* @file ip.h
* @brief Library supporting sending / receiving IP packets encapsulated
in an Ethernet II frame .
*/
#ifndef __IP_H_
#define __IP_H_
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <map>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <utility>
#include "packetio.h"
#include "device.h"
#include <queue>
using namespace std;
#pragma once
extern map <pair<string,uint>,int> router;//map dst_add to device number
extern map <pair<string,uint>,string> routing_tb;//map dst_add to mac_add to be sent
extern map <pair<string,uint>,uint> routing_tab;
extern map <pair<string,uint>,uint> dis;
extern map <pair<uint,uint>,int> mask_tb;
extern map <pair<uint,uint>,string> mask_mac;
extern map <string,uint> name2ip;//map device name to its ip
extern map <uint,int> pack_rec;
extern map<uint,string> dst_info;
extern queue<pair<pair<string,int>,int> >packet;
/* *
* @brief Send an IP packet to specified host .
*
* @param src Source IP address .
* @param dest Destination IP address .
* @param proto Value of ‘ protocol ‘ field in IP header .
* @param buf pointer to IP payload
* @param len Length of IP payload
* @return 0 on success , -1 on error .
*/
typedef unsigned int uint;
extern mutex g_lock;

int sendIPPacket (const struct in_addr src , const struct in_addr dest ,
int proto , const void * buf , int len, const int dev_id ,const uint identi) ;
/* *
* @brief Process an IP packet upon receiving it .
*
* @param buf Pointer to the packet .
* @param len Length of the packet .
* @return 0 on success , -1 on error .
* @see addDevice
*/
typedef int (*IPPacketReceiveCallback) ( const void * buf , int len ,int id) ;

unsigned getipbystr(const char* s);

string getstrbyip(unsigned ip);

int receiveippacket(const int id);

/* *
* @brief Register a callback function to be called each time an IP
packet was received .
*
* @param callback The callback function .
* @return 0 on success , -1 on error .
* @see I P P a c k e t R e c e i v e C a l l b a c k
*/
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback ) ;
/* *
* @brief Manully add an item to routing table . Useful when talking
with real Linux machines .
*
* @param dest The destination IP prefix .
* @param mask The subnet mask of the destination IP prefix .
* @param nextHopMAC MAC address of the next hop .
* @param device Name of device to send packets on .
* @return 0 on success , -1 on error
*/
int setRoutingTable ( const struct in_addr dest ,
const struct in_addr mask ,
const void * nextHopMAC , const char * device ) ;

int find_maskip(uint ip);

#endif