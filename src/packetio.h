/* *
* @file packetio . h
* @brief Library supporting sending / receiving Ethernet II frames .
*/

#ifndef __PACKETIO_H_
#define __PACKETIO_H_
#include <netinet/ether.h>
#include <pcap/pcap.h>
#include "device.h"
#include "ip.h"
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <string>
#pragma once
using namespace std;
#define MAX_SIZE 100000
/* *
* @brief Encapsulate some data into an Ethernet II frame and send it .
*
* @param buf Pointer to the payload .
* @param len Length of the payload .
* @param ethtype EtherType field value of this frame .
* @param destmac MAC address of the destination .
* @param id ID of the device ( returned by ‘ addDevice ‘) to send on .
* @return 0 on success , -1 on error .
* @see addDevice
*/

typedef int (*frameReceiveCallback) (const void * , int , int ) ;
class MAC_add
{
    public:
        uint8_t mac[6];
        friend bool operator < (MAC_add x,MAC_add y)
        {
            for(int i=0;i<6;i++)
            {
                if(x.mac[i]<y.mac[i])return 1;
            }
            return 0;
        }
};


extern frameReceiveCallback call_back;

pcap_t* deviceactivate(int id);

uint getipadd(const char* add);

int sendFrame (const void * buf , int len ,int ethtype , const void * destmac , int id );

int receiveframe(int id);

/* *
* @brief Process a frame upon receiving it .
*
* @param buf Pointer to the frame .
* @param len Length of the frame .
* @param id ID of the device ( returned by ‘ addDevice ‘) receiving
*
current frame .
* @return 0 on success , -1 on error .
* @see addDevice
*/

/* *
* @brief Register a callback function to be called each time an
*
Ethernet II frame was received .
*
* @param callback the callback function .
* @return 0 on success , -1 on error .
* @see frameReceiveCallback
*/
int setFrameReceiveCallback (frameReceiveCallback callback ) ;

#endif