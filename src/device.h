/* *
* @file device.h
* @brief Library supporting network device management .
*/
#ifndef __DEVICE_H_
#define __DEVICE_H_

#include <unordered_map>
#include <string>
#include "packetio.h"
#include "ip.h"
#pragma once
#define MAX_ERRBUF 100
#define MAX_LENGTH 1000
using namespace std;
struct MAC_add;
extern int total_device;
extern unordered_map <string, int> name2id;
extern unordered_map <int, string> id2name;
extern unordered_map <uint,int> ip2id;
extern unordered_map <int,uint> id2ip;
extern map <MAC_add,int> mac2id;
extern map <int,MAC_add> id2mac;
typedef unsigned long long ull;

/* *
* Add a device to the library for sending / receiving packets .
*
* @param device Name of network device to send / receive packet on .
* @return A non - negative _device - ID_ on success , -1 on error .
*/
MAC_add getMACadd(const char* device);

uint getipadd(const char* device);

int getdevicenumber();

int addDevice(const char * device) ;
/* *
* Find a device added by ‘ addDevice ‘.
*
* @param device Name of the network device .
* @return A non - negative _device - ID_ on success , -1 if no such device
* was found .
*/
int findDevice (const char * device) ;

string findDevicebyid(int id);
/* *
* Find a device added by ‘ addDevice ‘.
*
* @param id id of the network device returned by addDevice.
* @return A string , name of the device, "" if none was found .
*/
int addalldevs();


#endif