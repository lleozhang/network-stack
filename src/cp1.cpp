#include "device.h"
#include <pcap/pcap.h>
int main()
{
    char errbuf[MAX_ERRBUF];
    pcap_if_t *it;

    int tmp=pcap_findalldevs(&it,errbuf);
    if(tmp==-1)
    {
        fprintf(stderr,"something went wrong!\n");
        return 0;
    }
    pcap_if_t *my_it=it;
    while(it)
    {
        int fl=addDevice(it->name);
        printf("%s\n",it->name);
        if(fl==-1)
        {
            fprintf(stderr,"device added failed!\n");
            return 0;
        }
        it=it->next;
    }
    while(my_it)
    {
        int fl=findDevice(my_it->name);
        printf("%s\n",my_it->name);
        if(fl==-1)
        {
            fprintf(stderr,"device not found!\n");
            return 0;
        }
        my_it=my_it->next;
    }
    printf("Implement correct!\n");
    return 0;
}