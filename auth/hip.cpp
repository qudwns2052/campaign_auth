#include "hip.h"

hip::hip()
{

}

void get_authen(pcap_t* handle, Mac addr)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;


        radiotap_header * rt_header = (radiotap_header *)(packet);
        dot11_frame * frame = (dot11_frame *)(packet + rt_header->it_len);

        dot11_beacon_frame * beacon_frame = (dot11_beacon_frame *)(packet + rt_header->it_len);
        int dot11_tags_len = header->len - (rt_header->it_len + sizeof(dot11_beacon_frame));

        if(frame->fc.type != dot11_fc::type::MANAGEMENT)
        {
            continue;
        }

        if (frame->fc.subtype != dot11_fc::subtype::AUTH)
        {
            continue;
        }

//        printf("%02X:%02X:%02X:%02X:%02X:%02X\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

        cout << addr << endl;

        Mac STATION = frame->addr1;
        Mac BSSID = frame->addr2;



    }
}
