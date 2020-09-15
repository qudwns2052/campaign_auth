#include "include.h"

static map<Mac, ap_info> map_ap;
static map<Mac, station_info> map_station;


int main(int argc, char* argv[])
{

    char errbuf[PCAP_ERRBUF_SIZE];

    char* dev = argv[1];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);


    if (handle == NULL)
    {
        printf("fail open_offline...%s\n",errbuf);
        return -1;
    }

    int i=0;
    int j=1;
    int ap_num=0;
    int ap_index=1;

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

        if((frame->fc.type == dot11_fc::type::CONTROL))
        {
            i++;
            continue;
        }

        // AP
        if((frame->fc.subtype == dot11_fc::subtype::BEACON) || (frame->fc.subtype == dot11_fc::subtype::PROBE_RES))
        {

            dot11_beacon_frame * beacon_frame = (dot11_beacon_frame *)(frame);

            Mac BSSID = frame->get_BSSID(); //key
            uint8_t antsignal = *rt_header->radiotap_present_flag(DBM_ANTSIGNAL);
            uint8_t channel = *((dot11_tagged_param *)beacon_frame->get_tag(3, dot11_tags_len))->get_data();
            //cnt
            std::string ESSID = ((dot11_tagged_param *)beacon_frame->get_tag(0, dot11_tags_len))->get_ssid();

            ap_info temp_ap_info;
            temp_ap_info.BSSID = BSSID;
            temp_ap_info.antsignal = antsignal;
            temp_ap_info.channel = channel;
            temp_ap_info.ESSID = ESSID;

            if(map_ap.find(BSSID) == map_ap.end())
            {
                temp_ap_info.cnt = 1;
                map_ap[BSSID] = temp_ap_info;
            }
            else
            {
                map_ap[BSSID].cnt++;
            }


        }

        usleep(20000);
        system("clear");
        printf("%d\n", i);
        printf("Number\tBSSID\t\t\tPWR\tBeacons\tCH\tESSID\n\n");

        j = 1;

        for(auto it = map_ap.begin() ; it != map_ap.end(); it++)
        {
            printf("%d\t", j++);
            it->second.Print();
        }


        printf("\n");
        i++;

        if(i > 100)
        {

            printf("select AP Number (Research : 0) : ");
            cin >> ap_num;
            if(ap_num != 0)
            {
                break;
            }
            i=0;
        }
    }


    Mac target;

    j = 1;
    for(auto it = map_ap.begin() ; it != map_ap.end(); it++)
    {
        if(j++ == ap_num)
        {
            target = it->first;
            break;
        }
    }



    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;


        radiotap_header * rt_header = (radiotap_header *)(packet);
        dot11_frame * frame = (dot11_frame *)(packet + rt_header->it_len);

        dot11_authentication * auth= (dot11_authentication *)(packet + rt_header->it_len);
        int dot11_tags_len = header->len - (rt_header->it_len + sizeof(dot11_authentication));

        if(frame->fc.type != dot11_fc::type::MANAGEMENT)
        {
            continue;
        }

        if (frame->fc.subtype != dot11_fc::subtype::AUTH)
        {
            continue;
        }

        if (memcmp(frame->get_BSSID(),target, 6))
            continue;

        if(auth->fp.SEQ == 0x0001)
        {
            FILE *fp;

            fp = fopen("./data/test.txt", "a");

            if(fp == NULL)
            {
                printf("open error\n");
            }
            char buf[1024];
            sprintf(buf, "%s\n", mac_to_string(frame->addr2).c_str());

            fputs(buf, fp);

            printf("OKOK\n");
            fclose(fp);
        }

//        if(auth->fp.SEQ == 0x0001)
//        {
//            printf("%s -> %s\n", mac_to_string(frame->addr2).c_str(), mac_to_string(frame->addr1).c_str());
//        }
//        else
//        {
//            printf("%s -> %s\n", mac_to_string(frame->addr2).c_str(), mac_to_string(frame->addr1).c_str());
//        }
    }



    pcap_close(handle);
    return 0;
}
