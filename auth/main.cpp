#include "include.h"

static map<Mac, ap_info> map_ap;
static map<Mac, station_info> map_station;


struct multi_arg
{
    pcap_t * handle;
    uint8_t * packet;

};

void * t_func(void *multiple_arg) {
    struct multi_arg *my_multiple_arg = (struct multi_arg *)multiple_arg;


    int milisec = 20; // length of time to sleep, in miliseconds
    struct timespec req = {0};
    req.tv_sec = 0;
    req.tv_nsec = milisec * 1000000L;
    for (int k=0; k<500000; k++)
    {
        if (pcap_sendpacket(my_multiple_arg->handle, my_multiple_arg->packet, sizeof(radiotap_header) + sizeof(dot11_frame) + 2) != 0)
        {
            printf("error\n");
        }
        nanosleep(&req, (struct timespec *)NULL);
    }
}



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


    int reset = remove("./data/deauth.txt");

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

        if(i > 200)
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


    Mac my_ap;

    j = 1;
    for(auto it = map_ap.begin() ; it != map_ap.end(); it++)
    {
        if(j++ == ap_num)
        {
            my_ap = it->first;
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

        if (memcmp(frame->get_BSSID(),my_ap, 6))
            continue;

        if(auth->fp.SEQ == 0x0001)
        {
            FILE *fp;

            char target_mac[1024] = {0};
            char buf[1024] = {0};
            int state = 1;
            Mac target = frame->addr2;

            sprintf(target_mac, "%s\n", mac_to_string(frame->addr2).c_str());

            fp = fopen("./data/whitelist.txt", "r");

            if(fp == NULL)
            {
                printf("open error\n");
            }

            if (fp != NULL) {
                while (!feof(fp))
                {
                    fgets(buf, 100, fp);

                    if(memcmp(buf, target_mac, 18) == 0)
                    {
                        state = 0;
                        break;
                    }
                }
            }

            fclose(fp);

            if(state == 0)
                continue;

            fp = fopen("./data/deauth.txt", "a");

            if(fp == NULL)
            {
                printf("open error\n");
            }

            fputs(target_mac, fp);

            printf("OKOK\n");
            fclose(fp);

            uint8_t * deauth_frame = set_deauth(target, my_ap);

            pthread_t thread;

            struct multi_arg * multiple_arg;
            multiple_arg = (struct multi_arg *)malloc(sizeof(struct multi_arg));
            multiple_arg->handle = handle;
            multiple_arg->packet = deauth_frame;

            pthread_create(&thread, NULL, t_func, (void *) multiple_arg);

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

