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


    printf("start thread\n");
    for (int k=0; k<20; k++)
    {
        if (pcap_sendpacket(my_multiple_arg->handle, my_multiple_arg->packet, sizeof(radiotap_header) + sizeof(dot11_frame) + 2) != 0)
        {
            printf("error\n");
        }
        usleep(5000);
        printf("%d\n", k);
    }
    printf("end thread\n");
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

    FILE * t_fp = fopen("./data/deauth.txt", "w");
    fclose(t_fp);


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


    set<string> deauth_list;
    set<string> white_list;
    set<string>::iterator it;
    set<string>::iterator it_temp;
    string s_temp;


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

        if(auth->fp.SEQ != 0x0001)
        {
            continue;
        }

        FILE *fp;

        char target_mac[1024] = {0};
        char buf[1024] = {0};
        int state = 1;
        Mac target = frame->addr2;

        white_list.clear();

        sprintf(target_mac, "%s", mac_to_string(frame->addr2).c_str());

        fp = fopen("./data/whitelist.txt", "r");

        if(fp == NULL)
        {
            printf("open error\n");
        }

        if (fp != NULL) {
            while (!feof(fp))
            {
                fgets(buf, 100, fp);
                buf[strlen(buf)-1] = '\0';
                s_temp = buf;
                white_list.insert(s_temp);
                if(memcmp(buf, target_mac, 17) == 0)
                {
                    state = 0;
                }
            }
        }

        fclose(fp);

        for(it = white_list.begin(); it != white_list.end(); it++)
        {
            it_temp=deauth_list.find(*it);
            if(it_temp != deauth_list.end())
            {
                printf("find : erase deauth list\n");
                deauth_list.erase(it_temp);
            }
        }

        fp = fopen("./data/deauth.txt", "w");

        if(fp == NULL)
        {
            printf("open error\n");
        }

        for(it = deauth_list.begin(); it != deauth_list.end(); it++)
        {
            fputs(it->c_str(), fp);
            fputs("\n", fp);
        }

        fclose(fp);


        if(state == 0)
            continue;

        s_temp = mac_to_string(frame->addr2);
        deauth_list.insert(s_temp);


        printf("gogo deauth %s\n", s_temp.c_str());

        uint8_t * deauth_frame = set_deauth(target, my_ap);

        pthread_t thread;

        struct multi_arg * multiple_arg;
        multiple_arg = (struct multi_arg *)malloc(sizeof(struct multi_arg));
        multiple_arg->handle = handle;
        multiple_arg->packet = deauth_frame;

        pthread_create(&thread, NULL, t_func, (void *) multiple_arg);

        pthread_detach(thread);



    }



    pcap_close(handle);
    return 0;
}

