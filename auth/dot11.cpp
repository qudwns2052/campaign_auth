#include "dot11.h"

uint8_t * dot11_frame::get_BSSID(void)
{
    uint8_t status = this->fc.flags & (dot11_fc::flags::TO_DS | dot11_fc::flags::FROM_DS);
    switch(status)
    {
    case 0b10:  //DBS
        return this->addr2;
        break;
    case 0b01:  //BSD
        return this->addr1;
        break;
    case 0b00:  //DSB
        return this->addr3;
        break;
    case 0b11:  //RTDS
        printf("i don't know\n");
        return nullptr;
        break;
    default:
        return nullptr;
    }
}

uint8_t * dot11_frame::get_tag(uint8_t tag, int tags_len)
{
    uint8_t * offset = (uint8_t *)this + sizeof(dot11_frame);

    uint8_t * start_offset = offset;

    while(((*offset) != tag) && (offset - start_offset < tags_len))
    {
        offset += (*(offset + 1)) + 2;
    }

    return offset;

}

uint8_t * dot11_beacon_frame::get_tag(uint8_t tag, int tags_len)
{
    uint8_t * offset = (uint8_t *)this + sizeof(dot11_beacon_frame);

    uint8_t * start_offset = offset;

    while(((*offset) != tag) && (offset - start_offset < tags_len))
    {
        offset += (*(offset + 1)) + 2;
    }

    return offset;

}

void ap_info::Print(void)
{

    cout << BSSID << "\t";
    printf("-%d\t", (~(antsignal) & 0xFF) + 0b1);
    printf("%d\t", cnt);
    printf("%d\t", channel);
    printf("%s\n", ESSID.c_str());
//    cout << ESSID << "\t";
    printf("\n");
}

void station_info::Print(void)
{

    cout << BSSID << "\t" << STATION << "\t";
    printf("-%d\t", (~(antsignal) & 0xFF) + 0b1);
    printf("%d\t", cnt);
    cout << probe << "\t";
    printf("\n");
}


uint8_t* set_deauth(uint8_t * target, uint8_t * addr)
{


    uint8_t * packet = (uint8_t *)malloc(sizeof(radiotap_header) + sizeof(dot11_frame) + 2);
    radiotap_header * rt_header = (radiotap_header *)packet;
    rt_header->it_version = 0;
    rt_header->it_pad = 0;
    rt_header->it_len = 8;
    rt_header->it_present = 0;

    dot11_frame * frame = (dot11_frame *)(packet + rt_header->it_len);
    frame->fc.version = 0;
    frame->fc.type = dot11_fc::type::MANAGEMENT;
    frame->fc.subtype = dot11_fc::subtype::DEAUTH;
    frame->fc.flags = 0;
    memcpy(frame->addr1, target, 6);
    memcpy(frame->addr2, addr, 6);
    memcpy(frame->addr3, addr, 6);
    frame->frag_num = 0;
    frame->seq_num = 0;

    *(packet+sizeof(radiotap_header) + sizeof(dot11_frame)) = (uint16_t)(0x0007); // Class 3 frame received from nonassociated STA

    return (uint8_t*)packet;
}

uint8_t* set_beacon(uint8_t * addr)
{

    uint8_t * packet = (uint8_t *)malloc(sizeof(radiotap_header) + sizeof(dot11_frame) + 2);
    radiotap_header * rt_header = (radiotap_header *)packet;
    rt_header->it_version = 0;
    rt_header->it_pad = 0;
    rt_header->it_len = 8;

    dot11_beacon_frame * frame = (dot11_beacon_frame *)(packet + rt_header->it_len);
    frame->fc.type = dot11_fc::type::MANAGEMENT;
    frame->fc.subtype = dot11_fc::subtype::BEACON;
    memset(frame->addr1, 0xFF, 6);
    memcpy(frame->addr2, addr, 6);
    memcpy(frame->addr3, addr, 6);
    frame->frag_num = 0;
    frame->seq_num = 0;

    return (uint8_t*)packet;
}

std::string mac_to_string(uint8_t * addr)
{
    char temp[18];
    sprintf(temp, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return std::string(temp);

}
