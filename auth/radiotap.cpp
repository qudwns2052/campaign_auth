#include "radiotap.h"

static const struct radiotap_align_size radiotap_align_size_arr[] = {
    [TSFT] = { .align = 8, .size = 8, },
    [FLAGS] = { .align = 1, .size = 1, },
    [RATE] = { .align = 1, .size = 1, },
    [CHANNEL] = { .align = 2, .size = 4, },
    [FHSS] = { .align = 2, .size = 2, },
    [DBM_ANTSIGNAL] = { .align = 1, .size = 1, },
    [DBM_ANTNOISE] = { .align = 1, .size = 1, },
    [LOCK_QUALITY] = { .align = 2, .size = 2, },
    [TX_ATTENUATION] = { .align = 2, .size = 2, },
    [DB_TX_ATTENUATION] = { .align = 2, .size = 2, },
    [DBM_TX_POWER] = { .align = 1, .size = 1, },
    [ANTENNA] = { .align = 1, .size = 1, },
    [DB_ANTSIGNAL] = { .align = 1, .size = 1, },
    [DB_ANTNOISE] = { .align = 1, .size = 1, },
    [RX_FLAGS] = { .align = 2, .size = 2, },
    [TX_FLAGS] = { .align = 2, .size = 2, },
    [RTS_RETRIES] = { .align = 1, .size = 1, },
    [DATA_RETRIES] = { .align = 1, .size = 1, },
    [XCHANNEL] = { .align = 4, .size = 8, },
    [MCS] = { .align = 1, .size = 3, },
    [AMPDU_STATUS] = { .align = 4, .size = 8, },
    [VHT] = { .align = 2, .size = 12, },
    [TIMESTAMP] = { .align = 8, .size = 12, }
};


uint8_t* radiotap_header::radiotap_present_flag(radiotap_presence ps)
{
    int offset;

    if(this->it_present & (0b1 << 31))
    {
        offset = sizeof(radiotap_header) + sizeof(this->it_present);
    }
    else
    {
        offset = sizeof(radiotap_header);
    }

    for(int i = 0; i < ps; i++)
    {
        if(this->it_present & (0b1 << i))
        {
            if(offset % radiotap_align_size_arr[i].align != 0)
            {
                offset += radiotap_align_size_arr[i].align - (offset % radiotap_align_size_arr[i].align);
            }
            offset += radiotap_align_size_arr[i].size;
        }
    }

    if(offset % radiotap_align_size_arr[ps].align!= 0)
    {
        offset += radiotap_align_size_arr[ps].align - (offset & radiotap_align_size_arr[ps].align);
    }


    return ((uint8_t*)this + offset);
}
