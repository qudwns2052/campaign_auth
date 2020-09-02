#pragma once
#include "include.h"

enum radiotap_presence {
    TSFT = 0,
    FLAGS = 1,
    RATE = 2,
    CHANNEL = 3,
    FHSS = 4,
    DBM_ANTSIGNAL = 5,
    DBM_ANTNOISE = 6,
    LOCK_QUALITY = 7,
    TX_ATTENUATION = 8,
    DB_TX_ATTENUATION = 9,
    DBM_TX_POWER = 10,
    ANTENNA = 11,
    DB_ANTSIGNAL = 12,
    DB_ANTNOISE = 13,
    RX_FLAGS = 14,
    TX_FLAGS = 15,
    RTS_RETRIES = 16,
    DATA_RETRIES = 17,
    XCHANNEL = 18,    /* 18 is XChannel, but it's not defined yet */
    MCS = 19,
    AMPDU_STATUS = 20,
    VHT = 21,
    TIMESTAMP = 22,

    /* valid in every it_present bitmap, even vendor namespaces */
    RADIOTAP_NAMESPACE = 29,
    VENDOR_NAMESPACE = 30,
    EXT = 31
};

struct radiotap_align_size {
    uint8_t align:4, size:4;
};

#pragma pack(push, 1)
typedef struct radiotap_header {

    uint8_t        it_version;     /* set to 0 */
    uint8_t        it_pad;
    uint16_t       it_len;         /* entire length */
    uint32_t       it_present;     /* fields present */


    uint8_t* radiotap_present_flag(radiotap_presence ps);

}radiotap_header;

#pragma pack(pop)
