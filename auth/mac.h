#pragma once

#include "include.h"
;
#pragma pack(push, 1)

class Mac
{
public:
    uint8_t addr[6];

    Mac() {}
    Mac(uint8_t * _mac)
    {
        memcpy(this->addr, _mac, 6);
    }
    void operator=(const uint8_t * addr)
    {
        memcpy(this->addr, addr, 6);
    }
    bool operator ==(const Mac & ref)
    {
        return !memcmp(this->addr, ref.addr, 6);
    }
    bool operator ==(const uint8_t * addr)
    {
        return !memcmp(this->addr, addr, 6);
    }
    bool operator !=(const Mac & ref)
    {
        return !memcmp(this->addr, ref.addr, 6);
    }
    bool operator !=(const uint8_t * addr)
    {
        return !memcmp(this->addr, addr, 6);
    }

    bool operator <(const Mac & ref) const
    {
        return (memcmp(this->addr, ref.addr, 6) < 0) ? true : false;
    }

    operator uint8_t * () { return addr; }
    operator std::string() const
    {
        char temp[18];
        sprintf(temp, "%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        return std::string(temp);
    }

};


#pragma pack(pop)
