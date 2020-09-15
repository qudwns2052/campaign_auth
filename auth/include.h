#pragma once

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdint.h>
#include <cstring>
#include <map>
#include <unistd.h>
#include <pthread.h>
#include "mac.h"
#include "radiotap.h"
#include "dot11.h"
#include "hip.h"

using namespace std;
