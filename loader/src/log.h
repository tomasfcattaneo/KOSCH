/* безликий */
#pragma once

#include <stdio.h>

#ifdef KOSHCHEI_RELEASE
#define LOG_INF(fmt, ...) ((void)0)
#define LOG_WRN(fmt, ...) ((void)0)
#define LOG_ERR(fmt, ...) ((void)0)
#else
#define LOG_INF(fmt, ...) fprintf(stdout, "[INF] " fmt "\n", ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) fprintf(stdout, "[WRN] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) fprintf(stderr, "[ERR] " fmt "\n", ##__VA_ARGS__)
#endif
