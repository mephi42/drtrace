#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t updcrc32(uint32_t value, char* buf, size_t len);
uint32_t crc32(char* buf, size_t len);

#ifdef __cplusplus
}
#endif
