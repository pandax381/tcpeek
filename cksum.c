#include "tcpeek.h"

uint16_t
cksum16(uint16_t *data, uint16_t size, uint32_t init) {
	uint32_t sum;

	sum = init;
	while(size > 1) {
        sum += *(data++);
        size -= 2;
	}
	if(size) {
        sum += *(uint8_t *)data;
	}
    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
    return ~(uint16_t)sum;
}
