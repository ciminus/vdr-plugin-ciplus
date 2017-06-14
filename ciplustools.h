#ifndef CIPLUSTOOLS_H
#define CIPLUSTOOLS_H

#include "ciplus.h"
#include <stdint.h>
#include <stdio.h>

#define dbgprotocol(a...) if (DebugProtocol) fprintf(stderr, a)

int get_random(unsigned char *dest, int len);
int add_padding(uint8_t *dest, unsigned int len, unsigned int blocklen);
int BYTE16(unsigned char *dest, uint16_t val);
int BYTE32(uint8_t *dest, uint32_t val);
uint32_t UINT32(const uint8_t *in, unsigned int len);

const uint8_t *GetLength(const uint8_t *Data, int &Length);
uint8_t *SetLength(uint8_t *Data, int Length);
char *CopyString(int Length, const uint8_t *Data);
char *GetString(int &Length, const uint8_t **Data);

void trim(char *input);

#endif

