#include "ciplustools.h"
#include <vdr/tools.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>



int get_random(unsigned char *dest, int len)
{
	int fd;
	const char *urnd = "/dev/urandom";

	fd = open(urnd, O_RDONLY);
	if (fd <= 0) {
		printf("cannot open %s\n", urnd);
		return -1;
	}

	if (read(fd, dest, len) != len) {
		printf("cannot read from %s\n", urnd);
		close(fd);
		return -2;
	}

	close(fd);

	return len;
}

int add_padding(uint8_t *dest, unsigned int len, unsigned int blocklen)
{
	uint8_t padding = 0x80;
	int count = 0;

	while (len & (blocklen - 1)) {
		*dest++ = padding;
		++len;
		++count;
		padding = 0;
	}

	return count;
}

int BYTE16(unsigned char *dest, uint16_t val)
{
	*dest++ = val >> 8;
	*dest++ = val;
	return 2;
}

int BYTE32(unsigned char *dest, uint32_t val)
{
	*dest++ = val >> 24;
	*dest++ = val >> 16;
	*dest++ = val >> 8;
	*dest++ = val;

	return 4;
}

uint32_t UINT32(const unsigned char *in, unsigned int len)
{
	uint32_t val = 0;
	unsigned int i;

	for (i = 0; i < len; i++) {
		val <<= 8;
		val |= *in++;
	}

	return val;
}

#define SIZE_INDICATOR 0x80

const uint8_t *GetLength(const uint8_t *Data, int &Length)
///< Gets the length field from the beginning of Data.
///< Returns a pointer to the first byte after the length and
///< stores the length value in Length.
{
  Length = *Data++;
  if ((Length & SIZE_INDICATOR) != 0) {
     int l = Length & ~SIZE_INDICATOR;
     Length = 0;
     for (int i = 0; i < l; i++)
         Length = (Length << 8) | *Data++;
     }
  return Data;
}

uint8_t *SetLength(uint8_t *Data, int Length)
///< Sets the length field at the beginning of Data.
///< Returns a pointer to the first byte after the length.
{
  uint8_t *p = Data;
  if (Length < 128)
     *p++ = Length;
  else {
     int n = sizeof(Length);
     for (int i = n - 1; i >= 0; i--) {
         int b = (Length >> (8 * i)) & 0xFF;
         if (p != Data || b)
            *++p = b;
         }
     *Data = (p - Data) | SIZE_INDICATOR;
     p++;
     }
  return p;
}

char *CopyString(int Length, const uint8_t *Data)
///< Copies the string at Data.
///< Returns a pointer to a newly allocated string.
{
  // Some CAMs send funny characters at the beginning of strings.
  // Let's just skip them:
  while (Length > 0 && (*Data == ' ' || *Data == 0x05 || *Data == 0x96 || *Data == 0x97)) {
        Length--;
        Data++;
        }
  char *s = MALLOC(char, Length + 1);
  strncpy(s, (char *)Data, Length);
  s[Length] = 0;
  // The character 0x8A is used as newline, so let's put a real '\n' in there:
  strreplace(s, 0x8A, '\n');
  return s;
}

char *GetString(int &Length, const uint8_t **Data)
///< Gets the string at Data.
///< Returns a pointer to a newly allocated string, or NULL in case of error.
///< Upon return Length and Data represent the remaining data after the string has been skipped.
{
  if (Length > 0 && Data && *Data) {
     int l = 0;
     const uint8_t *d = GetLength(*Data, l);
     char *s = CopyString(l, d);
     Length -= d - *Data + l;
     *Data = d + l;
     return s;
     }
  return NULL;
}

void trim(char *input)
{
   char *dst = input, *src = input;
   char *end;

   // Skip whitespace at front...
   //
   while (isspace((unsigned char)*src))
   {
      ++src;
   }

   // Trim at end...
   //
   end = src + strlen(src) - 1;
   while (end > src && isspace((unsigned char)*end))
   {
      *end-- = 0;
   }

   // Move if needed.
   //
   if (src != dst)
   {
      while ((*dst++ = *src++));
   }
}