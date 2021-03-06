/* ppcrack 0.1 - decrypts PowerPacker encrypted data files with brute force
 * by Stuart Caie <kyzer@4u.net>, this software is in the Public Domain
 *
 * For 80x86 Linux, compile with:
 * gcc -O3 -fomit-frame-pointer -fexpensive-optimizations -funroll-all-loops \
 *     -funroll-loops -finline-functions -fschedule-insns2 -mcpu=pentiumpro \
 *     -o ppcrack ppcrack.c
 *
 * Usage: ppcrack [-<key>] <files>
 *
 * Example: ppcrack -034b5769 AMOSdemo.AMOS.pp
 *          ppcrack *.pp
 *
 * The whole keyspace is scanned, unless you supply the -key argument, where
 * that key (in hexadecimal) to key FFFFFFFF is scanned.
 *
 * Anything which decrypts then decrunches to valid data is saved to disk
 * as <original filename>.<decryption key>
 *
 * As a bonus, if any file is a PowerPacker data file, but not encrypted,
 * it will be decrunched anyway, and saved as <original filename>.decrunched
 */

#include <stdlib.h>
#include <stdio.h>
#include "ppcrack.h"

size_t filelen;

void *loadfile(char *name) {
  void *mem = NULL; FILE *fd;
  if ((fd = fopen(name, "rb"))) {
    if ((fseek(fd, 0, SEEK_END) == 0) && (filelen = ftell(fd))
    &&  (fseek(fd, 0, SEEK_SET) == 0) && (mem = malloc(filelen))) {
      if (fread(mem, 1, filelen, fd) < filelen) { free(mem); mem = NULL; }
    }
    fclose(fd);
  }
  return mem;
}

int savefile(char *name, void *mem, size_t length) {
  FILE *fd = fopen(name, "wb");
  int ok = fd && (fwrite(mem, 1, length, fd) == length);
  if (fd) fclose(fd);
  return ok;
}



char output_name[512];

inline void ppDecryptCopy(UBYTE *src, UBYTE *dest, ULONG len, ULONG key) {
  UBYTE a = (key>>24) & 0xFF;
  UBYTE b = (key>>16) & 0xFF;
  UBYTE c = (key>> 8) & 0xFF;
  UBYTE d = (key    ) & 0xFF;

  len = (len + 3) >> 2;
  while (len--) {
    *dest++ = *src++ ^ a;
    *dest++ = *src++ ^ b;
    *dest++ = *src++ ^ c;
    *dest++ = *src++ ^ d;
  }
}

#define PP_READ_BITS(nbits, var) do {                          \
  bit_cnt = (nbits);                                           \
  while (bits_left < bit_cnt) {                                \
    if (buf_src < src) return 0; /* out of source bits */      \
    bit_buffer |= (*--buf_src << bits_left);                   \
    bits_left += 8;                                            \
  }                                                            \
  (var) = 0;                                                   \
  bits_left -= bit_cnt;                                        \
  while (bit_cnt--) {                                          \
    (var) = ((var) << 1) | (bit_buffer & 1);                   \
    bit_buffer >>= 1;                                          \
  }                                                            \
} while(0)

#define PP_BYTE_OUT(byte) do {                                 \
  if (out < dest) return 0; /* output overflow */              \
  *--out = (byte);                                             \
  written++;                                                   \
} while (0)

int ppDecrunch(UBYTE *src, UBYTE *dest, UBYTE *offset_lens,
               ULONG src_len, ULONG dest_len, UBYTE skip_bits)
{
  UBYTE *buf_src, *out, *dest_end, bits_left = 0, bit_cnt;
  ULONG bit_buffer = 0, x, todo, offbits, offset, written=0;

  if (src == NULL || dest == NULL || offset_lens == NULL) return 0;

  /* set up input and output pointers */
  buf_src = src + src_len;
  out = dest_end = dest + dest_len;

  /* skip the first few bits */
  PP_READ_BITS(skip_bits, x);

  /* while there are input bits left */
  while (written < dest_len) {
    PP_READ_BITS(1, x);
    if (x == 0) {
      /* 1bit==0: literal, then match. 1bit==1: just match */
      todo = 1; do { PP_READ_BITS(2, x); todo += x; } while (x == 3);
      while (todo--) { PP_READ_BITS(8, x); PP_BYTE_OUT(x); }
    }

    /* match: read 2 bits for initial offset bitlength / match length */
    PP_READ_BITS(2, x);
    offbits = offset_lens[x];
    todo = x+2;
    if (x == 3) {
      PP_READ_BITS(1, x);
      if (x==0) offbits = 7;
      PP_READ_BITS(offbits, offset);
      do { PP_READ_BITS(3, x); todo += x; } while (x == 7);
    }
    else {
      PP_READ_BITS(offbits, offset);
    }
    if ((out + offset) >= dest_end) return 0; /* match overflow */
    while (todo--) { x = out[offset]; PP_BYTE_OUT(x); }
  }

  /* all output bytes written without error */
  return 1;
  /* return (src == buf_src) ? 1 : 0; */
}                     


/* this pretends to decrunch a data stream. If it wasn't decrypted
 * exactly right, it will access match offsets that don't exist, or
 * request match lengths that there isn't enough data for, or will
 * underrun or overrun the theoretical output buffer
 */
inline int ppValidate(UBYTE *src, UBYTE *offset_lens,
                      ULONG src_len, ULONG dest_len, UBYTE skip_bits)
{
  UBYTE *buf_src, bits_left = 0, bit_cnt;
  ULONG bit_buffer = 0, x, todo, offbits, offset, written=0;

  if (src == NULL || offset_lens == NULL) return 0;

  /* set up input pointer */
  buf_src = src + src_len;

  /* skip the first few bits */
  PP_READ_BITS(skip_bits, x);

  /* while there are input bits left */
  while (written < dest_len) {
    PP_READ_BITS(1, x);
    if (x == 0) {
      /* 1bit==0: literal, then match. 1bit==1: just match */
      todo = 1; do { PP_READ_BITS(2, x); todo += x; } while (x == 3);
      written += todo; if (written > dest_len) return 0;
      while (todo--) PP_READ_BITS(8, x);
    }

    /* match: read 2 bits for initial offset bitlength / match length */
    PP_READ_BITS(2, x);
    offbits = offset_lens[x];
    todo = x+2;
    if (x == 3) {
      PP_READ_BITS(1, x);
      if (x==0) offbits = 7;
      PP_READ_BITS(offbits, offset);
      do { PP_READ_BITS(3, x); todo += x; } while (x == 7);
    }
    else {
      PP_READ_BITS(offbits, offset);
    }
    if (offset >= written) return 0; /* match overflow */
    written += todo; if (written > dest_len) return 0;
  }

  /* all output bytes written without error */
  return 1;
}                     

void ppcrack(char *name, UBYTE *data, ULONG len) {
  /* PP FORMAT:
   *      1 longword identifier           'PP20' or 'PX20'
   *     [1 word checksum (if 'PX20')     $ssss]
   *      1 longword efficiency           $eeeeeeee
   *      X longwords crunched file       $cccccccc,$cccccccc,...
   *      1 longword decrunch info        'decrlen' << 8 | '8 bits other info'
   */
  UBYTE *output, crypted;
  ULONG outlen;

  if (len < 16) {
    printf("%s: file is too short to be a PP file (%u bytes)\n", name, len);
    return;
  }

  if (data[0]=='P' && data[1]=='P' && data[2]=='2' && data[3]=='0') {
    if (len & 0x03) {
      printf("%s: file length is not a multiple of 4\n", name);
      return;
    }
    crypted = 0;
  }
  else if (data[0]=='P' && data[1]=='X' && data[2]=='2' && data[3]=='0') {
    if ((len-2) & 0x03) {
      printf("%s: (file length - 2) is not a multiple of 4\n", name);
      return;
    }
    crypted = 1;
  }
  else {
    printf("%s: file does not have the PP signature\n", name);
    return;
  }

  outlen = (data[len-4]<<16) | (data[len-3]<<8) | data[len-2];

  printf("%s: decrunched length = %u bytes\n", name, outlen);

  output = (UBYTE *) malloc(outlen);
  if (output == NULL) {
    printf("%s: out of memory!\n", name);
    return;
  }

  if (crypted == 0) {
    printf("%s: not encrypted, decrunching anyway\n", name);
    if (ppDecrunch(&data[8], output, &data[4], len-12, outlen, data[len-1])) {
      printf("%s: Decrunch successful!\n", name);
      sprintf(output_name, "%s.decrunched", name);
      savefile(output_name, (void *) output, outlen);
    }
  }
  else {
    /* brute-force calculate the key */

    ULONG key = key_start;

    /* shortcut to halve keyspace:
     * PowerPacker alternates between two operations - literal and match.
     * The FIRST operation must be literal, as there's no data been output
     * to match yet, so the first BIT in the compressed stream must be set
     * to 0. The '8 bits other info' is actually the number of bits unused
     * in the first longword. We must ignore these.
     *
     * So we know which bit is the first one in the compressed stream, and
     * that is matched a bit in the decryption XOR key.
     *
     * We know the encrypted value of the first bit, and we know it must
     * actually be 0 when decrypted. So, if the value is 1, then that bit
     * of the decryption key must be 1, to invert that bit to a 0. If the
     * value is 0, then that bit of the decryption key must be 0, to leave
     * that bit set at 0.
     *
     * Given the knowledge of exactly one of the bits in the keys, we can
     * reject all keys that do not have the appropriate value for this bit.
     */
    ULONG drop_mask = 1 << data[len-1];
    ULONG drop_value = ( (data[len-8]<<24) | (data[len-7]<<16)
                       | (data[len-6]<<8)  |  data[len-5] ) & drop_mask;

    UBYTE *temp = (UBYTE *) malloc(len-14);
    if (temp == NULL) {
      printf("%s: out of memory!\n", name);
      return;
    }

    do {
      if ((key & 0xFFF) == 0) {
        printf("key %08x\r", key);
        fflush(stdout);
      }

      if ((key & drop_mask) != drop_value) continue;

      /* decrypt with this key */
      ppDecryptCopy(&data[10], temp, len-14, key);

      if (ppValidate(temp, &data[6], len-14, outlen, data[len-1])) {
        printf("%s: key %08x success!\n", name, key);
	ppDecrunch(temp, output, &data[6], len-14, outlen, data[len-1]);
        sprintf(output_name, "%s.%08x", name, key);
        savefile(output_name, output, outlen);
      }

    } while (key++ != 0xFFFFFFFF);
    free(temp);
    printf("All keys done!\n");
  }

  free((void *) output);
}
/*
int main(int argc, char *argv[]) {
  int i;
  if (argc < 2) {
    printf("Usage: %s [-key] <encrypted powerpacked file(s)>\n", argv[0]);
    printf("Example: %s -30a9f3e3 secret.pp\n", argv[0]);
    return 1;
  }

  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-') {
      if (sscanf(&argv[i][1], "%x", &key_start) == 1) {
        printf("Base key to try decryption from: 0x%08x\n", key_start);
      }
      else {
        key_start = 0;
      }
    }
    else {
      void *data = loadfile(argv[i]);
      if (data != NULL) {
        ppcrack(argv[i], (UBYTE *) data, (int) filelen);
        free(data);
      }
    }
  }
  return 0;
}*/
