#ifndef VARINT
#define VARINT

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define kVarInt62ErrorMask UINT64_C(0xc000000000000000)
#define kVarInt62Mask8Bytes UINT64_C(0x3fffffffc0000000)
#define kVarInt62Mask4Bytes UINT64_C(0x000000003fffc000)
#define kVarInt62Mask2Bytes UINT64_C(0x0000000000003fc0)

typedef uint8_t varint;

varint *write_var_int_62(uint64_t);

uint64_t read_var_int_62(const varint *);

size_t varint_len(const varint *);

size_t bytes_needed(uint64_t);

#endif