#include "varint.h"

/**
 * Converts an integer into a variable-length integer
 *
 * @param value the integer to be converted
 * @return A pointer to the varint buffer
 */
varint *write_var_int_62(const uint64_t value) {

    // Checks if most-significant 2 bytes are zero.
    // Otherwise, value is out of range.
    if ((value & kVarInt62ErrorMask) == 0) {

        varint *target;

        // Checks if the value fits in an 8-bytes encoding
        if ((value & kVarInt62Mask8Bytes) != 0) {
            // By right shifting operations, takes each byte
            // from left to right, executes bitwise and with a
            // bitmask and, only for the most-significant byte,
            // add the value 0xc0, which is binary 11000000, to set
            // the value 11 in the most significant bits.
            target = malloc(8);
            *(target + 0) = ((value >> 56) & 0x3f) + 0xc0;
            *(target + 1) = ((value >> 48) & 0xff);
            *(target + 2) = ((value >> 40) & 0xff);
            *(target + 3) = ((value >> 32) & 0xff);
            *(target + 4) = ((value >> 24) & 0xff);
            *(target + 5) = ((value >> 16) & 0xff);
            *(target + 6) = ((value >> 8) & 0xff);
            *(target + 7) = value & 0xff;
            return target;
        }

        // Checks if the value fits in an 4-bytes encoding
        if ((value & kVarInt62Mask4Bytes) != 0) {
            // By right shifting operations, takes each byte
            // from left to right, executes bitwise and with a
            // bitmask and, only for the most-significat byte,
            // add the value 0xc0, which is binary 11000000, to set
            // the value 11 in the most significant bits.
            target = malloc(4);
            *(target + 0) = ((value >> 24) & 0x3f) + 0x80;
            *(target + 1) = ((value >> 16) & 0xff);
            *(target + 2) = ((value >> 8) & 0xff);
            *(target + 3) = value & 0xff;
            return target;
        }

        // Checks if the value fits in an 2-bytes encoding
        if ((value & kVarInt62Mask2Bytes) != 0) {
            // By right shifting operations, takes each byte
            // from left to right, executes bitwise and with a
            // bitmask and, only for the most-significant byte,
            // add the value 0xc0, which is binary 11000000, to set
            // the value 11 in the most significant bits.
            target = malloc(2);
            *(target + 0) = ((value >> 8) & 0x3f) + 0x40;
            *(target + 1) = value & 0xff;
            return target;
        }

        target = malloc(1);
        *target = value & 0x3f;
        return target;
    }
    return NULL;      // If the value contains encoding errors
}

/**
 * Converts a variable-length integer into a 64-bits integer
 *
 * @param value a pointer to a varint buffer
 * @return the 64-bits integer value of the buffer
 */
uint64_t read_var_int_62(const varint *value) {

    // Takes most significant two bits as varint length
    size_t length = 1 << ((value[0] & 0xc0) >> 6);
    uint64_t ret = 0;

    switch (length) {
        case 1: {
            ret = value[0] & 0x3f;
            break;
        }
        case 2: {
            ret += (value[0] & 0x3f) << 8;
            ret += value[1];
            break;
        }
        case 4: {
            ret += (value[0] & 0x3f) << 24;
            ret += (value[1] & 0xff) << 16;
            ret += (value[2] & 0xff) << 8;
            ret += value[3];
            break;
        }
        case 8: {
            ret += ((uint64_t) value[0] & 0x3f) << 56;
            ret += ((uint64_t) value[1] & 0xff) << 48;
            ret += ((uint64_t) value[2] & 0xff) << 40;
            ret += ((uint64_t) value[3] & 0xff) << 32;
            ret += ((uint64_t) value[4] & 0xff) << 24;
            ret += ((uint64_t) value[5] & 0xff) << 16;
            ret += ((uint64_t) value[6] & 0xff) << 8;
            ret += value[7];
            break;
        }
        default : {
            return -1;
        }
    }
    return ret;
}

size_t varint_len(const varint *value) {
    uint8_t i = (value[0] & 0xc0) >> 6;
    return 1 << i;
}

size_t bytes_needed(uint64_t value) {
    if ((value & kVarInt62ErrorMask) == 0) {
        // Checks if the value fits in an 8-bytes encoding
        if ((value & kVarInt62Mask8Bytes) != 0)
            return 8;
        // Checks if the value fits in an 4-bytes encoding
        if ((value & kVarInt62Mask4Bytes) != 0)
            return 4;
        // Checks if the value fits in an 2-bytes encoding
        if ((value & kVarInt62Mask2Bytes) != 0)
            return 2;
        // Checks if the value fits in an 1-bytes encoding
        return 1;
    }
    return 0;
}

void print_varint(varint *var_int) {
    size_t len = varint_len(var_int);
    printf("Printing %ld:\n", read_var_int_62(var_int));
    for (int i = 0; i < len; i++) {
        printf("%x\t", var_int[i]);
    }
    printf("\n");
    for (int i = 0; i < len; i++) {
        printf("%u\t", var_int[i]);
    }
    printf("\n");
}
