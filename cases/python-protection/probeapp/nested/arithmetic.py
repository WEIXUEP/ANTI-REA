def rotate(value, count):
    return ((value << count) | (value >> (32 - count))) & 0xffffffff
