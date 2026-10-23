def apply(values):
    return [(value ^ 0xa341316c) & 0xffffffff for value in values]
