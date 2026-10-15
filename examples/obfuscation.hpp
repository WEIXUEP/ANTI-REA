#pragma once
#if defined(AR_OBF_LIGHT)
#define AR_CONTROL                                                                                 \
    [[clang::annotate(                                                                             \
        "obf: mba(prob=40,maxSites=30), substitution(loop=1), split(num=2), strenc(minlen=6)")]]
#define AR_TOKEN AR_CONTROL
#elif defined(AR_OBF_MEDIUM)
#define AR_CONTROL                                                                                 \
    [[clang::annotate("obf: mba(prob=65,maxSites=60), substitution(loop=2), split(num=3), "        \
                      "bcf(prob=20,loop=1), strenc(minlen=6)")]]
#define AR_TOKEN AR_CONTROL
#elif defined(AR_OBF_HEAVY)
#define AR_CONTROL                                                                                 \
    [[clang::annotate("obf: mba(prob=70,maxSites=80), split(num=3), bcf(prob=25,loop=1), "         \
                      "flattening(minBlocks=3,maxBlocks=100), shield(maxSites=50), "               \
                      "adec(prob=25,maxSites=8,asm=0), strenc(minlen=6)")]]
#define AR_TOKEN AR_CONTROL
#elif defined(AR_OBF_MIXED_VM)
#define AR_CONTROL                                                                                 \
    [[clang::annotate("obf: mba(prob=60,maxSites=40), split(num=3), "                              \
                      "flattening(minBlocks=3,maxBlocks=100), strenc(minlen=6)")]]
#define AR_TOKEN [[clang::annotate("obf: vm(preset=light,antiDebug=0,hardened=0,bindAntiDebug=0)")]]
#else
#define AR_CONTROL
#define AR_TOKEN
#endif
