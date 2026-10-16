#ifndef D2K_TG_ENROLL_H
#define D2K_TG_ENROLL_H
#include "tg_identity.h"
#define TG_ENROLL_SIZE 120
int tg_enroll_proof(const tg_identity *identity, uint8_t out[TG_ENROLL_SIZE]);
#endif
