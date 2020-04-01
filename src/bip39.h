#ifndef BIP39_H
#define BIP39_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

void* bip39_new_context();
void bip39_dispose_context(void* ctx);
const char * bip39_get_mnemonic(void* ctx, uint16_t n);

// Returns -1 if the string is not a valid BIP39 mnemonic.
int16_t bip39_get_index(const char* mnemonic);

void bip39_start_search(void* ctx);
void bip39_choose_low(void* ctx);
void bip39_choose_high(void* ctx);

const char * bip39_get_low(const void* ctx);
const char * bip39_get_high(const void* ctx);
const bool bip39_done_search(const void* ctx);
const uint16_t bip39_selected_word(const void* ctx);

void bip39_set_payload_bytes(void* ctx, size_t bytes);
void bip39_set_payload_words(void* ctx, size_t words);

void bip39_append_checksum(void* ctx);
bool bip39_verify_checksum(const void* ctx);

void bip39_clear(void* ctx);

uint16_t bip39_get_word(const void* ctx, size_t n);
void bip39_set_word(void* ctx, size_t n, uint16_t w);

const uint8_t* bip39_get_payload(const void* ctx);

#endif
