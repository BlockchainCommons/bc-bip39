#ifndef BIP39_H
#define BIP39_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

//
// The following API is high-level and recommended.
//

// Returns the English mnemonic string for the given BIP39 word
// Returns NULL if the word is out of range (> 2047).
void bip39_mnemonic_from_word(uint16_t word, char *mnemonic);

// Returns the BIP39 word for the given English mnemonic string.
// Returns -1 if the string is not a valid BIP39 mnemonic.
int16_t bip39_word_from_mnemonic(const char *mnemonic);

// Writes out the BIP39 words for the given secret.
// Returns the number of words written;
size_t bip39_words_from_secret(const uint8_t *secret, size_t secret_len,
                               uint16_t *words, size_t max_words_len);

// Writes out the BIP39 English mnemonics for the given secret.
// Returns the length of the string written.
size_t bip39_mnemonics_from_secret(const uint8_t *secret, size_t secret_len,
                                   char *mnemonics, size_t max_mnemonics_len);

// Writes out the BIP39 words for the given English mnemonics.
// Returns the number of words written.
size_t bip39_words_from_mnemonics(const char *mnemonics, uint16_t *words,
                                  size_t max_words_len);

// Writes out the secret for the given English mnemonics.
// Returns the number of bytes written.
size_t bip39_secret_from_mnemonics(const char *mnemonics, uint8_t *secret,
                                   size_t max_secret_len);

// Writes the 32-byte (BIP39_SEED_LEN) SHA256 hash of `string` to `seed`.
#define BIP39_SEED_LEN 32
void bip39_seed_from_string(const char *string, uint8_t *seed);

//
// The following API is low-level and requires the creation of a context handle.
//

typedef struct bip39_context_struct bip39_context_t;

bip39_context_t *bip39_new_context();
void bip39_dispose_context(bip39_context_t *ctx);

const char *bip39_get_mnemonic(bip39_context_t *ctx, uint16_t n);

void bip39_start_search(bip39_context_t *ctx);
void bip39_choose_low(bip39_context_t *ctx);
void bip39_choose_high(bip39_context_t *ctx);

const char *bip39_get_low(const bip39_context_t *ctx);
const char *bip39_get_high(const bip39_context_t *ctx);
const bool bip39_done_search(const bip39_context_t *ctx);
const uint16_t bip39_selected_word(const bip39_context_t *ctx);

void bip39_set_byte_count(bip39_context_t *ctx, size_t bytes);
uint8_t bip39_get_byte_count(const bip39_context_t *ctx);
void bip39_set_bytes(bip39_context_t *ctx, const uint8_t *bytes, size_t length);
const uint8_t *bip39_get_bytes(const bip39_context_t *ctx);

void bip39_set_word_count(bip39_context_t *ctx, size_t words);
size_t bip39_get_word_count(const bip39_context_t *ctx);
void bip39_set_word(bip39_context_t *ctx, size_t n, uint16_t w);
uint16_t bip39_get_word(const bip39_context_t *ctx, size_t n);

void bip39_set_payload(bip39_context_t *ctx, size_t length,
                       const uint8_t *bytes);

void bip39_append_checksum(bip39_context_t *ctx);
bool bip39_verify_checksum(const bip39_context_t *ctx);

void bip39_clear(bip39_context_t *ctx);

#endif
