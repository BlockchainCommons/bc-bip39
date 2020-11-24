#include "bip39.h"
#include "arduino-support.h"
#include "index_char.h"

#include "prefix1.h"
#include "prefix2.h"

#include "suffix_array.h"

#include <stdlib.h>
#include <string.h>

#ifdef ARDUINO
#include "bc-crypto-base.h"
#else
#include <bc-crypto-base/bc-crypto-base.h>
#endif

// This class provides a couple of services related to Bip39 mnemonic sentences
// First, it provides a way to look up english mnemonics by the code word that
// they represent.
// Next, it provides a means to generate a checksum on a sequence of bytes
// and then generate a series of words from that, or it provides you with
// a mechanism to input a sequence of words, verify the checksum and extract
// the original paylaod.

#define BIP39_BUF_MAX 40

typedef struct context_t {
    char wordBuf[9];
    char wordBufHi[9];

    uint16_t lo;
    uint16_t mid;
    uint16_t hi;

    size_t payload_byte_count;
    size_t payload_word_count;

    uint8_t buffer[BIP39_BUF_MAX];

    uint8_t currentWord;
} context;

void* bip39_new_context() {
    size_t context_len = sizeof(context);
    context* ctx = calloc(context_len, 1);
    ctx->payload_byte_count = 32;
    ctx->payload_word_count = 24;
    return ctx;
}

void bip39_dispose_context(void* ctx) { free(ctx); }

static char lookup(const index_char* table, uint8_t length, uint16_t n) {
    uint8_t lo = 0;
    uint8_t hi = length;
    static index_char m;

    while (lo + 1 < hi) {
        uint8_t mid = (lo + hi) / 2;
        MEMCPY_P(&m, &(table[mid]), sizeof(index_char));
        if (m.i < n) {
            lo = mid;
        } else if (m.i > n) {
            hi = mid;
        } else {
            lo = mid;
            break;
        }
    }
    MEMCPY_P(&m, &table[lo], sizeof(index_char));
    return m.c;
}

static void load_mnemonic(uint16_t i, char* b) {
    b[0] = lookup(bip39_prefix1, PREFIX_1_LEN, i);
    b[1] = lookup(bip39_prefix2, PREFIX_2_LEN, i);
    STRCPY_P(b + 2, bip39_suffix[i]);
}

const char* bip39_get_mnemonic(void* ctx, uint16_t i) {
    if (i > 2047) {
        return NULL;
    }
    context* c = ctx;
    load_mnemonic(i, c->wordBuf);
    return c->wordBuf;
}

void bip39_mnemonic_from_word(uint16_t word, char* mnemonic) {
  context* ctx = bip39_new_context();
  const char* string = bip39_get_mnemonic(ctx, word);
  if(string == NULL) {
      mnemonic[0] = '\0';
  } else {
      strcpy(mnemonic, string);
  }
  bip39_dispose_context(ctx);
}

void bip39_start_search(void* ctx) {
    context* c = ctx;
    c->lo = 0;
    c->hi = 2048;
    c->mid = (c->lo + c->hi) / 2;
    load_mnemonic(c->lo, c->wordBuf);
    load_mnemonic(c->mid, c->wordBufHi);
}

void bip39_choose_low(void* ctx) {
    context* c = ctx;
    c->hi = c->mid;
    c->mid = (c->lo + c->hi) / 2;
    load_mnemonic(c->mid, c->wordBufHi);
}

void bip39_choose_high(void* ctx) {
    context* c = ctx;
    c->lo = c->mid;
    c->mid = (c->lo + c->hi) / 2;
    load_mnemonic(c->lo, c->wordBuf);
    load_mnemonic(c->mid, c->wordBufHi);
}

const char* bip39_get_low(const void* ctx) {
    const context* c = ctx;
    return c->wordBuf;
}

const char* bip39_get_high(const void* ctx) {
    const context* c = ctx;
    return c->wordBufHi;
}

const bool bip39_done_search(const void* ctx) {
    const context* c = ctx;
    return c->lo == c->mid;
}

const uint16_t bip39_selected_word(const void* ctx) {
    const context* c = ctx;
    return c->lo;
}

// NOTE that there is something fishy here.
// 25 * 8 = 200 / 11
void bip39_set_byte_count(void* ctx, size_t bytes) {
    context* c = ctx;
    c->payload_byte_count = bytes;
    c->payload_word_count = ((uint16_t)bytes * 3 + 2) / 4;
}

void bip39_set_word_count(void* ctx, size_t words) {
    context* c = ctx;
    c->payload_word_count = words;
    c->payload_byte_count = ((uint16_t)words * 11 - 1) / 8;
}

size_t bip39_get_word_count(const void* ctx) {
    const context* c = ctx;
    return c->payload_word_count;
}

uint8_t bip39_get_byte_count(const void* ctx) {
    const context* c = ctx;
    return c->payload_byte_count;
}

static uint8_t* compute_checksum(const void* ctx) {
    const context* c = ctx;

    uint8_t* digest = malloc(SHA256_DIGEST_LENGTH);
    sha256_Raw(c->buffer, c->payload_byte_count, digest);
    return digest;
}

void bip39_append_checksum(void* ctx) {
    context* c = ctx;

    uint8_t* res = compute_checksum(ctx);

    c->buffer[c->payload_byte_count] = res[0];
    c->buffer[c->payload_byte_count + 1] = res[1];

    free(res);
}

bool bip39_verify_checksum(const void* ctx) {
    const context* c = ctx;

    uint8_t checksum_bits = 11 - ((c->payload_byte_count * 8) % 11);
    uint8_t* res = compute_checksum(ctx);

    uint8_t mask;

    bool result;

    if (checksum_bits <= 8) {
        mask = 0xFF << (8 - checksum_bits);
        result = (c->buffer[c->payload_byte_count] & mask) == (res[0] & mask);
    } else {
        mask = 0xFF << (16 - checksum_bits);
        result =
            c->buffer[c->payload_byte_count] == res[0] &&
            (c->buffer[c->payload_byte_count + 1] & mask) == (res[1] & mask);
    }

    free(res);

    return result;
}

void bip39_clear(void* ctx) {
    context* c = ctx;

    for (uint16_t i = 0; i < BIP39_BUF_MAX; i++) {
        c->buffer[i] = 0;
    }
    for (uint8_t i = 0; i < 9; i++) {
        c->wordBuf[i] = 0;
        c->wordBufHi[i] = 0;
    }
}

uint16_t bip39_get_word(const void* ctx, size_t n) {
    const context* c = ctx;

    // Get the nth word from the buffer
    size_t bit_index = 11 * n;
    size_t start_byte_index = bit_index / 8;
    size_t bits_at_index =
        8 - (bit_index % 8);  // number of bits of b[j] that belong to w
    size_t bits_at_next_index = 11 - bits_at_index;

    if (start_byte_index >= BIP39_BUF_MAX) {
        return 0xFFFF;
    }

    size_t byte_index = start_byte_index;
    uint8_t byte = c->buffer[byte_index];
    uint16_t word = (byte << bits_at_next_index) & 0x7FF;
    byte_index++;

    while (byte_index < BIP39_BUF_MAX) {
        if (bits_at_next_index > 8) {
            bits_at_next_index = bits_at_next_index - 8;
            byte = c->buffer[byte_index];
            word |= byte << bits_at_next_index;
        } else {
            byte = c->buffer[byte_index];
            word |= byte >> (8 - bits_at_next_index);
            break;
        }
        byte_index++;
    }
    return word;
}

void bip39_set_word(void* ctx, size_t n, uint16_t w) {
    context* c = ctx;

    // Set the nth word in the buffer to w
    uint16_t b = 11 * (uint16_t)n;
    uint16_t j = b / 8;
    uint8_t k = 8 - (b % 8);
    uint8_t down = 11 - k;

    // mask off upper bits to keep from accidentally
    // polluting other words
    w = w & 0x7FF;

    if (j >= BIP39_BUF_MAX) {
        return;
    }

    // This might be a partial byte,
    // so only set the bits that we are interested in
    c->buffer[j] &= ~(0x7FF >> down);
    c->buffer[j++] |= (w >> down);

    while (j < BIP39_BUF_MAX) {
        if (down > 8) {
            down = down - 8;
            c->buffer[j++] = (w >> down);
        } else {
            // again, may be a partial byte
            c->buffer[j] &= ~(0x7FF << (8 - down));
            c->buffer[j] |= (w << (8 - down));
            break;
        }
    }
}

const uint8_t* bip39_get_bytes(const void* ctx) {
    const context* c = ctx;
    return c->buffer;
}

void bip39_set_bytes(void* ctx, const uint8_t* bytes, size_t length) {
    if (length >= BIP39_BUF_MAX) {
        return;
    }
    context* c = ctx;
    for (int i = 0; i < length; i++) {
        c->buffer[i] = bytes[i];
    }
}

int16_t find_in_prefix_1(char c) {
    for (int i = 0; i < PREFIX_1_LEN; i++) {
        if (bip39_prefix1[i].c == c) {
            return bip39_prefix1[i].i;
        }
    }
    return -1;
}

void find_in_prefix_2(char c, int16_t start_index, int16_t* i1, int16_t* i2) {
    int lo = 0;
    int hi = PREFIX_2_LEN;
    index_char m;

    while (lo < hi) {
        int mid = (lo + hi) / 2;
        MEMCPY_P(&m, &(bip39_prefix2[mid]), sizeof(index_char));
        if (m.i < start_index) {
            lo = mid;
        } else if (m.i > start_index) {
            hi = mid;
        } else {
            lo = mid;
            break;
        }
    }

    while (m.c < c) {
        lo += 1;
        if (lo == PREFIX_2_LEN) {
            *i1 = -1;
            return;
        }
        MEMCPY_P(&m, &(bip39_prefix2[lo]), sizeof(index_char));
    }

    if (m.c == c) {
        *i1 = m.i;
        if (lo == PREFIX_2_LEN - 1) {
            *i2 = 2048;
        } else {
            MEMCPY_P(&m, &(bip39_prefix2[lo + 1]), sizeof(index_char));
            *i2 = m.i;
        }
    } else {
        *i1 = -1;
    }
}

int16_t bip39_word_from_mnemonic(const char* mnemonic) {
    if (mnemonic == NULL) {
        return -1;
    }
    if (strlen(mnemonic) < 3) {
        return -1;
    }
    char c0 = mnemonic[0];
    int16_t start_index = find_in_prefix_1(c0);
    char c1 = mnemonic[1];
    int16_t i1, i2;
    find_in_prefix_2(c1, start_index, &i1, &i2);
    const char* s1 = mnemonic + 2;
    if (i1 == -1) {
        return -1;
    }
    for (int i = i1; i < i2; i++) {
        const char* s2 = bip39_suffix[i];
        if (strcmp(s1, s2) == 0) {
            return i;
        }
    }
    return -1;
}

void bip39_set_payload(void* ctx, size_t length, const uint8_t* bytes) {
    if (length > BIP39_BUF_MAX) {
        return;
    }
    context* c = ctx;
    bip39_clear(ctx);
    memcpy(c->buffer, bytes, length);
    bip39_append_checksum(ctx);
}

size_t bip39_words_from_secret(const uint8_t* secret, size_t secret_len, uint16_t* words, size_t max_words_len) {
    if (secret_len % 4 != 0) {
        return 0;
    }
    if (secret_len < 8) {
        return 0;
    }
    if (secret_len > 32) {
        return 0;
    }

    void* ctx = bip39_new_context();

    bip39_set_byte_count(ctx, secret_len);
    bip39_set_payload(ctx, secret_len, secret);

    size_t words_len = bip39_get_word_count(ctx);

    for (int i = 0; i < words_len && i < max_words_len; i++) {
        words[i] = bip39_get_word(ctx, i);
    }

    bip39_dispose_context(ctx);

    return words_len;
}

size_t bip39_mnemonics_from_secret(const uint8_t* secret, size_t secret_len, char* mnemonics, size_t max_mnemonics_len) {
    if(max_mnemonics_len == 0) { return 0; }

    size_t max_words_len = 40;
    uint16_t words[max_words_len];
    size_t words_len = bip39_words_from_secret(secret, secret_len, words, max_words_len);
    if(words_len == 0) {
        return 0;
    }

    char string[300];
    string[0] = '\0';
    for (int i = 0; i < words_len; i++) {
        if (i != 0) {
            strcat(string, " ");
        }
        char mnemonic[20];
        bip39_mnemonic_from_word(words[i], mnemonic);
        strcat(string, mnemonic);
    }
    size_t mnemonics_len = strlen(string);

    if (mnemonics_len > max_mnemonics_len - 1) {
        return 0;
    }
    strcpy(mnemonics, string);

    return mnemonics_len;
}

size_t bip39_words_from_mnemonics(const char* mnemonics, uint16_t* words, size_t max_words_len) {
    const char* p = mnemonics;
    size_t max_buf_len = 16;
    char buf[max_buf_len];

    int words_len = 0;
    while(*p != '\0') {
        int buf_len;
        for(buf_len = 0; *p >= 'a' && *p <= 'z'; buf_len++, p++) {
            if(buf_len < (max_buf_len - 1)) {
                buf[buf_len] = *p;
            } else {
                buf[buf_len] = 0;
            }
        }

        if(buf_len < 15) {
            buf[buf_len] = '\0';
        }

        if(words_len < max_words_len) {
            int16_t w = bip39_word_from_mnemonic(buf);
            if (w < 0) {
                return 0;
            } else {
                words[words_len] = w;
            }
        }

        words_len++;

        while(*p != '\0' && (*p < 'a' || *p > 'z')) {
            p++;
        }
    }
    return words_len;
}

size_t bip39_secret_from_mnemonics(const char* mnemonics, uint8_t* secret, size_t max_secret_len) {
    size_t max_words_len = 30;
    uint16_t words[max_words_len];
    size_t words_len = bip39_words_from_mnemonics(mnemonics, words, max_words_len);
    if (words_len == 0) {
        return 0;
    }
    void* ctx = bip39_new_context();

    bip39_set_word_count(ctx, words_len);
    for(int i = 0; i < words_len; i++) {
        bip39_set_word(ctx, i, words[i]);
    }
    size_t secret_len = bip39_get_byte_count(ctx);
    if(secret_len > max_secret_len) {
        goto fail;
    }
    if(!bip39_verify_checksum(ctx)) {
        goto fail;
    }
    memcpy(secret, bip39_get_bytes(ctx), secret_len);

    bip39_dispose_context(ctx);

    return secret_len;

    fail:
    bip39_dispose_context(ctx);
    return 0;
}

void bip39_seed_from_string(const char* string, uint8_t* seed) {
    sha256_Raw((uint8_t*)string, strlen(string), seed);
}
