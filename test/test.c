//
//  test.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include "../src/bc-bip39.h"
#include "test-utils.h"
#include <assert.h>
#include <bc-crypto-base/bc-crypto-base.h>
#include <stdio.h>
#include <string.h>

static bool _test_mnemonic_from_word(int16_t word, const char* expected) {
    bool result = false;

    char mnemonic[20];
    bip39_mnemonic_from_word(word, mnemonic);
    if(expected == NULL) {
        result = strlen(mnemonic) == 0;
    } else {
        result = equal_strings(mnemonic, expected);
    }

    return result;
}

static void test_mnemonic_from_word() {
    assert(_test_mnemonic_from_word(0, "abandon"));
    assert(_test_mnemonic_from_word(1018, "leg"));
    assert(_test_mnemonic_from_word(1024, "length"));
    assert(_test_mnemonic_from_word(2047, "zoo"));
    assert(_test_mnemonic_from_word(2048, NULL));
}

bool _test_word_from_mnemonic(const char* s, int16_t expected) {
    int16_t c = bip39_word_from_mnemonic(s);
    return c == expected;
}

static void test_word_from_mnemonic() {
    assert(_test_word_from_mnemonic("abandon", 0));
    assert(_test_word_from_mnemonic("leg", 1018));
    assert(_test_word_from_mnemonic("length", 1024));
    assert(_test_word_from_mnemonic("zoo", 2047));
    assert(_test_word_from_mnemonic("aaa", -1));
    assert(_test_word_from_mnemonic("zzz", -1));
    assert(_test_word_from_mnemonic("123", -1));
    assert(_test_word_from_mnemonic("ley", -1));
    assert(_test_word_from_mnemonic("lengthz", -1));
    assert(_test_word_from_mnemonic("zoot", -1));
}

static void test_seed_from_string() {
    char* rolls = "123456";
    size_t secret_len = 16;
    uint8_t ref_secret[] =
        { 0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0xd3, 0xc2,
        0x9a, 0x3a, 0x62, 0x92, 0x80, 0xe6, 0x86, 0xcf };
    size_t strings_len = 12;
    char* ref_strings[] =
        { "mirror", "reject", "rookie", "talk",
        "pudding", "throw", "happy", "era",
        "myth", "already", "payment", "owner" };
    uint16_t words[] =
    { 1132, 1447, 1502, 1772,
    1385, 1802, 839, 610,
    1172, 57, 1293, 1265 };

    uint8_t seed[BIP39_SEED_LEN];
    bip39_seed_from_string(rolls, seed);
    assert(memcmp(ref_secret, seed, secret_len) == 0);

    void* ctx = bip39_new_context();

    bip39_set_byte_count(ctx, secret_len);
    bip39_set_payload(ctx, secret_len, seed);

    for (int i = 0; i < strings_len; ++i) {
        char* ref_string = ref_strings[i];
        uint16_t word = bip39_get_word(ctx, i);
        assert(word == words[i]);
        const char* string = bip39_get_mnemonic(ctx, word);
        assert(strcmp(string, ref_string) == 0);
    }

    bip39_dispose_context(ctx);
}

static bool _test_mnemonics_from_secret(const char* secret_hex, const char* expected_mnemonics) {
    uint8_t* secret_data;
    size_t secret_len = hex_to_data(secret_hex, &secret_data);
    size_t max_mnemonics_len = 300;
    char mnemonics[max_mnemonics_len];
    size_t mnemonics_len = bip39_mnemonics_from_secret(secret_data, secret_len, mnemonics, max_mnemonics_len);
    bool result;
    if(expected_mnemonics == NULL) {
        result = mnemonics_len == 0;
    } else {
        result = equal_strings(mnemonics, expected_mnemonics);
    }
    free(secret_data);
    return result;
}

static void test_mnemonics_from_secret() {
    assert(_test_mnemonics_from_secret("baadf00dbaadf00d", "rival hurdle address inspire tenant alone"));
    assert(_test_mnemonics_from_secret("baadf00dbaadf00dbaadf00dbaadf00d", "rival hurdle address inspire tenant almost turkey safe asset step lab boy"));
    assert(_test_mnemonics_from_secret("baadf00dbaadf00dbaadf00dbaadf00dff", NULL));
    assert(_test_mnemonics_from_secret("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"));
}

static bool _test_secret_from_mnemonics(const char* mnemonics, const char* expected_secret_hex) {
    uint8_t* expected_secret;
    size_t expected_secret_len = hex_to_data(expected_secret_hex, &expected_secret);

    size_t max_secret_len = 32;
    uint8_t secret[max_secret_len];
    size_t secret_len = bip39_secret_from_mnemonics(mnemonics, secret, max_secret_len);

    bool result = equal_uint8_buffers(secret, secret_len, expected_secret, expected_secret_len);

    free(expected_secret);

    return result;
}

static void test_secret_from_mnemonics() {
    assert(_test_secret_from_mnemonics("rival hurdle address inspire tenant alone", "baadf00dbaadf00d"));
    assert(_test_secret_from_mnemonics("rival hurdle address inspire tenant almost turkey safe asset step lab boy", "baadf00dbaadf00dbaadf00dbaadf00d"));
    assert(_test_secret_from_mnemonics("legal winner thank year wave sausage worth useful legal winner thank yellow", "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"));
}

int main() {
    test_mnemonic_from_word();
    test_word_from_mnemonic();
    test_seed_from_string();
    test_mnemonics_from_secret();
    test_secret_from_mnemonics();
}
