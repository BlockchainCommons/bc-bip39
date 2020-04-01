#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include "../src/bc-bip39.h"
#include "test-utils.h"

static bool _test_get_mnemonic(int16_t i, const char* expected) {
    bool result = false;

    void* ctx = bip39_new_context();

    const char* word = bip39_get_mnemonic(ctx, i);
    if(expected == NULL) {
        result = word == NULL;
    } else {
        result = equal_strings(word, expected);
    }

    bip39_dispose_context(ctx);

    return result;
}

static void test_get_mnemonic() {
    assert(_test_get_mnemonic(0, "abandon"));
    assert(_test_get_mnemonic(1018, "leg"));
    assert(_test_get_mnemonic(1024, "length"));
    assert(_test_get_mnemonic(2047, "zoo"));
    assert(_test_get_mnemonic(2048, NULL));
}

bool _test_get_index(const char* s, int16_t expected) {
    int16_t c = bip39_get_index(s);
    return c == expected;
}

static void test_get_index() {
    assert(_test_get_index("abandon", 0));
    assert(_test_get_index("leg", 1018));
    assert(_test_get_index("length", 1024));
    assert(_test_get_index("zoo", 2047));
    assert(_test_get_index("aaa", -1));
    assert(_test_get_index("zzz", -1));
    assert(_test_get_index("123", -1));
    assert(_test_get_index("ley", -1));
    assert(_test_get_index("lengthz", -1));
    assert(_test_get_index("zoot", -1));
}

int main() {
    test_get_mnemonic();
    test_get_index();
}
