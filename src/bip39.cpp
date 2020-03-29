#include "bip39.h"
#include <avr/pgmspace.h>
#include <Arduino.h>

Sha256 sha256;

struct Bip39IndexChar {
    uint16_t i;
    char c;
};

const Bip39IndexChar bip39_prefix1[] PROGMEM = {
#include "prefix1.inc"
};

const Bip39IndexChar bip39_prefix2[] PROGMEM = {
#include "prefix2.inc"
};

#include "suffix_strings.inc"

const char* const bip39_suffix[] PROGMEM = {
#include "suffix_array.inc"
};

char 
bip39_lookup(Bip39IndexChar *table, uint8_t length, uint16_t n) {
  uint8_t lo = 0;
  uint8_t hi = length;
  uint8_t mid;
  static Bip39IndexChar m;

  while(lo+1 < hi) {
    mid = (lo + hi) /2;
    memcpy_P(&m, &(table[mid]), sizeof (Bip39IndexChar));
    if(m.i < n) {
        lo = mid;
    } else if (m.i> n) {
        hi = mid;
    } else {
        lo = mid;
        break;
    }
  } 
  memcpy_P (&m, &table[lo], sizeof (Bip39IndexChar));
  return m.c;
}

void
Bip39::loadMnemonic(uint16_t i, char *b)
{
  b[0] = bip39_lookup(bip39_prefix1, PREFIX_1_LEN, i);    
  b[1] = bip39_lookup(bip39_prefix2, PREFIX_2_LEN, i);    
  strcpy_P(b + 2, (char*)pgm_read_word(&(bip39_suffix[i]))); // Necessary casts and dereferencing, just copy.
}

const char *
Bip39::getMnemonic(uint16_t i) {
  loadMnemonic(i, wordBuf);
  return wordBuf;
}

void
Bip39::startSearch() {
  lo = 0;
  hi = 2048;
  mid = (lo + hi)/2;
  loadMnemonic(lo, wordBuf);
  loadMnemonic(mid, wordBufHi);
}

void
Bip39::chooseLow() {
  hi = mid;
  mid = (lo+hi)/2;
  loadMnemonic(mid, wordBufHi);
}

void
Bip39::chooseHigh() {
  lo = mid;
  mid = (lo+hi)/2;
  loadMnemonic(lo, wordBuf);
  loadMnemonic(mid, wordBufHi);
}


// NOTE that there is something fishy here. 
// 25 * 8 = 200 / 11
void
Bip39::setPayloadBytes(uint8_t bytes) {
  payloadBytes = bytes;
  payloadWords = ((uint16_t) bytes * 3 +2) / 4;
}

void
Bip39::setPayloadWords(uint8_t words) {
  payloadWords = words;
  payloadBytes = ((uint16_t) words * 11 - 1) / 8;
}

#define MIN_CHECKSUM_BITS 1

uint8_t *
Bip39::computeChecksum() {
  sha256.init();
  for(uint8_t i=0; i< payloadBytes; i++) {
    sha256.write(buffer[i]);
  }
  return sha256.result();
}

void
Bip39::appendChecksum() {
  uint8_t *res = computeChecksum();
  
  buffer[payloadBytes] = res[0];
  buffer[payloadBytes+1] = res[1];
}

bool 
Bip39::verifyChecksum() const {
  uint8_t checksum_bits =  11 - ((payloadBytes * 8) % 11);
  uint8_t *res = computeChecksum();
  
  uint8_t mask;
  
  if(checksum_bits <= 8) {
    mask = 0xFF << (8-checksum_bits);
    return (buffer[payloadBytes] & mask) == (res[0] & mask);
  } else {
    mask = 0xFF << (16 - checksum_bits);
    return buffer[payloadBytes] == res[0] && (buffer[payloadBytes+1] & mask) == (res[1] & mask);
  }
}


void
Bip39::clear() {
  for(uint16_t i=0; i< BIP39_BUF_MAX; i++) {
    buffer[i] = 0;
  }
  for(uint8_t i=0; i<9; i++) {
    wordBuf[i] = 0;
    wordBufHi[i] = 0;
  }
}

uint16_t 
Bip39::getWord(uint8_t n) const {
  // Get the nth word from the buffer
  uint16_t b = 11*(uint16_t)n;
  uint16_t j = b / 8;
  uint8_t k = 8 - (b % 8);  // number of bits of b[j] that belong to w
  uint8_t up = 11 - k;

  if(j >= BIP39_BUF_MAX) {
    return 0xFFFF;
  }
   
  uint16_t word = ( buffer[j++] << up ) & 0x7FF;
  
  while( j < BIP39_BUF_MAX ) {
    if(up > 8) {
      up = up - 8;
      word |= buffer[j++] << up;
    } else {
      word |= buffer[j++] >> (8-up);
      break;
    }
  }
  return word;
}

void
Bip39::setWord(uint8_t n, uint16_t w) {
  // Set the nth word in the buffer to w
  uint16_t b = 11*(uint16_t)n;
  uint16_t j = b / 8;
  uint8_t k = 8 - (b % 8);
  uint8_t down = 11 - k;

  // mask off upper bits to keep from accidentally
  // polluting other words
  w = w & 0x7FF;
  
  if(j >= BIP39_BUF_MAX) {
    return 0xFFFF;
  }

  // This might be a partial byte,
  // so only set the bits that we are interested in
  buffer[j]   &= ~ (0x7FF >> down);
  buffer[j++] |= (w >> down);
    
  while( j < BIP39_BUF_MAX ) {
    if(down > 8) {
      down = down - 8;
      buffer[j++] = (w >> down);
    } else {
      // again, may be a partial byte
      buffer[j] &= ~(0x7FF << (8-down));
      buffer[j] |= (w << (8-down));	       
      break;
    }
  }
}



