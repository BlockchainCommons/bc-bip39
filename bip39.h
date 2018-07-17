#ifndef BIP39_H
#define BIP39_H

#include <inttypes.h>
#include <sha256.h>

#define BIP39_BUF_MAX 40

// This class provides a couple of services related to Bip39 mnemonic sentences
// First, it provides a way to look up english mnemonics by the code word that
// they represent.
// Next, it provides a means to generate a checksum on a sequence of bytes
// and then generate a series of words from that, or it provides you with
// a mechanism to input a sequence of words, verify the checksum and extract
// the original paylaod.

class Bip39 {
  private:
  char wordBuf[9];  
  char wordBufHi[9];

  uint16_t lo;
  uint16_t mid;
  uint16_t hi;
  
  uint8_t payloadBytes = 32;
  uint8_t payloadWords = 24;

  uint8_t buffer[BIP39_BUF_MAX];
  uint8_t *computeChecksum();

  uint8_t currentWord;
  void loadMnemonic(uint16_t i, char *b);
 public:
  Bip39() {}
  const char * getMnemonic(uint16_t n);

  void startSearch();
  void chooseLow();
  void chooseHigh();
  
  const char * getLow() const { return wordBuf; }
  const char * getHigh() const { return wordBufHi; }
  const bool doneSearch() const { return lo == mid; }
  const uint16_t selectedWord() const { return lo; }
  
  void setPayloadBytes(uint8_t bytes);
  void setPayloadWords(uint8_t words);

  uint8_t getPayloadBytes() {return payloadBytes;}
  uint8_t getPayloadWords() {return payloadWords;}

  uint16_t getWord(uint8_t) const;  
  void setWord(uint8_t i, uint16_t word);

  void setPayload(uint8_t length, uint8_t *bytes);
  
  bool verifyChecksum() const;
  void appendChecksum();
  
  const uint8_t* getPayload() const { return buffer; }
  void clear();

};

#endif
