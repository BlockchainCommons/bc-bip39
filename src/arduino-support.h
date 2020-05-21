#ifndef ARDUINO_SUPPORT_H
#define ARDUINO_SUPPORT_H

#ifdef ARDUINO
#include <Arduino.h>
#include <avr/pgmspace.h>
#define MEMCPY_P(x, y, z) memcpy_P(x, y, z)
#define STRCPY_P(x, y) strcpy_P(x, y)
#define PGM_READ_WORD(x) pgm_read_word(x)
#else
#define PROGMEM
#define MEMCPY_P(x, y, z) memcpy(x, y, z)
#define STRCPY_P(x, y) strcpy(x, y)
#define PGM_READ_WORD(x) (*x)
#endif

#endif /* ARDUINO_SUPPORT_H */
