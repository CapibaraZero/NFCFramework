/*
 * This file is part of the Capibara zero project(https://capibarazero.github.io/).
 * Copyright (c) 2024 Andrea Canale.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NFCFramework_H
#define NFCFramework_H

#include <Arduino.h>
#include <Wire.h>
#include "Adafruit_PN532.h"
#include <SPI.h>

// Some Mifare definitions
#define MIFARE_CLASSIC_SIZE 1024
#define MIFARE_CLASSIC_BLOCKS 64
#define MIFARE_ULTRALIGHT_SIZE 512
#define MIFARE_ULTRALIGHT_BLOCKS 16
#define MIFARE_IS_ULTRALIGHT(uid_length) (uid_length > 4)
#define BLOCK_SIZE 16   //  Default block size

// Some NFCTAG21xx definitions
#define NTAG_PAGE_SIZE 4
#define NTAG203_PAGES 42
#define NTAG213_PAGES 45
#define NTAG215_PAGES 135
#define NTAG216_PAGES 231
#define NTAG203_RESERVED_PAGES 3
#define NTAG21X_RESERVED_PAGES 6

// FeliCa definitions
#define DEFAULT_SYSTEM_CODE 0xFFFF
#define DEFAULT_REQUEST_CODE 0x01

// Manufacturer codes for FeliCa cards as per Sony documentation
enum FelicaManufacturer {
    ISO18092 = 0x01FE,
    TYPE3 = 0x02FE,
    PLUG_LITE = 0x03FE,
    STANDARD = 0x04FE,	// First digit is random
    UNREGISTERED = 0x05FE
};

// System codes for FeliCa cards as per Sony documentation
enum FelicaSystemCodes {
    INVALID = 0xFFFF,
    NDEF = 0x12FC,
    NFC_F = 0x4000,
    LITE_S = 0x88B4,
    SECURE_ID = 0x957A,
    COMMON_AREA = 0xFE00,
    PLUG = 0xFEE1
};

typedef struct DumpResult{
    uint8_t unreadable = 0;
    uint8_t unauthenticated = 0;
} DumpResult;

typedef enum KeyType {
    KEY_A,
    KEY_B
} KeyType;

typedef struct Key {
    KeyType type;
    uint8_t data[6];
} Key;
typedef struct TagType {
    const char *name;
    uint16_t atqa;
    uint8_t sak;
    uint8_t uid_length;
    uint8_t blocks;
} TagType;

#define MIFARE_CLASSIC_1K (TagType){"Mifare Classic 1K", 0x04, 0x08, 4, 64}
// #define MIFARE_CLASSIC_4K (TagType){0x04, 0x03, 16, 264 }
#define MIFARE_MINI (TagType){"Mifare Mini",0x04, 0x09, 4, 20}

// Debug macros
#ifdef ARDUINO_NANO_ESP32
#define SERIAL_DEVICE Serial
#else
#define SERIAL_DEVICE Serial0
#endif

#define LOG_ERROR(reason) SERIAL_DEVICE.printf("\e[31m%s\e[0m", reason)
#define LOG_SUCCESS(reason) SERIAL_DEVICE.printf("\e[32m%s\e[0m", reason)
#define LOG_INFO(reason) SERIAL_DEVICE.printf("%s", reason)

class NFCFramework
{
private:
    Adafruit_PN532 *nfc;
    void print_block(int currentblock, uint8_t *block);
    void print_error(int block_number, const char *reason);
    uint8_t *prepare_tag_store(uint8_t *tag_data, size_t tag_size); 

    // Create JIS system code(0xAA00 to 0xAAFE) dynamically to save some memory
    void fill_JIS_system_code(uint8_t *out);
public:
    // NFCFramework(int sck, int miso, int mosi, int ss);
    NFCFramework(uint8_t sck, uint8_t miso, uint8_t mosi, uint8_t ss){
        nfc = new Adafruit_PN532(sck, miso, mosi, ss);
        LOG_INFO("Init NFC Framework");
        nfc->begin();
        nfc->SAMConfig();
    }
    NFCFramework(uint8_t irq, uint8_t rst){
        nfc = new Adafruit_PN532(irq, rst);
        LOG_INFO("Init NFC Framework");
        nfc->begin();
        nfc->SAMConfig();
    }
    ~NFCFramework();
    bool ready();
    void power_down() {
        nfc->reset();
        nfc->begin();
        nfc->SAMConfig();
    }
    void printHex(byte *data, uint32_t length) {
    for (uint8_t i = 0; i < length; i++) {
        if (data[i] < 0x10) {
            LOG_INFO(" 0");
        } else {
            LOG_INFO(' ');
        }
        SERIAL_DEVICE.print(data[i], HEX);
    }
    } 
    static TagType lookup_tag(uint16_t atqa, uint8_t sak, uint8_t uid_len) {
        if (atqa == 0x04 && sak == 0x08 && uid_len == MIFARE_CLASSIC_1K.uid_length) {
            return MIFARE_CLASSIC_1K;
        } else if (atqa == 0x04 && sak == 0x09 && uid_len == MIFARE_MINI.uid_length) {
            return MIFARE_MINI;
        } else {
            return (TagType){0, 0, 0, 20};
        }
    }
    // Generic ISO14443A functions
    int get_tag_uid(uint8_t *uid, uint8_t length);
    int get_tag_uid(uint8_t *uid, uint8_t *length);
    int get_tag_uid(uint8_t *uid, uint8_t *length, uint16_t *atqa, uint8_t *sak);

    // Mifare functions
    bool auth_tag(uint8_t *key, uint8_t block_number, KeyType key_type);
    bool write_tag(size_t block_number, uint8_t *data, uint8_t key_type, uint8_t *key);
    void emulate_tag(uint8_t *data);
    
    bool read_block(uint8_t block, uint8_t *key, KeyType key_type, uint8_t *out);
    // uint8_t *dump_tag(uint8_t key[], size_t *uid_length);
    uint8_t* dump_tag(uint8_t key[], size_t *uid_length, DumpResult *result);
    uint8_t* dump_tag(Key *key, uint8_t blocks, DumpResult *result);

    // NFCTAG21xx functions
    uint8_t *dump_ntag2xx_tag(size_t pages);
    bool write_ntag2xx_page(size_t page, uint8_t *data);
    
    // FeliCa functions
    int felica_polling(uint8_t *idm, uint8_t *pmm, uint16_t *response_code);
    int felica_polling(uint8_t system_code, uint8_t *idm, uint8_t *pmm, uint16_t *response_code);
    int felica_polling(uint8_t system_code, uint8_t request_code ,uint8_t *idm, uint8_t *pmm, uint16_t *response_code);
    int felica_read_without_encryption(uint8_t service_codes_list_length, uint16_t *service_codes, uint8_t block_number, uint16_t *block_list, uint8_t data[][16]);
    int felica_write_without_encryption(uint8_t service_codes_list_length, uint16_t *service_codes, uint8_t block_number, uint16_t *block_list, uint8_t data[][16]);
    void felica_release() { nfc->felica_Release(); };
};

#endif
