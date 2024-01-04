/*
 * This file is part of the Capibara zero project(https://capibarazero.github.io/).
 * Copyright (c) 2023 Andrea Canale.
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

#include <Adafruit_PN532.h>
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
#define DEFAULT_REQUEST_CODE 0xFF

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
    NDEF = 0x12FC,
    NFC_F = 0x4000,
    LITE_S = 0x88B4,
    SECURE_ID = 0x957A,
    COMMON_AREA = 0xFE00,
    PLUG = 0xFEE1
};



class NFCFramework
{
private:
    int sck;
    int miso;
    int mosi;
    int ss;
    Adafruit_PN532 nfc = Adafruit_PN532(PN532_IRQ_PIN, PN532_RST_PIN);  // I2C pins defined by build_flags
    void print_block(int currentblock, uint8_t *block);
    void print_error(int block_number, const char *reason);
    uint8_t *prepare_tag_store(uint8_t *tag_data, size_t tag_size); 

    // Create JIS system code(0xAA00 to 0xAAFE) dynamically to save some memory
    void fill_JIS_system_code(uint8_t *out);
public:
    NFCFramework(int sck, int miso, int mosi, int ss);
    NFCFramework(){nfc.begin();};
    ~NFCFramework();
    bool ready();
    void printHex(byte *data, uint32_t length) {
        nfc.PrintHex(data, length);
    } 
    
    // Generic ISO14443A functions
    int get_tag_uid(uint8_t *uid, uint8_t length);
    int get_tag_uid(uint8_t *uid, uint8_t *length);

    // Mifare functions
    bool auth_tag(uint8_t *key);
    bool write_tag(size_t block_number, uint8_t *data, uint8_t *key);
    void emulate_tag(uint8_t *data);
    bool format_mifare();
    uint8_t *dump_tag(uint8_t key[], size_t *uid_length); 

    // NFCTAG21xx functions
    uint8_t *dump_ntag2xx_tag(size_t pages);
    bool write_ntag2xx_page(size_t page, uint8_t *data);
    
    // FeliCa functions
    int felica_polling(uint8_t *idm, uint8_t *pmm, uint16_t *response_code);
    int felica_polling(uint8_t system_code, uint8_t *idm, uint8_t *pmm, uint16_t *response_code);
    int felica_polling(uint8_t system_code, uint8_t request_code ,uint8_t *idm, uint8_t *pmm, uint16_t *response_code);
    void felica_request_response(uint8_t *out);
    void felica_request_service(uint8_t node_number, uint16_t *node_codes, uint16_t *key_version);
    void felica_request_system_code(uint8_t *num_sys_code, uint16_t *sys_code_list);
    void felica_read_without_encryption(uint8_t service_codes_list_length, uint16_t *service_codes, uint8_t block_number, uint16_t *block_list, uint8_t data[][16]);
    int felica_write_without_encryption(uint8_t service_codes_list_length, uint16_t *service_codes, uint8_t block_number, uint16_t *block_list, uint8_t data[][16]);
    void felica_release() { nfc.felica_Release(); };
};

#endif
