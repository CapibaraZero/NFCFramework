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
#define NTAG203_PAGES 42
#define NTAG213_PAGES 45
#define NTAG215_PAGES 135
#define NTAG216_PAGES 231

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
public:
    NFCFramework(int sck, int miso, int mosi, int ss);
    inline NFCFramework(){nfc.begin();};
    ~NFCFramework();
    bool ready();
    void get_tag_uid(uint8_t *uid, uint8_t length);
    uint8_t *dump_tag(uint8_t key[], size_t *uid_length);
    bool format_mifare();
    inline void printHex(byte *data, uint32_t length) {
        nfc.PrintHex(data, length);
    }
    bool auth_tag(uint8_t *key);
    bool write_tag(size_t block_number, uint8_t *data, uint8_t *key);
    void emulate_tag(uint8_t *data);
    uint8_t *dump_ntag2xx_tag(size_t pages);
    bool write_ntag2xx_page(size_t page, uint8_t *data);
};

#endif
