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

#include "nfc_framework.hpp"
#include "Arduino.h"
#include <map>

NFCFramework::~NFCFramework()
{
    LOG_INFO("Deleting NFC Framework");
}

bool NFCFramework::ready()
{
    return nfc.getFirmwareVersion();
}

int NFCFramework::get_tag_uid(uint8_t *uid, uint8_t length)
{
    return nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &length);
}

int NFCFramework::get_tag_uid(uint8_t *uid, uint8_t *length)
{
    LOG_INFO("Getting NFC Framework");
    return nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, length);
}

int NFCFramework::get_tag_uid(uint8_t *uid, uint8_t *length, uint16_t *atqa, uint8_t *sak)
{
    LOG_INFO("Getting NFC Framework");
    return nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, length, atqa, sak);
}

void NFCFramework::print_block(int currentblock, uint8_t *block)
{
    SERIAL_DEVICE.print("Block ");
    SERIAL_DEVICE.print(currentblock, DEC);
    if (currentblock < 10)
    {
        SERIAL_DEVICE.print("  ");
    }
    else
    {
        SERIAL_DEVICE.print(" ");
    }
    nfc.PrintHexChar(block, BLOCK_SIZE);
}

void NFCFramework::print_error(int block_number, const char *reason)
{
    SERIAL_DEVICE.printf("Block %i %s", block_number, reason);
}

uint8_t *NFCFramework::prepare_tag_store(uint8_t *tag_data, size_t tag_size)
{
    tag_data = (uint8_t *)malloc(sizeof(uint8_t) * tag_size);
    memset(tag_data, 0, sizeof(uint8_t) * tag_size); // Initialize to 0
    return tag_data;
}

bool NFCFramework::read_block(uint8_t block, uint8_t *key, KeyType key_type, uint8_t *out) {
    Serial.println("Read1");
    uint8_t uid[7] = {0};            // Buffer to store the returned UID
    uint8_t uidLength = 0;           // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    Serial.print("Block: ");
    Serial.println(block);
    Serial.print("Key: ");
    for (size_t i = 0; i < 6; i++)
    {
        Serial.print(key[i], HEX);
    }
    Serial.println();
    
    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
            Serial.println("Read12");
        if(nfc.mifareclassic_AuthenticateBlock(uid, uidLength, block, key_type, key)) {
            Serial.println("Authentication successful!");   
            return nfc.mifareclassic_ReadDataBlock(block, out);
        } else {
            Serial.println("Authentication failed!");
            return false;
        }
    }
    return false;
};

uint8_t *NFCFramework::dump_tag(uint8_t key[], size_t *uid_length, DumpResult *result)
{
    // unreadable_sectors = 0;
    // unauthenticated_sectors = 0;
    result->unreadable = 0;
    result->unauthenticated = 0;
    uint8_t uid[7] = {0};            // Buffer to store the returned UID
    uint8_t uidLength = 0;           // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    uint8_t block[BLOCK_SIZE] = {0}; // Array to store each block during reads
    uint8_t *all_blocks;             // Whole tag data

    // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
    // 'uid' will be populated with the UID, and uidLength will indicate
    // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)

    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        *uid_length = uidLength;
        // Display some basic information about the card
        SERIAL_DEVICE.printf("Found a new card!\n UID Length: %i\n UID Value: ", uidLength);
        nfc.PrintHex(uid, uidLength);
        SERIAL_DEVICE.println("");

        if (MIFARE_IS_ULTRALIGHT(uidLength))
        {
            SERIAL_DEVICE.println("Found Mifare Ultralight card!\n");
            all_blocks = prepare_tag_store(all_blocks, MIFARE_ULTRALIGHT_SIZE);
        }
        else
        {
            SERIAL_DEVICE.println("Found Mifare Classic card!\n");
            all_blocks = prepare_tag_store(all_blocks, MIFARE_CLASSIC_SIZE);
        }

        for (size_t currentblock = 0;
             currentblock < (MIFARE_IS_ULTRALIGHT(uidLength) ? MIFARE_ULTRALIGHT_BLOCKS : MIFARE_CLASSIC_BLOCKS);
             currentblock++)
        {
            SERIAL_DEVICE.print("------------------------Sector ");
            SERIAL_DEVICE.print(currentblock / 4, DEC);
            SERIAL_DEVICE.println("-------------------------");
            if (!MIFARE_IS_ULTRALIGHT(uidLength))
            {
                if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, currentblock, 0, key))
                {
                    if (nfc.mifareclassic_ReadDataBlock(currentblock, block))
                    {
                        // Read successful
                        memcpy(&all_blocks[currentblock * 16], block, sizeof(block)); // Store block in all_blocks array
                        print_block(currentblock, &all_blocks[currentblock * 16]);    // Print block
                    }
                    else
                    {
                        result->unreadable++;
                        print_error(currentblock, "Unable to read\n");
                        memset(&all_blocks[currentblock * 16], -1, sizeof(block)); // Store block in all_blocks array
                    }
                }
                else
                {
                    result->unauthenticated++;
                    print_error(currentblock, "Unable to authenticate.\n");
                    memset(&all_blocks[currentblock * 16], -1, sizeof(block)); // Store block in all_blocks array
                };
            }
            else
            {
                if (nfc.mifareultralight_ReadPage(currentblock, block))
                {
                    // Read successful
                    print_block(currentblock, block);                             // Print block
                    memcpy(&all_blocks[currentblock * 16], block, sizeof(block)); // Store block in all_blocks array
                }
                else
                {
                    result->unreadable++;
                    print_error(currentblock, "Unable to read\n");
                }
            }
        }
    }else {
        SERIAL_DEVICE.println("Timeout");
        return NULL;
    }

    return all_blocks;
}

uint8_t* NFCFramework::dump_tag(Key* keys, uint8_t blocks, DumpResult *result)
{
    // unreadable_sectors = 0;
    // unauthenticated_sectors = 0;
    result->unreadable = 0;
    result->unauthenticated = 0;
    uint8_t uid[7] = {0};            // Buffer to store the returned UID
    uint8_t uidLength = 0;           // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    uint8_t block[BLOCK_SIZE] = {0}; // Array to store each block during reads
    uint8_t *all_blocks;             // Whole tag data

    // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
    // 'uid' will be populated with the UID, and uidLength will indicate
    // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)

    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        // *uid_length = uidLength;
        // Display some basic information about the card
        SERIAL_DEVICE.printf("Found a new card!\n UID Length: %i\n UID Value: ", uidLength);
        nfc.PrintHex(uid, uidLength);
        SERIAL_DEVICE.println("");

        if (MIFARE_IS_ULTRALIGHT(uidLength))
        {
            SERIAL_DEVICE.println("Found Mifare Ultralight card!\n");
            all_blocks = prepare_tag_store(all_blocks, MIFARE_ULTRALIGHT_SIZE);
            blocks = MIFARE_ULTRALIGHT_SIZE;
        }
        else
        {
            SERIAL_DEVICE.println("Found Mifare Classic card!\n");
            all_blocks = prepare_tag_store(all_blocks, MIFARE_CLASSIC_SIZE);
        }

        for (size_t currentblock = 0;
             currentblock < blocks;
             currentblock++)
        {
            SERIAL_DEVICE.print("------------------------Sector ");
            SERIAL_DEVICE.print(currentblock / 4, DEC);
            SERIAL_DEVICE.println("-------------------------");
            if (!MIFARE_IS_ULTRALIGHT(uidLength))
            {
                if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, currentblock, keys[currentblock / 4].type, keys[currentblock / 4].data))
                {
                    if (nfc.mifareclassic_ReadDataBlock(currentblock, block))
                    {
                        // Read successful
                        memcpy(&all_blocks[currentblock * 16], block, sizeof(block)); // Store block in all_blocks array
                        print_block(currentblock, &all_blocks[currentblock * 16]);    // Print block
                    }
                    else
                    {
                        result->unreadable++;
                        print_error(currentblock, "Unable to read\n");
                        memset(&all_blocks[currentblock * 16], 0, sizeof(block)); // Store block in all_blocks array
                    }
                }
                else
                {
                    result->unauthenticated++;
                    print_error(currentblock, "Unable to authenticate.\n");
                    memset(&all_blocks[currentblock * 16], 0, sizeof(block)); // Store block in all_blocks array
                };
            }
            else
            {
                if (nfc.mifareultralight_ReadPage(currentblock, block))
                {
                    // Read successful
                    print_block(currentblock, block);                             // Print block
                    memcpy(&all_blocks[currentblock * 16], block, sizeof(block)); // Store block in all_blocks array
                }
                else
                {
                    result->unreadable++;
                    print_error(currentblock, "Unable to read\n");
                }
            }
        }
    }else {
        SERIAL_DEVICE.println("Timeout");
        return NULL;
    }

    return all_blocks;
}

bool NFCFramework::auth_tag(uint8_t *key, uint8_t block_number, KeyType key_type)
{
    uint8_t uid[7] = {0}; // Buffer to store the returned UID
    uint8_t uidLength;    // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, block_number, key_type, key))
        {
            SERIAL_DEVICE.println("Key found!");
            return true;
        }else {
            SERIAL_DEVICE.println("Key not found!");
        }
    }else {
        SERIAL_DEVICE.println("Timeout");
    }
    return false;
}

bool NFCFramework::write_tag(size_t block_number, uint8_t *data, uint8_t key_type, uint8_t *key)
{
    uint8_t uid[7] = {0}; // Buffer to store the returned UID
    uint8_t uidLength;    // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, block_number, key_type, key))
        {
            return nfc.mifareclassic_WriteDataBlock(block_number, data);
        }
    }else {
        SERIAL_DEVICE.println("Timeout");
    }
    return false;
}

// TODO: Implement emulator
void NFCFramework::emulate_tag(uint8_t *data)
{
    // To be done
}

uint8_t *NFCFramework::dump_ntag2xx_tag(size_t pages)
{
    uint8_t uid[7] = {0};                                           // Buffer to store the returned UID
    uint8_t uidLength;                                              // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    uint8_t *tag_data = prepare_tag_store(tag_data, pages * NTAG_PAGE_SIZE); // Container for all sectors

    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        SERIAL_DEVICE.println("Found an ISO14443A card");
        SERIAL_DEVICE.print("  UID Length: ");
        SERIAL_DEVICE.print(uidLength, DEC);
        SERIAL_DEVICE.println(" bytes");
        SERIAL_DEVICE.print("  UID Value: ");
        nfc.PrintHex(uid, uidLength);
        SERIAL_DEVICE.println("");
        if (uidLength != 7)
        {
            LOG_INFO("Not a ntag2xx");
            return NULL;
        }
        else
        {
            uint8_t data[NTAG_PAGE_SIZE];

            LOG_INFO("Probably a ntag2xx tag");
            for (uint8_t i = 0; i < pages; i++)
            {
                // if (nfc.ntag2xx_ReadPage(i, data))
                // {
                //     // Read successfully
                //     memcpy(&tag_data[i * NTAG_PAGE_SIZE], data, sizeof(data));
                // }
                // else
                // {
                //     memset(&tag_data[i * NTAG_PAGE_SIZE], -1, sizeof(data)); // Store block in all_blocks array
                //     LOG_ERROR("Failed to read page");
                // }
            }
        }
    }else {
        SERIAL_DEVICE.println("Timeout");
        return NULL;
    }

    return tag_data;
}

bool NFCFramework::write_ntag2xx_page(size_t page, uint8_t *data)
{
    uint8_t uid[7] = {0}; // Buffer to store the returned UID
    uint8_t uidLength;    // Length of the UID (4 or 7 bytes depending on ISO14443A card type)

    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        SERIAL_DEVICE.println("Found an ISO14443A card");
        SERIAL_DEVICE.print("  UID Length: ");
        Serial.print(uidLength, DEC);
        Serial.println(" bytes");
        SERIAL_DEVICE.print("  UID Value: ");
        nfc.PrintHex(uid, uidLength);
        SERIAL_DEVICE.println("");
        if (uidLength != 7)
        {
            LOG_INFO("Not a ntag2xx");
        }
        else
        {
            LOG_INFO("Probably a ntag2xx tag");
            return nfc.mifareultralight_WritePage(page, data);
        }
    }else {
        SERIAL_DEVICE.println("Timeout");
        return false;
    }
    return false;
}

void NFCFramework::fill_JIS_system_code(uint8_t *out)
{
    int j = 0;
    for (int i = 0xAA00; i < 0xAAFE; i++)
    {
        out[j++] = i;
    }
}

int NFCFramework::felica_polling(uint8_t *idm, uint8_t *pmm, uint16_t *response_code)
{
    int polling_result = nfc.felica_Polling(DEFAULT_SYSTEM_CODE, DEFAULT_REQUEST_CODE, idm, pmm, response_code, 65535);
    if (polling_result < 0)
    {
        LOG_ERROR("Failed to poll with result: ");
        SERIAL_DEVICE.println(polling_result);
    }
    return polling_result;
}

int NFCFramework::felica_polling(uint8_t system_code, uint8_t *idm, uint8_t *pmm, uint16_t *response_code)
{
    int polling_result = nfc.felica_Polling(system_code, DEFAULT_REQUEST_CODE, idm, pmm, response_code, 65535);
    if (polling_result < 0)
    {
        LOG_ERROR("Failed to poll with result: ");
        SERIAL_DEVICE.println(polling_result);
    }
    return polling_result;
}

int NFCFramework::felica_polling(uint8_t system_code, uint8_t request_code, uint8_t *idm, uint8_t *pmm, uint16_t *response_code)
{
    int polling_result = nfc.felica_Polling(system_code, request_code, idm, pmm, response_code, 65535);
    if (polling_result < 0)
    {
        LOG_ERROR("Failed to poll with result: ");
        SERIAL_DEVICE.println(polling_result);
    }
    return polling_result;
}

int NFCFramework::felica_read_without_encryption(uint8_t service_codes_list_length, uint16_t *service_codes, uint8_t block_number, uint16_t *block_list, uint8_t data[][16])
{
    uint8_t _idm[8];
    uint8_t _pmm[8];
    uint16_t sys_code;
    if(felica_polling(_idm, _pmm, &sys_code)) { // Wait for a FeliCa card
        int result = nfc.felica_ReadWithoutEncryption(service_codes_list_length, service_codes, block_number, block_list, data);
        if (result <= 0)
        {
            data = NULL;
            LOG_ERROR("Error during reading. Error: ");
            SERIAL_DEVICE.println(result);
            return result;
        }else {
            LOG_SUCCESS("Data read successfully");
            return result;
        }
    }
    return -1;
}

int NFCFramework::felica_write_without_encryption(uint8_t service_codes_list_length, uint16_t *service_codes, uint8_t block_number, uint16_t *block_list, uint8_t data[][16])
{
    uint8_t _idm[8];
    uint8_t _pmm[8];
    uint16_t sys_code;
    if(felica_polling(_idm, _pmm, &sys_code)) { // Wait for a FeliCa card
        return nfc.felica_WriteWithoutEncryption(service_codes_list_length, service_codes, block_number, block_list, data);
    } else {
        return -1;
    }
}
