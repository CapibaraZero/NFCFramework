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

#include "nfc_framework.hpp"
#include "Arduino.h"

// Debug macros
#define SERIAL_DEVICE Serial0
#define LOG_ERROR(reason) SERIAL_DEVICE.printf("\e[31m%s\e[0m", reason)
#define LOG_SUCCESS(reason) SERIAL_DEVICE.printf("\e[32m%s\e[0m", reason)
#define LOG_INFO(reason) SERIAL_DEVICE.printf("%s", reason)

NFCFramework::NFCFramework(int sck, int miso, int mosi, int ss) // SPI
{
    nfc = Adafruit_PN532(sck, miso, mosi, ss);
    nfc.begin();
}

NFCFramework::~NFCFramework()
{
    Wire.end();
}

bool NFCFramework::ready()
{
    return nfc.getFirmwareVersion();
}

void NFCFramework::get_tag_uid(uint8_t *uid, uint8_t length)
{
    nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &length);
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

uint8_t *NFCFramework::dump_tag(uint8_t key[], size_t *uid_length)
{
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
                if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, currentblock, 1, key))
                {
                    if (nfc.mifareclassic_ReadDataBlock(currentblock, block))
                    {
                        // Read successful
                        memcpy(&all_blocks[currentblock * 16], block, sizeof(block)); // Store block in all_blocks array
                        print_block(currentblock, &all_blocks[currentblock * 16]);    // Print block
                    }
                    else
                    {
                        print_error(currentblock, "Unable to read\n");
                    }
                }
                else
                {
                    print_error(currentblock, "Unable to authenticate.\n");
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
                    print_error(currentblock, "Unable to read\n");
                }
            }
        }
    }

    return all_blocks;
}

bool NFCFramework::auth_tag(uint8_t *key)
{
    uint8_t uid[7] = {0}; // Buffer to store the returned UID
    uint8_t uidLength;    // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 0, 1, key))
	{
            SERIAL_DEVICE.println("Key found!");
            return true;
        }
    }
    SERIAL_DEVICE.println("Key not found!");
    return false;
}

bool NFCFramework::format_mifare()
{
    uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0}; // Buffer to store the returned UID
    uint8_t uidLength;                     // Length of the UID (4 or 7 bytes depending on ISO14443A card type)

    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        return nfc.mifareclassic_FormatNDEF();
    }
    return false;
}

bool NFCFramework::write_tag(size_t block_number, uint8_t *data, uint8_t *key)
{
    uint8_t uid[7] = {0}; // Buffer to store the returned UID
    uint8_t uidLength;    // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength))
    {
        if (nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 0, 1, key))
        {
            return nfc.mifareclassic_WriteDataBlock(block_number, data);
        }
    }
    return false;
}

// TODO: Implement emulator
void NFCFramework::emulate_tag(uint8_t *data)
{
    // To be done
}

uint8_t *NFCFramework::dump_ntag2xx_tag(size_t pages) {
  uint8_t uid[7] = { 0 };  // Buffer to store the returned UID
  uint8_t uidLength;                        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  uint8_t *tag_data = (uint8_t *) malloc(pages * sizeof(uint8_t));	// Container for all sectors

  if(nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength)) {
    SERIAL_DEVICE.println("Found an ISO14443A card");
    SERIAL_DEVICE.print("  UID Length: ");Serial.print(uidLength, DEC);Serial.println(" bytes");
    SERIAL_DEVICE.print("  UID Value: ");
    nfc.PrintHex(uid, uidLength);
    SERIAL_DEVICE.println("");
    if(uidLength != 7) {
      LOG_INFO("Not a ntag2xx");
      return NULL;
    }else {
      uint8_t data[32];

      LOG_INFO("Probably a ntag2xx tag");
      for (uint8_t i = 0; i < pages; i++)
      {
	if(nfc.ntag2xx_ReadPage(i, data)) {
	  // Read successfully
	  memcpy(&tag_data[i], data, sizeof(data));
	}else {
	  LOG_ERROR("Failed to read page");
	}
      } 
    }
  }

  return tag_data;
}

bool NFCFramework::write_ntag2xx_page(size_t page, uint8_t *data){
  uint8_t uid[7] = { 0 };  // Buffer to store the returned UID
  uint8_t uidLength;       // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  
  if(nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength)) {
    SERIAL_DEVICE.println("Found an ISO14443A card");
    SERIAL_DEVICE.print("  UID Length: ");Serial.print(uidLength, DEC);Serial.println(" bytes");
    SERIAL_DEVICE.print("  UID Value: ");
    nfc.PrintHex(uid, uidLength);
    SERIAL_DEVICE.println("");
    if(uidLength != 7) {
      LOG_INFO("Not a ntag2xx");
    }else {
      LOG_INFO("Probably a ntag2xx tag");
      return nfc.ntag2xx_WritePage(page, data);
    }
  }
  return false; 
}