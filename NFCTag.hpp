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

#ifndef NFCTAG_H
#define NFCTAG_H

#include <stdint.h>
#include <map>
#include "nfc_framework.hpp"

class NFCTag
{
private:
    uint8_t *data;
    bool ultralight = false;
    bool ntag = false;
    bool felica = false;
    uint8_t *uid;
    uint8_t *pmm;
    uint16_t sys_code;
    size_t pages_num;
    /*  
        We can't take block position using array index 
        otherwise we would have enormous array with empty block
        so is better to track block information in a map
    */
    std::map<int, uint8_t*> felica_blocks;
    inline size_t get_block_size() { return ntag ? NTAG_PAGE_SIZE : BLOCK_SIZE; }
public:
    NFCTag(uint8_t *new_data, size_t uid_length);
    // Constructor for NTAG
    NFCTag(uint8_t *new_data, size_t uid_length, size_t pages);
    // Constructor for FeliCa
    NFCTag(uint8_t *idm, uint8_t *_pmm, uint16_t _sys_code);
    NFCTag(uint8_t *idm, uint8_t *_pmm, uint16_t _sys_code, std::map<size_t, uint8_t*> *blocks);
    ~NFCTag(){};
    inline uint8_t *get_uid() { return uid; };
    inline uint8_t *get_data() { return data; };
    inline size_t get_data_size() { return sizeof(data); }; // TODO: Drop it
    inline bool is_ultralight() { return ultralight; };
    inline bool is_ntag() { return ntag; }
    void get_block(int index, uint8_t *block);
    inline size_t get_blocks_count() {
        if(ntag)
            return pages_num;
        return ultralight ? MIFARE_ULTRALIGHT_BLOCKS : MIFARE_CLASSIC_BLOCKS;
    };
    inline uint8_t get_bcc() { return ultralight ? 0 : data[5]; };
    inline uint8_t get_sak() { return ultralight ? data[8] : data[6]; };
    void get_atqa(uint8_t *atqa);
    FelicaSystemCodes get_sys_code();
    void add_block(int pos, uint8_t data[16]);
};

#endif
