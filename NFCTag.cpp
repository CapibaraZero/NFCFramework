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

#include <stdlib.h>
#include <string.h>
#include "NFCTag.hpp"

#define GET_TAG_SIZE(uid_length) uid_length > 4 ? MIFARE_ULTRALIGHT_SIZE : MIFARE_CLASSIC_SIZE
NFCTag::NFCTag(uint8_t *new_data, size_t uid_length)
{
    data = (uint8_t *)malloc(GET_TAG_SIZE(uid_length));
    memcpy(data, new_data, GET_TAG_SIZE(uid_length));
    uid = (uint8_t *)malloc(uid_length * sizeof(uint8_t));
    memcpy(uid, data, uid_length);
    if (uid_length > 4)
        ultralight = true;
}

NFCTag::NFCTag(uint8_t *new_data, size_t uid_length, size_t pages)
{
    data = (uint8_t *)malloc(GET_TAG_SIZE(uid_length));
    memcpy(data, new_data, GET_TAG_SIZE(uid_length));
    uid = (uint8_t *)malloc(uid_length * sizeof(uint8_t));
    memcpy(uid, data, uid_length);
    ntag = true;
    pages_num = pages;
}

NFCTag::NFCTag(uint8_t *idm, uint8_t *_pmm, uint16_t _sys_code)
{
    uid = (uint8_t *)malloc(8 * sizeof(uint8_t));
    memcpy(uid, idm, 8);
    memcpy(pmm, _pmm, 8);
    sys_code = _sys_code;
    felica = true;
}

NFCTag::NFCTag(uint8_t *idm, uint8_t *_pmm, uint16_t _sys_code, std::map<size_t, uint8_t*> *blocks)
{
    uid = (uint8_t *)malloc(8 * sizeof(uint8_t));
    memcpy(uid, idm, 8);
    memcpy(pmm, _pmm, 8);
    sys_code = _sys_code;
    felica_blocks.insert(blocks->begin(), blocks->end());
    felica = true;
}


void NFCTag::get_block(int index, uint8_t *block)
{
    memcpy(block, &data[index * get_block_size()], sizeof(uint8_t) * get_block_size());
}

void NFCTag::get_atqa(uint8_t *atqa)
{
    memcpy(atqa, ultralight ? &data[9] : &data[7], sizeof(uint8_t) * 2);
}

FelicaSystemCodes NFCTag::get_sys_code()
{
    if (!felica)
        return INVALID;

    switch (sys_code)
    {
    case NDEF:
        return NDEF;
        break;
    case NFC_F:
        return NFC_F;
        break;
    case LITE_S:
        return LITE_S;
        break;
    case SECURE_ID:
        return SECURE_ID;
        break;
    case COMMON_AREA:
        return COMMON_AREA;
        break;
    case PLUG:
        return PLUG;
        break;
    default:
        return INVALID;
        break;
    }
}

void NFCTag::add_block(int pos, uint8_t data[16]) {
    if(!felica)
        return;

    felica_blocks.insert(std::pair<int, uint8_t*>(pos, data));
}