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

#include <stdlib.h>
#include <string.h>
#include "NFCTag.hpp"

NFCTag::NFCTag(uint8_t *new_data, size_t uid_length) {
    data = new_data;
    uid = (uint8_t *)malloc(uid_length * sizeof(uint8_t));
    memcpy(uid, data, uid_length);
    if(uid_length > 4)
        ultralight = true;
}

NFCTag::NFCTag(uint8_t *new_data, size_t uid_length, size_t pages) {
    data = new_data;
    uid = (uint8_t *)malloc(uid_length * sizeof(uint8_t));
    memcpy(uid, data, uid_length);
    ntag = true;
    pages_num = pages;
}

void NFCTag::get_block(int index, uint8_t *block) {
    memcpy(block, &data[index * get_block_size()], sizeof(uint8_t) * get_block_size());
}

void NFCTag::get_atqa(uint8_t *atqa) {
    memcpy(atqa, ultralight ? &data[9] : &data[7], sizeof(uint8_t) * 2);
}
