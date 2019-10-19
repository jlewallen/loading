/**
 * This software is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this source code. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LDING_LOADING_H
#define LDING_LOADING_H

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fkb_firmware_t {
    uint32_t flags;
    uint32_t timestamp;
    uint32_t number;
    uint8_t version[16];
    uint32_t binary_size;
    uint32_t data_size;
    uint32_t bss_size;
    uint32_t got_size;
    uint32_t vtor_offset;
    uint32_t got_offset;
    uint8_t name[256];
    uint32_t hash_size;
    uint8_t hash[128];
} fkb_firmware_t;

typedef struct fkb_header_t {
    uint8_t signature[4];
    uint32_t version;
    uint32_t size;
    fkb_firmware_t firmware;
    uint32_t number_symbols;
    uint32_t number_relocations;
} fkb_header_t;

#define FKB_SYMBOL_TYPE_OBJECT     (0)

#define FKB_SYMBOL_TYPE_FUNC       (1)

typedef struct fkb_symbol_t {
    uint32_t type;
    uint32_t size;
    uint32_t address;
    uint8_t  name[24];
} fkb_symbol_t;

typedef struct fkb_relocation_t {
    uint32_t symbol;
    uint32_t offset;
} fkb_relocation_t;

typedef struct fkb_launch_info_t {
    uint32_t upgrading;
} fkb_launch_info_t;

typedef struct fkb_exec_state_t {
    uint32_t *vtor;
    uint32_t *sp;
    uint32_t *entry;
    uint32_t *got;
} fkb_exec_state_t;

#define FKB_EXEC_STATE_OK           (0)
#define FKB_EXEC_STATE_BAD_VTOR    (-1)
#define FKB_EXEC_STATE_BAD_SP      (-2)

uint32_t fkb_verify_exec_state(fkb_header_t *fkbh, fkb_exec_state_t *fkes);

extern fkb_launch_info_t fkb_launch_info;

fkb_header_t *fkb_try_header(void *ptr);

uint32_t fkb_find_and_launch(void *ptr);

uint32_t fkb_try_launch(fkb_header_t *fkbh);

uint32_t fkb_external_printf(const char *str, ...);

uint32_t fkb_external_println(const char *str, ...);

uint32_t fkb_external_vprintf(const char *str, va_list args);

#define FKB_HEADER_SIGNATURE()   ("FKB")

#ifdef __cplusplus
}
#endif

#endif // LDING_LOADING_H
