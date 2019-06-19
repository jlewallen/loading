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

#include <SEGGER_RTT.h>

typedef struct fkb_header_t {
    uint8_t signature[4];
    uint32_t version;
    uint32_t header_size;
    uint32_t flags;
    uint32_t code_size;
    uint32_t data_size;
    uint32_t bss_size;
} fkb_header_t;

#define debug_prints(f)          SEGGER_RTT_WriteString(0, f)

#define debug_println(f, ...)    SEGGER_RTT_printf(0, f "\n", ## __VA_ARGS__)

#define debug_printf(f, ...)     SEGGER_RTT_printf(0, f, ## __VA_ARGS__)

#define debug_flush()

#endif // LDING_LOADING_H
