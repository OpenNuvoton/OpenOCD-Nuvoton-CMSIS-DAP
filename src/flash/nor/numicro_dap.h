/* SPDX-License-Identifier: GPL-2.0-or-later */

/***************************************************************************
 *   Copyright (C) 2023 by Nuvoton Technology Corporation                  *
 *   ccli0 <ccli0@nuvoton.com>                                             *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifndef OPENOCD_FLASH_NOR_NUMICRO_DAP_H
#define OPENOCD_FLASH_NOR_NUMICRO_DAP_H

/* Nuvoton NUMICROM Series register locations */
#define NUMICRO_AHB5_SYS_BASE		0x50000000
#define NUMICRO_AHB4_SYS_BASE		0x40000000

/* Definition for Erase timeout */
#define	TIMEOUT_ERASE				100000

/* Definition for Flash Memory */
#define	SECTOR_SIZE_512		0x00000200
#define	SECTOR_SIZE_2K		0x00000800
#define	SECTOR_SIZE_4K		0x00001000
#define	SECTOR_SIZE_8K		0x00002000

/* flash MAX banks */
#define NUMICRO_DAP_MAX_FLASH_BANKS		2

/* flash bank structs */
struct numicro_dap_flash_bank_type {
	uint32_t base;
	uint32_t size;
};

/* part structs */
struct numicro_dap_cpu_type {
	char *partname;
	uint32_t partid;
	unsigned int flash_type;
	unsigned int n_banks;
	struct numicro_dap_flash_bank_type bank[NUMICRO_DAP_MAX_FLASH_BANKS];
	unsigned int page_size;
};

struct numicro_dap_flash_bank {
	int		probed;
	const struct numicro_dap_cpu_type *cpu;
};

#endif /* OPENOCD_FLASH_NOR_NUMICRO_DAP_H */
