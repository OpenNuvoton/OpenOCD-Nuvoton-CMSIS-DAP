// SPDX-License-Identifier: GPL-2.0-or-later

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "numicrom23.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/armv7m.h>

#include <target/image.h>

/* Definition NUMICROM23 Flash Memory Address */
#define NUMICROM23_APROM_BASE		0x00000000
#define NUMICROM23_LDROM_BASE		0x0F100000

/* Definition NUMICROM23 Flash Memory Type */
#define NUMICROM23_FLASH_TYPE_M2L31	0x00000000


#define NUMICROM23_BANKS(aprom_size, ldrom_size) \
	.flash_type = NUMICROM23_FLASH_TYPE_M2L31, \
	.n_banks = 2, \
	{ {NUMICROM23_APROM_BASE, (aprom_size)}, {NUMICROM23_LDROM_BASE, (ldrom_size)} }

static const struct numicrom23_cpu_type numicrom23_parts[] = {
	/*PART NO*/			/*PART ID*/		/*Banks*/
	/* M2L31 Series */
	{"M2L31",		0x01d23140,		NUMICROM23_BANKS(512 * 1024, 8 * 1024)},
	{"M2L31FPGA",	0xffffffff,		NUMICROM23_BANKS(512 * 1024, 8 * 1024)},
};

/* Definition for static functions */
static int numicrom23_get_cpu_type(struct target *target, const struct numicrom23_cpu_type **cpu);
static int numicrom23_get_flash_size(struct flash_bank *bank,
									const struct numicrom23_cpu_type *cpu,
									uint32_t *flash_size);

/**
 * @brief	"flash bank" Command
 * @date	February, 2023
 * @note	[Usage]	flash bank $_FLASHNAME numicrom23
 *					<Address> <size> <ChipWidth> <BusWidth> <Target> <Type>
 *						<Address>	: Flash memory base address
 *						<Size>		: Flash memory size
 *						<ChipWidth>	: Chip width in byte (Not use)
 *						<BusWidth>	: Bus width in byte (Not use)
 *						<Target>	: Target device (***.cpu)
 *						<Type>		: Write control type
 * @param
 * @return	int			ERROR_OK or the non-zero
 **/
FLASH_BANK_COMMAND_HANDLER(numicrom23_flash_bank_command)
{
	struct numicrom23_flash_bank	*flash_bank_info;

	flash_bank_info = malloc(sizeof(struct numicrom23_flash_bank));
	if (!flash_bank_info) {
		LOG_ERROR("NuMicro flash driver: Out of memory");
		return ERROR_FAIL;
	}

	memset(flash_bank_info, 0, sizeof(struct numicrom23_flash_bank));

	bank->driver_priv = flash_bank_info;
	flash_bank_info->probed	= 0;

	return ERROR_OK;
}

static int numicrom23_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	return ERROR_OK;
}

static int numicrom23_write(struct flash_bank *bank, const uint8_t *buffer, uint32_t offset, uint32_t count)
{
	int	result = ERROR_OK;
	struct target *target = bank->target;
	struct working_area	*algorithm = NULL;
	struct working_area	*source	= NULL;
	struct armv7m_algorithm	armv7m_info;

	struct reg_param reg_params[5];

	uint32_t remain_size = 0;
	uint32_t buffer_size = 0;
	uint32_t write_address = 0;
	uint32_t write_size	= 0;
	uint8_t	*write_data	= 0;

	uint32_t algorithm_init_entry_offset = 0;
	uint32_t algorithm_programpage_entry_offset = 0;
	uint32_t algorithm_lr = 0;

	static const uint32_t numicrom23_write_code[] = {
	0xE00ABE00,
	0xb087b5b0, 0x460c4613, 0x90054605, 0x92039104, 0x21594833, 0x21166001, 0x21886001, 0x68006001,
	0x93022801, 0x95009401, 0xe7ffd003, 0x90062001, 0x482ce052, 0x4a2c6801, 0x60014311, 0x6801482b,
	0x43112204, 0xe7ff6001, 0x68004829, 0x40082150, 0xd0012850, 0xe7f7e7ff, 0x21694826, 0x68006001,
	0x40082129, 0xd0032829, 0x2001e7ff, 0xe0339006, 0x68004821, 0x7100f240, 0xf2404008, 0x42881100,
	0xe7ffd018, 0x481ce7ff, 0x21016800, 0xd0014208, 0xe7f8e7ff, 0x68014819, 0x43912207, 0x43112201,
	0xe7ff6001, 0x68004814, 0x42082101, 0xe7ffd001, 0xe7ffe7f8, 0x68014812, 0x43912207, 0x43112206,
	0x48106001, 0x220f6801, 0x60014391, 0x2103480e, 0x20006001, 0xe7ff9006, 0xb0079806, 0x46c0bdb0,
	0x40000100, 0x40000200, 0x00040004, 0x40000204, 0x40000250, 0x4000c000, 0x400001fc, 0x400001f8,
	0x40000210, 0x40000220, 0x4000c04c, 0x4601b082, 0x91009001, 0x4807e7ff, 0x21016800, 0xd0014208,
	0xe7f8e7ff, 0x68014804, 0x43912201, 0x20006001, 0x4770b002, 0x4000c040, 0x4000c000, 0x4601b082,
	0x20009001, 0xb0029100, 0x46c04770, 0x4601b084, 0x91009002, 0x481be7ff, 0x21016800, 0xd0014208,
	0xe7f8e7ff, 0x68014818, 0x43112240, 0x98026001, 0x60084916, 0x49174816, 0x48176001, 0x60012122,
	0x21014816, 0xf3bf6001, 0xe7ff8f6f, 0x6800480d, 0x42082101, 0xe7ffd001, 0x480be7f8, 0x90016800,
	0x7800a801, 0x28000640, 0xe7ffd506, 0x49069801, 0x20016008, 0xe0029003, 0x90032000, 0x9803e7ff,
	0x4770b004, 0x4000c040, 0x4000c000, 0x4000c004, 0x4000c008, 0x0055aa03, 0x4000c00c, 0x4000c010,
	0xb088b580, 0x4603460a, 0x91059006, 0x90042000, 0x93009201, 0x9804e7ff, 0x42889905, 0xe7ffd222,
	0x99049806, 0x58400089, 0x98039003, 0x050921ff, 0x21794008, 0x42880549, 0xe7ffd110, 0x490c9803,
	0x90031840, 0xf7ff9803, 0x9002ff91, 0x28009802, 0xe7ffd003, 0x90079802, 0xe7ffe007, 0x1c409804,
	0xe7d89004, 0x90072000, 0x9807e7ff, 0xbd80b008, 0xf0e00000, 0xb088b5b0, 0x460c4613, 0x90064605,
	0x92049105, 0x7800a806, 0x28000780, 0x94019302, 0xd0039500, 0x2001e7ff, 0xe08d9007, 0x1cc09805,
	0x43882103, 0xe7ff9005, 0x68004845, 0x42082101, 0xe7ffd001, 0x4843e7f8, 0x22406801, 0x60014311,
	0x9805e7ff, 0xd0742800, 0x483fe7ff, 0x60012100, 0x212f483e, 0x483e6001, 0x60012101, 0x8f6ff3bf,
	0x4837e7ff, 0x21016800, 0xd0014208, 0xe7f8e7ff, 0x68004834, 0xa8039003, 0x06407800, 0xd5062800,
	0x9803e7ff, 0x6008492f, 0x90072001, 0x9806e054, 0x6008492d, 0x68009804, 0x6008492e, 0x2127482b,
	0x482b6001, 0x60012101, 0x8f6ff3bf, 0x4824e7ff, 0x21016800, 0xd0014208, 0xe7f8e7ff, 0x68004821,
	0xa8039003, 0x06407800, 0xd5062800, 0x9803e7ff, 0x6008491c, 0x90072001, 0x9806e02e, 0x6008491a,
	0x2121481a, 0x481a6001, 0x60012101, 0x8f6ff3bf, 0x4813e7ff, 0x21016800, 0xd0014208, 0xe7f8e7ff,
	0x68004810, 0xa8039003, 0x06407800, 0xd5062800, 0x9803e7ff, 0x6008490b, 0x90072001, 0x9806e00c,
	0x90061d00, 0x1d009804, 0x98059004, 0x90051f00, 0x2000e787, 0xe7ff9007, 0xb0089807, 0x46c0bdb0,
	0x4000c040, 0x4000c000, 0x4000c004, 0x4000c00c, 0x4000c010, 0x4000c008, 0xb088b5b0, 0x460c4613,
	0x90064605, 0x92049105, 0x7800a806, 0x28000780, 0x94019302, 0xd0039500, 0x9806e7ff, 0xe04b9007,
	0x1cc09805, 0x43882103, 0xe7ff9005, 0x68004824, 0x42082101, 0xe7ffd001, 0x4822e7f8, 0x22406801,
	0x60014311, 0x21004820, 0xe7ff6001, 0x28009805, 0xe7ffd02f, 0x491d9806, 0x481d6008, 0x60012101,
	0x8f6ff3bf, 0x4816e7ff, 0x21016800, 0xd0014208, 0xe7f8e7ff, 0x68004813, 0xa8039003, 0x06407800,
	0xd5042800, 0x9803e7ff, 0x6008490e, 0x4811e011, 0x99046800, 0x42886809, 0xe7ffd001, 0x9806e009,
	0x90061d00, 0x1d009804, 0x98059004, 0x90051f00, 0x9806e7cc, 0xe7ff9007, 0xb0089807, 0x46c0bdb0,
	0x4000c040, 0x4000c000, 0x4000c00c, 0x4000c004, 0x4000c010, 0x4000c008, 0x00000000
	};

	/* Get working area for code */
	result = target_alloc_working_area(target,
										sizeof(numicrom23_write_code),
										&algorithm);
	if (result != ERROR_OK) {
		LOG_DEBUG("target_alloc_working_area() = %d\n", result);
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	/* Transfer write program to RAM */
	result = target_write_buffer(target,
								algorithm->address,
								sizeof(numicrom23_write_code),
								(const uint8_t *)numicrom23_write_code);
	if (result != ERROR_OK) {
		LOG_DEBUG("target_write_buffer() = %d\n", result);
		target_free_working_area(target, algorithm);
		return result;
	}

	/* Get working area for data */
	buffer_size	= 64 * 1024;
	result		= ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	while (result != ERROR_OK) {
		result = target_alloc_working_area_try(target, buffer_size, &source);
		if (result == ERROR_OK)
			break;

		buffer_size /= 2;
		if (buffer_size < 256) {
			LOG_DEBUG("target_alloc_working_area_try() = %d\n", result);
			target_free_working_area(target, algorithm);
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
	}

	algorithm_init_entry_offset = 0x5;
	algorithm_lr = 0x20000001;

	init_reg_param(&reg_params[0], "r0", 32, PARAM_OUT);    /* faddr */
	init_reg_param(&reg_params[1], "sp", 32, PARAM_OUT);    /* update SP */
	init_reg_param(&reg_params[2], "lr", 32, PARAM_OUT);    /* update LR */

	buf_set_u32(reg_params[0].value, 0, 32, 0);
	buf_set_u32(reg_params[1].value, 0, 32, algorithm->address + target->working_area_size);
	buf_set_u32(reg_params[2].value, 0, 32, algorithm_lr);

	armv7m_info.common_magic	= ARMV7M_COMMON_MAGIC;
	armv7m_info.core_mode		= ARM_MODE_THREAD;

	result = target_run_algorithm(target, 0, NULL, 3, reg_params,
									algorithm->address + algorithm_init_entry_offset, 0, 100000, &armv7m_info);
	if (result != ERROR_OK) {
		LOG_ERROR("Error executing NuMicro Flash init algorithm");
		result = ERROR_FLASH_OPERATION_FAILED;
	}

	// ProgramPage
	algorithm_programpage_entry_offset = 0x259;
	algorithm_lr = 0x20000001;

	init_reg_param(&reg_params[0], "r0", 32, PARAM_OUT);    /* faddr */
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);    /* number of words to program */
	init_reg_param(&reg_params[2], "r2", 32, PARAM_OUT);    /* *pLW (*buffer) */
	init_reg_param(&reg_params[3], "sp", 32, PARAM_OUT);    /* update SP */
	init_reg_param(&reg_params[4], "lr", 32, PARAM_OUT);    /* update LR */

	/* Program in units */
	remain_size		= count;
	write_address	= bank->base + offset;
	write_data		= (uint8_t *)buffer;
	write_size		= buffer_size;

	while (remain_size != 0) {
		if (remain_size < buffer_size)
			write_size = remain_size;

		LOG_INFO("Program at 0x%08x to 0x%08x",
				write_address, (write_address + write_size - 1));

		/* Set parameter (Write data) */
		result = target_write_buffer(target,
									source->address,
									write_size,
									write_data);
		if (result != ERROR_OK) {
			LOG_DEBUG("target_write_buffer() = %d\n", result);
			break;
		}

		buf_set_u32(reg_params[0].value, 0, 32, write_address);
		buf_set_u32(reg_params[1].value, 0, 32, write_size);
		buf_set_u32(reg_params[2].value, 0, 32, source->address);
		buf_set_u32(reg_params[3].value, 0, 32, algorithm->address + target->working_area_size);
		buf_set_u32(reg_params[4].value, 0, 32, algorithm_lr);

		/* Run program */
		result = target_run_algorithm(target,
										0, NULL,
										ARRAY_SIZE(reg_params), reg_params,
										algorithm->address + algorithm_programpage_entry_offset,
										0,
										10000,
										&armv7m_info);
		if (result != ERROR_OK) {
			LOG_DEBUG("target_run_algorithm() = %d\n", result);
			result = ERROR_FLASH_OPERATION_FAILED;
			break;
		}

		/* Next */
		remain_size		-= write_size;
		write_address	+= write_size;
		write_data		+= write_size;
	}

	/* Free allocated area */
	target_free_working_area(target, algorithm);
	target_free_working_area(target, source);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);
	destroy_reg_param(&reg_params[3]);
	destroy_reg_param(&reg_params[4]);

	return result;
}

static int numicrom23_get_cpu_type(struct target *target, const struct numicrom23_cpu_type **cpu)
{
	uint32_t part_id;
	int retval = ERROR_OK;

	/* Read PartID */
	retval = target_read_u32(target, NUMICROM23_SYS_BASE, &part_id);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to Get PartID\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	LOG_INFO("PDID: 0x%08" PRIx32 "", part_id);
	/* search part numbers */
	for (size_t i = 0; i < ARRAY_SIZE(numicrom23_parts); i++) {
		if (part_id == numicrom23_parts[i].partid) {
			*cpu = &numicrom23_parts[i];
			LOG_INFO("Device Name: %s", (*cpu)->partname);
			return ERROR_OK;
		}
	}

	return ERROR_FAIL;
}

static int numicrom23_get_flash_size(struct flash_bank *bank,
									const struct numicrom23_cpu_type *cpu,
									uint32_t *flash_size)
{
	for (size_t i = 0; i < cpu->n_banks; i++) {
		if (bank->base == cpu->bank[i].base) {
			*flash_size = cpu->bank[i].size;
			LOG_INFO("bank base = " TARGET_ADDR_FMT ", size = 0x%08"
					PRIx32, bank->base, *flash_size);
			return ERROR_OK;
		}
	}
	return ERROR_FLASH_OPERATION_FAILED;
}

static int numicrom23_probe(struct flash_bank *bank)
{
	int	cnt;
	uint32_t part_id = 0x00000000;
	uint32_t flash_size, offset = 0;
	const struct numicrom23_cpu_type *cpu;
	struct target *target = bank->target;
	int retval = ERROR_OK;

	/* Check tatget access */
	retval = target_read_u32(target, NUMICROM23_SYS_BASE, &part_id);
	if (retval != ERROR_OK || part_id == 0x00000000) {
		/**
		 * Run numicrom23_probe() again later
		 * by leaving flash_bank_info->probed=0.
		 **/
		return ERROR_OK;
	}

	retval = numicrom23_get_cpu_type(target, &cpu);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to detect a known part\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	retval = numicrom23_get_flash_size(bank, cpu, &flash_size);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to detect flash size\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	bank->size			= flash_size;
	bank->num_sectors	= bank->size / FLASH_SECTOR_SIZE_4K;
	bank->sectors		= malloc(sizeof(struct flash_sector) * bank->num_sectors);

	offset = 0;
	for (cnt = 0; cnt < (int)(bank->num_sectors); cnt++) {
		bank->sectors[cnt].offset		= offset;
		bank->sectors[cnt].size			= FLASH_SECTOR_SIZE_4K;
		bank->sectors[cnt].is_erased	= -1;
		bank->sectors[cnt].is_protected	= -1;
		offset += FLASH_SECTOR_SIZE_4K;
	}

	struct numicrom23_flash_bank	*flash_bank_info;
	flash_bank_info			= bank->driver_priv;
	flash_bank_info->probed	= 1;
	flash_bank_info->cpu	= cpu;

	return ERROR_OK;
}

static int numicrom23_protect(struct flash_bank *bank, int set, unsigned int first, unsigned int last)
{
	LOG_INFO("protect function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int numicrom23_erase_check(struct flash_bank *bank)
{
	LOG_INFO("erase_check function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int numicrom23_protect_check(struct flash_bank *bank)
{
	LOG_INFO("protect_check function is unsupported\n");
	return ERROR_OK;
}

static int numicrom23_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	return ERROR_OK;
}

static int numicrom23_auto_probe(struct flash_bank *bank)
{
	struct numicrom23_flash_bank *flash_bank_info = bank->driver_priv;

	if (flash_bank_info->probed)
		return ERROR_OK;

	return numicrom23_probe(bank);
}

COMMAND_HANDLER(numicrom23_handle_erase_all_sectors_command)
{
	return ERROR_OK;
}

static const struct command_registration numicrom23_subcommand_handlers[] = {
	{
		.name		= "erase_all_sectors",
		.handler	= numicrom23_handle_erase_all_sectors_command,
		.mode		= COMMAND_EXEC,
		.usage		= "",
		.help		= "Erase all sectors",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration numicrom23_command_handlers[] = {
	{
		.name		= "numicrom23",
		.mode		= COMMAND_ANY,
		.help		= "numicrom23 command group",
		.usage		= "",
		.chain		= numicrom23_subcommand_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver numicrom23_flash = {
	.name					= "numicrom23",
	.usage					= "",
	.commands				= numicrom23_command_handlers,
	.flash_bank_command		= numicrom23_flash_bank_command,
	.erase					= numicrom23_erase,
	.protect				= numicrom23_protect,
	.write					= numicrom23_write,
	.read					= default_flash_read,
	.probe					= numicrom23_probe,
	.auto_probe				= numicrom23_auto_probe,
	.erase_check			= numicrom23_erase_check,
	.protect_check			= numicrom23_protect_check,
	.info					= numicrom23_info,
	.free_driver_priv		= default_flash_free_driver_priv,
};
