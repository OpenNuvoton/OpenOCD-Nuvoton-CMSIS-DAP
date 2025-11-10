// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2023 by Nuvoton Technology Corporation Japan            *
 *   Yoshikazu Yamaguchi <yamaguchi.yoshikazu@nuvoton.com>                 *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "km1mxxx.h"
#include <helper/binarybuffer.h>
#include <helper/time_support.h>
#include <target/algorithm.h>
#include <target/armv7m.h>

#include <target/image.h>

/* Definition for Flash Memory Interface Register */
#define	FEWEN						0x4000E000
#define	FEWEN_KEY_CODE				0x2900
#define	FEWEN_ENABLE				0x004B

#define	FWCNT						0x4000E004
#define	FWCNT_ERASE					0x00000002
#define	FWCNT_START					0x00000001

#define	FMON						0x4000E008
#define	FMON_ERROR					0x0000FF00
#define	FMON_WBUSY					0x00000001

#define	PEADR						0x4000E00C

#define	SPROSTR						0x4000E020
#define	SPROSTR_ENABLE				0x00000000
#define	SPROEND						0x4000E024
#define	SPROEND_ENABLE				0xFFFFFE00

/* Definition for System Control Register */
#define	CKCTR						0x40001000
#define	CKCTR_KEY_CODE				0xA53C0000
#define	CKCTR_HRCEN					0x00000001

/* Definition for KM1M0XX Flash Memory Type */
#define KM1M0XX_FLASH_TYPE_KM1M0DX	0x00000000

/* Definition for clock control type */
enum clock_type_code {
	KM1M0XX_CLOCK_TYPE_NONE,
	KM1M0XX_CLOCK_TYPE_KM1M0DX
};

#define KM1M0DX_BANKS(aprom_size, d_flash_size) \
	.flash_type = KM1M0XX_FLASH_TYPE_KM1M0DX, \
	.n_banks = 2, \
	{ {0x00000000,	(aprom_size)}, \
	  {0x00100000,	(d_flash_size)} }

#define KM1M0GX_BANKS(aprom_size, option_size) \
	.flash_type = KM1M0XX_FLASH_TYPE_KM1M0DX, \
	.n_banks = 2, \
	{ {0x00000000,	(aprom_size)}, \
	  {0x00200800,	(option_size)} }

static const struct km1mxxx_cpu_type km1m0xx_parts[] = {
	/*PART NO*/			/*PART ID*/		/*Banks*/
	/* KM1M0D Series */
	{"KM1M0DF02N",	0x08001004,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},
	{"KM1M0DF02N",	0x08001001,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},
	{"KM1M0DF03N",	0x08001000,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},
	{"KM1M0DF03N",	0x08001003,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},
	{"KM1M0DF04N",	0x08001005,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},
	{"KM1M0DF04N",	0x08001002,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},
	{"KM1M0DF13N",	0x08002000,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},
	{"KM1M0DF13N",	0x08002003,	KM1M0DX_BANKS(512 * 1024, 48 * 1024)},

	/* KM1M0G Series */
	{"KM1M0GF01K",	0x08003000,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF02K",	0x08003001,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF03K",	0x08003002,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF04K",	0x08003003,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF01Z",	0x08003010,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF02Z",	0x08003011,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF03Z",	0x08003012,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF04Z",	0x08003013,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF11Z",	0x08004010,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF12Z",	0x08004011,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF13Z",	0x08004012,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF14Z",	0x08004013,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF01Y",	0x08005010,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF02Y",	0x08005011,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF03Y",	0x08005012,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF04Y",	0x08005013,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF11Y",	0x08006010,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF12Y",	0x08006011,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF13Y",	0x08006012,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
	{"KM1M0GF14Y",	0x08006013,	KM1M0GX_BANKS(256 * 1024, 2 * 1024)},

	/* For devices with no Part ID written. */
	/* default */
	{"KM1M0default",	0xffffffff,		KM1M0GX_BANKS(256 * 1024, 2 * 1024)},
};

/* Private variable  */
static uint32_t backup_ckctr;
static uint32_t km1m0xx_as_part_id;

/* Private functions  */
static int km1m0xx_get_cpu_type(struct target *target, const struct km1mxxx_cpu_type **cpu)
{
	uint32_t part_id;
	int retval = ERROR_OK;

	/* Read PartID */
	retval = target_read_u32(target, KM1MXXX_SYS_BASE, &part_id);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to Get PartID\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	/* For devices with no Part ID written. */
	uint32_t product_code = (part_id >> 20) & 0xff;
	if (product_code != 0x80) {
		LOG_ERROR("NuMicro flash driver: Invalid part ID. (0x%08x)", part_id);
		part_id = 0xffffffff;
	}
	LOG_INFO("NuMicro flash driver: Device ID: 0x%08" PRIx32 "", part_id);

	/* If an alternative Part ID is specified, replace it. */
	if (km1m0xx_as_part_id != 0) {
		LOG_INFO("NuMicro flash driver: Connect to flash as part ID = 0x%08" PRIx32 "", km1m0xx_as_part_id);
		part_id = km1m0xx_as_part_id;
	}

	/* search part numbers */
	for (size_t i = 0; i < ARRAY_SIZE(km1m0xx_parts); i++) {
		if (part_id == km1m0xx_parts[i].partid) {
			*cpu = &km1m0xx_parts[i];
			LOG_INFO("NuMicro flash driver: Device Name: %s", (*cpu)->partname);
			return ERROR_OK;
		}
	}

	return ERROR_FAIL;
}

static int km1m0xx_get_flash_size(struct flash_bank *bank, const struct km1mxxx_cpu_type *cpu, uint32_t *flash_size)
{
	for (size_t i = 0; i < cpu->n_banks; i++) {
		if (bank->base == cpu->bank[i].base) {
			if (cpu->bank[i].size == 0) {
				LOG_ERROR("NuMicro flash driver: No memory for bank (address = " TARGET_ADDR_FMT ")", bank->base);
				break;
			}
			*flash_size = cpu->bank[i].size;
			LOG_INFO("NuMicro flash driver: bank base = " TARGET_ADDR_FMT ", size = 0x%08"
					PRIx32, bank->base, *flash_size);
			return ERROR_OK;
		}
	}
	return ERROR_FLASH_OPERATION_FAILED;
}

static void	set_clock(struct flash_bank *bank, enum clock_type_code type)
{
	switch (type) {
	case KM1M0XX_CLOCK_TYPE_KM1M0DX:
		target_read_u32(bank->target, CKCTR, &backup_ckctr);
		backup_ckctr &= 0xffff;
		if (!(backup_ckctr & CKCTR_HRCEN)) {
			target_write_u32(bank->target, CKCTR, (backup_ckctr | CKCTR_HRCEN | CKCTR_KEY_CODE));
		}
		break;
	/* KM1M0XX_CLOCK_TYPE_NONE */
	default:
		break;
	}
}

static void	restore_clock(struct flash_bank *bank, enum clock_type_code type)
{
	switch (type) {
	case KM1M0XX_CLOCK_TYPE_KM1M0DX:
		if (!(backup_ckctr & CKCTR_HRCEN)) {
			target_write_u32(bank->target, CKCTR, (backup_ckctr | CKCTR_KEY_CODE));
		}
		break;
	/* KM1M0XX_CLOCK_TYPE_NONE */
	default:
		break;
	}
}

/**
 * @brief	"flash bank" Command
 * @date	May, 2023
 * @note	[Usage]	flash bank $_FLASHNAME km1m0xx
 *					<Address> <size> <ChipWidth> <BusWidth> <Target> <Type> [<PID>]
 *						<Address>	: Flash memory base address
 *						<Size>		: Flash memory size
 *						<ChipWidth>	: Chip width in byte (Not use)
 *						<BusWidth>	: Bus width in byte (Not use)
 *						<Target>	: Target device (***.cpu)
 *						<Type>		: Write control type
 *						<PID>		: Alternative Part ID
 * @param
 * @return	int			ERROR_OK or the non-zero
 **/
FLASH_BANK_COMMAND_HANDLER(km1m0xx_flash_bank_command)
{
	struct km1mxxx_flash_bank	*flash_bank_info;

	flash_bank_info = malloc(sizeof(struct km1mxxx_flash_bank));
	if (!flash_bank_info) {
		LOG_ERROR("NuMicro flash driver: No memory for bank");
		return ERROR_FAIL;
	}
	memset(flash_bank_info, 0, sizeof(struct km1mxxx_flash_bank));

	/* Specifying an alternative part ID */
	if (CMD_ARGC >= 8) {
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[7], km1m0xx_as_part_id);
	} else {
		km1m0xx_as_part_id = 0;
	}

	bank->driver_priv = flash_bank_info;
	flash_bank_info->probed	= 0;

	return ERROR_OK;
}

static int km1m0xx_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	uint32_t	read_fwcnt		= 0;
	uint32_t	read_fmon		= 0;
	uint64_t	timeout			= 0;
	uint32_t	sector_index	= 0;
	uint32_t	address			= 0;
	enum clock_type_code		clock_type = 0;
	struct km1mxxx_flash_bank	*flash_bank_info;

	/* Flash Memory type  */
	flash_bank_info = bank->driver_priv;
	if (!flash_bank_info) {
		LOG_ERROR("NuMicro flash driver: Unknown flash type\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	/* Set clock generator */
	clock_type = KM1M0XX_CLOCK_TYPE_KM1M0DX;
	set_clock(bank, clock_type);

	/* Flash memory write enable */
	target_write_u32(bank->target, FEWEN,	(FEWEN_KEY_CODE | FEWEN_ENABLE));
	target_write_u32(bank->target, SPROSTR,	SPROSTR_ENABLE);
	target_write_u32(bank->target, SPROEND,	SPROEND_ENABLE);

	/* Erase specified sectors */
	for (sector_index = first; sector_index <= last; sector_index++) {
		/* Get sector address */
		address = bank->base + bank->sectors[sector_index].offset;
		LOG_INFO("NuMicro flash driver: Erase at 0x%08x (Index:%d) ", address, sector_index);

		/* Set parameter */
		target_write_u32(bank->target, PEADR,
						(bank->base + bank->sectors[sector_index].offset));

		/* Start erase */
		target_write_u32(bank->target, FWCNT, (FWCNT_ERASE | FWCNT_START));

		/* Wait for erase completion */
		target_read_u32(bank->target, FMON, &read_fmon);
		read_fmon &= 0xFFFF;
		timeout = timeval_ms();
		while (1) {
			/* Check for completion */
			target_read_u32(bank->target, FMON, &read_fmon);
			if ((read_fmon & FMON_WBUSY) == 0x0000)
				break;

			/* Check error */
			if ((read_fmon & FMON_ERROR) != 0) {
				LOG_DEBUG("NuMicro flash driver: %s Error : FMON = %d\n", __func__, read_fmon);
				restore_clock(bank, clock_type);
				return ERROR_FAIL;
			}

			/* Check timeout */
			if ((timeval_ms() - timeout) > TIMEOUT_ERASE) {
				LOG_DEBUG("NuMicro flash driver: %s timeout : FMON = %d\n", __func__, read_fmon);
				restore_clock(bank, clock_type);
				return ERROR_FAIL;
			}
		}

		/* Clear START bit of FWCNT */
		target_read_u32(bank->target, FWCNT, &read_fwcnt);
		read_fwcnt &= ~(FWCNT_ERASE | FWCNT_START);
		target_write_u32(bank->target, FWCNT, read_fwcnt);

		/* Check error */
		if ((read_fmon & FMON_ERROR) != 0) {
			LOG_DEBUG("NuMicro flash driver: %s Error : FMON = %d\n", __func__, read_fmon);
			restore_clock(bank, clock_type);
			return ERROR_FAIL;
		}
	}

	/* Restore clock generator */
	restore_clock(bank, clock_type);

	return ERROR_OK;
}

static int km1m0xx_write(struct flash_bank *bank, const uint8_t *buffer, uint32_t offset, uint32_t count)
{
	int						result			= ERROR_OK;
	struct target			*target			= bank->target;
	struct working_area		*algorithm		= NULL;
	struct working_area		*source			= NULL;
	struct armv7m_algorithm	armv7m_info;

	struct reg_param		reg_params[2];
	uint32_t				mem_params32[5]	= {0, 0, 0, 0, 0};
	uint8_t					mem_params8[sizeof(mem_params32)];

	uint32_t				remain_size		= 0;
	uint32_t				buffer_size		= 0;
	uint32_t				write_address	= 0;
	uint32_t				write_size		= 0;
	uint32_t				program_unit	= 0;
	uint8_t					*write_data		= 0;
	uint32_t				status			= 0;
	enum clock_type_code	clock_type		= 0;

	struct km1mxxx_flash_bank	*flash_bank_info;
	static const uint8_t write_code[] = {
		0xf8, 0xb5, 0x00, 0x22, 0x00, 0x23, 0x00, 0x24,
		0x00, 0x20, 0x00, 0x21, 0x00, 0x25, 0x00, 0x95,
		0x28, 0x4d, 0x4d, 0x44, 0x2a, 0x68, 0x28, 0x4d,
		0x4d, 0x44, 0x2b, 0x68, 0x27, 0x4d, 0x4d, 0x44,
		0x2c, 0x68, 0x00, 0x25, 0x26, 0x4e, 0x4e, 0x44,
		0x35, 0x60, 0x3c, 0xe0, 0x25, 0x4d, 0xea, 0x60,
		0x00, 0x20, 0x05, 0xe0, 0x20, 0xcb, 0x86, 0x00,
		0x22, 0x4f, 0xf6, 0x19, 0x35, 0x61, 0x40, 0x1c,
		0x21, 0x4d, 0x4d, 0x44, 0x2d, 0x68, 0xad, 0x08,
		0x85, 0x42, 0xf3, 0xd8, 0x00, 0x25, 0x1d, 0x4e,
		0x35, 0x71, 0x01, 0x25, 0x35, 0x71, 0x1d, 0x4d,
		0x00, 0x95, 0x35, 0x46, 0x29, 0x89, 0x00, 0xbf,
		0x00, 0x9d, 0x6e, 0x1e, 0x00, 0x96, 0x00, 0x2d,
		0x00, 0xd1, 0xf8, 0xbd, 0x15, 0x4d, 0x29, 0x89,
		0xcd, 0x07, 0xed, 0x0f, 0x00, 0x2d, 0xf3, 0xd1,
		0x12, 0x4d, 0x2d, 0x79, 0x6d, 0x08, 0x6d, 0x00,
		0x10, 0x4e, 0x35, 0x71, 0xff, 0x25, 0x2d, 0x02,
		0x0d, 0x40, 0x00, 0x2d, 0x03, 0xd0, 0x0c, 0x4d,
		0x4d, 0x44, 0x29, 0x60, 0x09, 0xe0, 0x0c, 0x4d,
		0x4d, 0x44, 0x2d, 0x68, 0x52, 0x19, 0x0a, 0x4d,
		0x4d, 0x44, 0x2d, 0x68, 0x64, 0x1b, 0x00, 0x2c,
		0xc0, 0xd1, 0x00, 0xbf, 0x00, 0xbe, 0x00, 0xbf,
		0xdb, 0xe7, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
		0x48, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00,
		0x54, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x40,
		0x50, 0x00, 0x00, 0x00, 0xa0, 0x86, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	/* Get working area for code */
	result = target_alloc_working_area(target,
										sizeof(write_code),
										&algorithm);
	if (result != ERROR_OK) {
		LOG_DEBUG("NuMicro flash driver: target_alloc_working_area() = %d\n", result);
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	/* Transfer write program to RAM */
	result = target_write_buffer(target,
								algorithm->address,
								sizeof(write_code),
								write_code);
	if (result != ERROR_OK) {
		LOG_DEBUG("NuMicro flash driver: target_write_buffer() = %d\n", result);
		target_free_working_area(target, algorithm);
		return result;
	}

	/* Get working area for data */
	buffer_size	= 16 * 1024;
	result = ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	while (result != ERROR_OK) {
		result = target_alloc_working_area_try(target, buffer_size, &source);
		if (result == ERROR_OK)
			break;

		buffer_size /= 2;
		if (buffer_size < 256) {
			LOG_DEBUG("NuMicro flash driver: target_alloc_working_area_try() = %d\n", result);
			target_free_working_area(target, algorithm);
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
	}

	/* Flash Memory type  */
	flash_bank_info = bank->driver_priv;
	if (!flash_bank_info) {
		LOG_ERROR("NuMicro flash driver: Unknown flash type\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	/* Set flash type parameter */
	program_unit = 8;

	/* Set clock generator */
	clock_type = KM1M0XX_CLOCK_TYPE_KM1M0DX;
	set_clock(bank, clock_type);

	/* Flash memory write enable */
	target_write_u32(bank->target, FEWEN,	(FEWEN_KEY_CODE | FEWEN_ENABLE));
	target_write_u32(bank->target, SPROSTR,	SPROSTR_ENABLE);
	target_write_u32(bank->target, SPROEND,	SPROEND_ENABLE);

	/**
	 *	Set parameter (Core Register)
	 *		Offset from last address of write program
	 *		SP		: <-  -0x18		: Stack Pointer
	 *		r9		: <-  -0x58		: .data Section
	 **/
	init_reg_param(&reg_params[0], "sp", 32, PARAM_OUT);
	init_reg_param(&reg_params[1], "r9", 32, PARAM_OUT);

	buf_set_u32(reg_params[0].value, 0, 32,
				(algorithm->address + sizeof(write_code) - 0x18));
	buf_set_u32(reg_params[1].value, 0, 32,
				(algorithm->address + sizeof(write_code) - 0x58));

	/**
	 *	Set parameter
	 *		Offset from last address of write program
	 *		(-0x14	:  -> Address)
	 *		 -0x10	:  -> BufferAddress
	 *		(-0x0C	:  -> ByteCount)
	 *		 -0x08	:  -> Program Unit
	 *		(-0x04	: <-  Result)
	 **/
	mem_params32[1] = source->address;
	mem_params32[3] = program_unit;

	/* Program in units */
	remain_size		= count;
	write_address	= bank->base + offset;
	write_data		= (uint8_t *)buffer;
	write_size		= buffer_size;

	while (remain_size != 0) {
		if (remain_size < buffer_size)
			write_size = remain_size;

		LOG_INFO("NuMicro flash driver: Program at 0x%08x to 0x%08x",
				write_address, (write_address + write_size - 1));

		/**
		 *	Set parameter
		 *		Offset from last address of write program
		 *		 -0x14	:  -> Address
		 *		(-0x10	:  -> BufferAddress )
		 *		 -0x0C	:  -> ByteCount
		 *		(-0x08	:  -> Program Unit)
		 *		 -0x04	: <-  Result
		 **/
		mem_params32[0] = write_address;
		mem_params32[2] = write_size;
		mem_params32[4] = 0;
		target_buffer_set_u32_array(target,
									mem_params8,
									ARRAY_SIZE(mem_params32),
									mem_params32);
		result = target_write_buffer(target,
									algorithm->address + sizeof(write_code) - 0x14,
									16,
									mem_params8);
		if (result != ERROR_OK) {
			LOG_DEBUG("NuMicro flash driver: target_write_buffer() = %d\n", result);
			break;
		}

		/* Set parameter (Write data) */
		result = target_write_buffer(target,
									source->address,
									write_size,
									write_data);
		if (result != ERROR_OK) {
			LOG_DEBUG("NuMicro flash driver: target_write_buffer() = %d\n", result);
			break;
		}

		/* Run program */
		armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
		armv7m_info.core_mode = ARM_MODE_THREAD;
		result = target_run_algorithm(target,
										0, NULL,
										ARRAY_SIZE(reg_params), reg_params,
										algorithm->address,
										0,
										1000,
										&armv7m_info);
		if (result != ERROR_OK) {
			LOG_DEBUG("NuMicro flash driver: target_run_algorithm() = %d\n", result);
			result = ERROR_FLASH_OPERATION_FAILED;
			break;
		}

		/* Get status */
		result = target_read_u32(target,
								algorithm->address + sizeof(write_code) - 4,
								&status);
		if (result != ERROR_OK) {
			LOG_DEBUG("NuMicro flash driver: target_read_u32() = %d\n", result);
			break;
		}

		/* Next */
		remain_size		-= write_size;
		write_address	+= write_size;
		write_data		+= write_size;
	}

	/* Restore clock generator */
	restore_clock(bank, clock_type);

	/* Free allocated area */
	target_free_working_area(target, algorithm);
	target_free_working_area(target, source);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);

	return result;
}

static int km1m0xx_probe(struct flash_bank *bank)
{
	int			cnt;
	uint32_t	flash_size = 0;
	uint32_t	offset = 0;
	uint32_t	flash_sector_size = FLASH_SECTOR_SIZE_2K;
	const struct km1mxxx_cpu_type *cpu;
	struct target *target = bank->target;
	int retval = ERROR_OK;

	retval = km1m0xx_get_cpu_type(target, &cpu);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to detect a known part\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	retval = km1m0xx_get_flash_size(bank, cpu, &flash_size);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to detect flash size\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}
	flash_sector_size = FLASH_SECTOR_SIZE_2K;

	bank->size			= flash_size;
	bank->num_sectors	= bank->size / flash_sector_size;
	bank->sectors		= malloc(sizeof(struct flash_sector) * bank->num_sectors);

	offset = 0;
	for (cnt = 0; cnt < (int)(bank->num_sectors); cnt++) {
		bank->sectors[cnt].offset		= offset;
		bank->sectors[cnt].size			= flash_sector_size;
		bank->sectors[cnt].is_erased	= -1;
		bank->sectors[cnt].is_protected	= -1;
		offset += flash_sector_size;
	}

	struct km1mxxx_flash_bank	*flash_bank_info;
	flash_bank_info			= bank->driver_priv;
	flash_bank_info->probed	= 1;
	flash_bank_info->cpu	= cpu;

	return ERROR_OK;
}

static int km1m0xx_protect(struct flash_bank *bank, int set, unsigned int first, unsigned int last)
{
	LOG_INFO("NuMicro flash driver: protect function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int km1m0xx_erase_check(struct flash_bank *bank)
{
	LOG_INFO("NuMicro flash driver: erase_check function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int km1m0xx_protect_check(struct flash_bank *bank)
{
	LOG_INFO("NuMicro flash driver: protect_check function is unsupported\n");
	return ERROR_OK;
}

static int km1m0xx_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	return ERROR_OK;
}

static int km1m0xx_auto_probe(struct flash_bank *bank)
{
	struct km1mxxx_flash_bank *flash_bank_info = bank->driver_priv;

	if (flash_bank_info->probed)
		return ERROR_OK;

	return km1m0xx_probe(bank);
}

COMMAND_HANDLER(km1m0xx_handle_erase_all_sectors_command)
{
	struct flash_bank	*bank;
	int					result;

	/* Erase all sectors of each bank */
	for (bank = flash_bank_list(); bank; bank = bank->next) {
		/* Get bank information */
		get_flash_bank_by_name(bank->name, &bank);

		/* Erase all sectors */
		result = km1m0xx_erase(bank, 0, (bank->num_sectors - 1));
		if (result != ERROR_OK)
			return result;
	}

	return ERROR_OK;
}

static const struct command_registration km1m0xx_subcommand_handlers[] = {
	{
		.name		= "erase_all_sectors",
		.handler	= km1m0xx_handle_erase_all_sectors_command,
		.mode		= COMMAND_EXEC,
		.usage		= "",
		.help		= "Erase all sectors",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration km1m0xx_command_handlers[] = {
	{
		.name		= "km1m0xx",
		.mode		= COMMAND_ANY,
		.help		= "km1m0xx command group",
		.usage		= "",
		.chain		= km1m0xx_subcommand_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver km1m0xx_flash = {
	.name					= "km1m0xx",
	.usage					= "",
	.commands				= km1m0xx_command_handlers,
	.flash_bank_command		= km1m0xx_flash_bank_command,
	.erase					= km1m0xx_erase,
	.protect				= km1m0xx_protect,
	.write					= km1m0xx_write,
	.read					= default_flash_read,
	.probe					= km1m0xx_probe,
	.auto_probe				= km1m0xx_auto_probe,
	.erase_check			= km1m0xx_erase_check,
	.protect_check			= km1m0xx_protect_check,
	.info					= km1m0xx_info,
	.free_driver_priv		= default_flash_free_driver_priv,
};
