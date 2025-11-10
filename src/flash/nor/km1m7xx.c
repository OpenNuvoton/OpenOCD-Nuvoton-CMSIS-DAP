// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2021 by Nuvoton Technology Corporation Japan            *
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
#define	FI_BASE_ADDRESS				0x4001C000

#define	FEWEN						0x4001C000
#define	FEWEN_KEY_CODE				0x2900
#define	FEWEN_ENABLE				0x004B

#define	FISPROSTR					0x4001C018
#define	FISPROEND					0x4001C01C
#define	FISPROSTR_KM1M7C			0x4001C020
#define	FISPROEND_KM1M7C			0x4001C024

#define	FISPROSTR_ENABLE			0x00000000
#define	FISPROEND_ENABLE			0xFFFFFF00

#define	FWCNT						0x4001C004
#define	FWCNT_ERASE					0x00000002
#define	FWCNT_START					0x00000001

#define	FMON						0x4001C008
#define	FMON_ERROR					0x0000FF00
#define	FIFMON_ERROR				0x00FFFF00
#define	FMON_WBUSY					0x00000001

#define	PEADR						0x4001C00C

/* Definition for System Control Register */
#define	CCR							0xE000ED14
#define	CCR_IC						0x00020000
#define	CCR_DC						0x00010000

#define	CCSIDR						0xE000ED80
#define	CCSIDR_SSOCIATIVITY_POS		3
#define	CCSIDR_SSOCIATIVITY_MASK	((uint32_t)0x3FF << CCSIDR_SSOCIATIVITY_POS)
#define	CCSIDR_WAYS(cssidr)			(((cssidr) & CCSIDR_SSOCIATIVITY_MASK) \
										>> CCSIDR_SSOCIATIVITY_POS)
#define	CCSIDR_NUMSETS_POS			13
#define	CCSIDR_NUMSETS_MASK			((uint32_t)0x7FFF << CCSIDR_NUMSETS_POS)
#define	CCSIDR_SETS(cssidr)			(((cssidr) & CCSIDR_NUMSETS_MASK) \
										>> CCSIDR_NUMSETS_POS)

#define	CSSELR						0xE000ED84
#define	CSSELR_IND_DATA				0x00000000
#define	CSSELR_IND_INSTRUCTION		0x00000001

#define	ICIALLU						0xE000EF50
#define	ICIALLU_INVALIDATE			0x00000000

#define	DCCISW						0xE000EF74
#define	DCCISW_SET_POS				5
#define	DCCISW_SET_MASK				((uint32_t)0x1FF << DCCISW_SET_POS)
#define	DCCISW_SET(set)				(((set) << DCCISW_SET_POS) & DCCISW_SET_MASK)

#define	DCCISW_WAY_POS				30
#define	DCCISW_WAY_MASK				((uint32_t)0x00000003 << DCCISW_WAY_POS)
#define	DCCISW_WAY(way)				(((way) << DCCISW_WAY_POS) & DCCISW_WAY_MASK)

/* Definition KM1M7XX Flash Memory Address */
#define KM1M7XX_APROM_BASE			0x00800000
#define KM1M7XX_DATA_BASE			0x10800000
#define KM1M7XX_DATA0_BASE			0x00C04000
#define KM1M7XX_DATA1_BASE			0x00E04000

/* Definition KM1M7X Flash Memory Type */
#define KM1M7XX_FLASH_TYPE_KM1M7AB	0x00000000
#define KM1M7XX_FLASH_TYPE_KM1M7C	0x00000001

#define KM1M7ABX_BANKS(aprom_size, d_flash_size) \
	.flash_type = KM1M7XX_FLASH_TYPE_KM1M7AB, \
	.n_banks = 2, \
	{ {KM1M7XX_APROM_BASE, (aprom_size)}, {KM1M7XX_DATA_BASE, (d_flash_size)} }

#define KM1M7CX_BANKS(aprom_size, d_flash0_size, d_flash1_size) \
	.flash_type = KM1M7XX_FLASH_TYPE_KM1M7C, \
	.n_banks = 3, \
	{ {KM1M7XX_APROM_BASE, (aprom_size)}, {KM1M7XX_DATA0_BASE, (d_flash0_size)}, \
	  {KM1M7XX_DATA1_BASE, (d_flash1_size)} }

static const struct km1mxxx_cpu_type km1m7xx_parts_km1m7ab[] = {
	/*PART NO*/			/*PART ID*/		/*Banks*/
	/* KM1M7A/B Series */
	{"KM1M7A/BFxxK",	0x00000000,		KM1M7ABX_BANKS(256 * 1024, 64 * 1024)},
	{"KM1M7A/BFxxM",	0x00000000,		KM1M7ABX_BANKS(384 * 1024, 64 * 1024)},
	{"KM1M7A/BFxxN",	0x00000000,		KM1M7ABX_BANKS(512 * 1024, 64 * 1024)},
};

static const struct km1mxxx_cpu_type km1m7xx_parts[] = {
	/*PART NO*/			/*PART ID*/		/*Banks*/
	/* KM1M7C Series */
	{"KM1M7CF03N",		0x08700100,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF03K",		0x08700000,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF04N",		0x08700101,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF04K",		0x08700001,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF05N",		0x08700102,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF05K",		0x08700002,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF06N",		0x08700103,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF06K",		0x08700003,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF13N",		0x08701100,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF13K",		0x08701000,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF14N",		0x08701101,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF14K",		0x08701001,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF15N",		0x08701102,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF15K",		0x08701002,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF16N",		0x08701103,		KM1M7CX_BANKS(512 * 1024, 16 * 1024, 16 * 1024)},
	{"KM1M7CF16K",		0x08701003,		KM1M7CX_BANKS(256 * 1024, 16 * 1024, 16 * 1024)},
};

/* Definition for static variable  */
static uint32_t backup_ccr;
static uint32_t km1m7xx_as_part_id;

/* Definition for static functions */
static int km1m7xx_get_cpu_type(struct target *target, const struct km1mxxx_cpu_type **cpu);
static int km1m7xx_get_flash_size(struct flash_bank *bank, const struct km1mxxx_cpu_type *cpu, uint32_t *flash_size);

/* Cache control functions  */
static void	enable_icache(struct flash_bank *bank);
static void	disable_icache(struct flash_bank *bank);
static void	enable_dcache(struct flash_bank *bank);
static void	disable_dcache(struct flash_bank *bank);
static void	invalidate_dcache(struct flash_bank *bank);

static void	enable_icache(struct flash_bank *bank)
{
	uint32_t read_ccr = 0;

	/* Do nothing if I-Cache is invalid before writing */
	if ((backup_ccr & CCR_IC) == 0)
		return;

	/* Invalidate I-Cache */
	target_write_u32(bank->target, ICIALLU, ICIALLU_INVALIDATE);

	/* Enable I-Cache */
	target_read_u32(bank->target, CCR, &read_ccr);
	target_write_u32(bank->target, CCR, (read_ccr | CCR_IC));
}

static void	disable_icache(struct flash_bank *bank)
{
	uint32_t read_ccr = 0;

	/* Do nothing if I-Cache is disabeled */
	if ((backup_ccr & CCR_IC) == 0)
		return;

	/* Disable I-Cache */
	target_read_u32(bank->target, CCR, &read_ccr);
	target_write_u32(bank->target, CCR, (read_ccr & ~CCR_IC));
	target_write_u32(bank->target, ICIALLU, ICIALLU_INVALIDATE);
}

static void enable_dcache(struct flash_bank *bank)
{
	uint32_t read_ccr = 0;

	/* Do nothing if D-Cache is invalid before writing */
	if ((backup_ccr & CCR_DC) == 0)
		return;

	/* Invalidate D-Cache */
	invalidate_dcache(bank);

	/* Enable D-Cache */
	target_read_u32(bank->target, CCR, &read_ccr);
	target_write_u32(bank->target, CCR,	(read_ccr | CCR_DC));
}

static void disable_dcache(struct flash_bank *bank)
{
	uint32_t read_ccr = 0;

	/* Do nothing if D-Cache is disabeled */
	if ((backup_ccr & CCR_DC) == 0)
		return;

	/* Disable D-Cache */
	target_read_u32(bank->target, CCR, &read_ccr);
	target_write_u32(bank->target, CCR, (read_ccr & ~CCR_DC));

	/* Invalidate D-Cache */
	invalidate_dcache(bank);
}

static void invalidate_dcache(struct flash_bank *bank)
{
	uint32_t read_ccsidr;
	uint32_t sets;
	uint32_t ways;

	/*	Select Level 1 data cache */
	target_write_u32(bank->target, CSSELR, CSSELR_IND_DATA);

	/* Invalidate D-Cache */
	target_read_u32(bank->target, CCSIDR, &read_ccsidr);
	sets = CCSIDR_SETS(read_ccsidr);
	do {
		ways = CCSIDR_WAYS(read_ccsidr);
		do {
			target_write_u32(bank->target, DCCISW, DCCISW_SET(sets) | DCCISW_WAY(ways));
		} while (ways--);
	} while (sets--);
}

/**
 * @brief	"flash bank" Command
 * @date	October, 2018
 * @note	[Usage]	flash bank $_FLASHNAME km1m7xx
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
FLASH_BANK_COMMAND_HANDLER(km1m7xx_flash_bank_command)
{
	struct km1mxxx_flash_bank	*flash_bank_info;

	flash_bank_info = malloc(sizeof(struct km1mxxx_flash_bank));
	if (!flash_bank_info) {
		LOG_ERROR("NuMicro flash driver: Out of memory");
		return ERROR_FAIL;
	}

	memset(flash_bank_info, 0, sizeof(struct km1mxxx_flash_bank));

	/* Specifying an alternative part ID */
	if (CMD_ARGC >= 8) {
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[7], km1m7xx_as_part_id);
	} else {
		km1m7xx_as_part_id = 0;
	}

	bank->driver_priv = flash_bank_info;
	flash_bank_info->probed	= 0;

	return ERROR_OK;
}

static int km1m7xx_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	uint32_t	read_fwcnt		= 0;
	uint32_t	read_fmon		= 0;
	uint64_t	timeout			= 0;
	uint32_t	sector_index	= 0;
	uint32_t	address			= 0;
	uint32_t	flash_type		= KM1M7XX_FLASH_TYPE_KM1M7AB;
	uint32_t	cache_ctrl_flag	= 0;
	struct km1mxxx_flash_bank	*flash_bank_info;

	/* Flash Memory type  */
	flash_bank_info = bank->driver_priv;
	if (flash_bank_info) {
		flash_type = flash_bank_info->cpu->flash_type;
	} else {
		LOG_ERROR("NuMicro flash driver: Unknown flash type\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	/* Set flash type parameter */
	if (flash_type == KM1M7XX_FLASH_TYPE_KM1M7C)
		cache_ctrl_flag	= 1;
	else
		cache_ctrl_flag	= 0;

	/* Flash Cache disable */
	if (cache_ctrl_flag) {
		target_read_u32(bank->target, CCR, &backup_ccr);
		disable_icache(bank);
		disable_dcache(bank);
	}

	/* Flash memory write enable */
	target_write_u32(bank->target, FEWEN,	(FEWEN_KEY_CODE | FEWEN_ENABLE));
	if (flash_type == KM1M7XX_FLASH_TYPE_KM1M7C) {
		target_write_u32(bank->target, FISPROSTR_KM1M7C,	FISPROSTR_ENABLE);
		target_write_u32(bank->target, FISPROEND_KM1M7C,	FISPROEND_ENABLE);
	} else {
		target_write_u32(bank->target, FISPROSTR,			FISPROSTR_ENABLE);
		target_write_u32(bank->target, FISPROEND,			FISPROEND_ENABLE);
	}

	/* Erase specified sectors */
	for (sector_index = first; sector_index <= last; sector_index++) {
		/* Get sector address */
		address = bank->base + bank->sectors[sector_index].offset;
		LOG_INFO("Erase at 0x%08x (Index:%d) ", address, sector_index);

		/* Set parameter */
		target_write_u32(bank->target, PEADR,
						(bank->base + bank->sectors[sector_index].offset));

		/* Start erase */
		target_write_u32(bank->target, FWCNT, (FWCNT_ERASE | FWCNT_START));

		/* Read FMON three times to wait for FMON.BUSY to be set. */
		target_read_u32(bank->target, FMON, &read_fmon);
		target_read_u32(bank->target, FMON, &read_fmon);
		target_read_u32(bank->target, FMON, &read_fmon);

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
				LOG_DEBUG("%s Error : FMON = %d\n", __func__, read_fmon);
				return ERROR_FAIL;
			}

			/* Check timeout */
			if ((timeval_ms() - timeout) > TIMEOUT_ERASE) {
				LOG_DEBUG("%s timeout : FMON = %d\n", __func__, read_fmon);
				/* Flash Cache disable */
				if (cache_ctrl_flag) {
					enable_icache(bank);
					enable_dcache(bank);
				}
				return ERROR_FAIL;
			}
		}

		/* Clear START bit of FWCNT */
		target_read_u32(bank->target, FWCNT, &read_fwcnt);
		read_fwcnt &= ~(FWCNT_ERASE | FWCNT_START);
		target_write_u32(bank->target, FWCNT, read_fwcnt);

		/* Check error */
		if ((read_fmon & FMON_ERROR) != 0) {
			LOG_DEBUG("%s Error : FMON = %d\n", __func__, read_fmon);
			/* Flash Cache disable */
			if (cache_ctrl_flag) {
				enable_icache(bank);
				enable_dcache(bank);
			}
			return ERROR_FAIL;
		}
	}

	/* Flash Cache disable */
	if (cache_ctrl_flag) {
		enable_icache(bank);
		enable_dcache(bank);
	}

	return ERROR_OK;
}

static int km1m7xx_write(struct flash_bank *bank, const uint8_t *buffer, uint32_t offset, uint32_t count)
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
	uint32_t				cache_ctrl_flag	= 0;

	uint32_t	flash_type		= KM1M7XX_FLASH_TYPE_KM1M7AB;
	struct km1mxxx_flash_bank	*flash_bank_info;

	static const uint8_t write_code[] = {
		0xF0, 0xB5, 0x00, 0x22, 0x00, 0x23, 0x00, 0x24,
		0x00, 0x20, 0x00, 0x21, 0x00, 0x25, 0x28, 0x4E,
		0x4E, 0x44, 0x32, 0x68, 0x27, 0x4E, 0x4E, 0x44,
		0x33, 0x68, 0x27, 0x4E, 0x4E, 0x44, 0x34, 0x68,
		0x00, 0x26, 0x26, 0x4F, 0x4F, 0x44, 0x3E, 0x60,
		0x3C, 0xE0, 0x25, 0x4E, 0xF2, 0x60, 0x00, 0x20,
		0x06, 0xE0, 0x40, 0xCB, 0xDF, 0xF8, 0x88, 0xC0,
		0x0C, 0xEB, 0x80, 0x07, 0x3E, 0x61, 0x40, 0x1C,
		0x20, 0x4E, 0x4E, 0x44, 0x36, 0x68, 0xB0, 0xEB,
		0x96, 0x0F, 0xF2, 0xD3, 0x00, 0x26, 0x1C, 0x4F,
		0x3E, 0x71, 0x01, 0x26, 0x3E, 0x71, 0x3E, 0x46,
		0x31, 0x89, 0x31, 0x89, 0x31, 0x89, 0x1A, 0x4D,
		0x31, 0x89, 0x00, 0xBF, 0x2E, 0x1E, 0xA5, 0xF1,
		0x01, 0x05, 0x00, 0xD1, 0xF0, 0xBD, 0x14, 0x4E,
		0x31, 0x89, 0x01, 0xF0, 0x01, 0x06, 0x00, 0x2E,
		0xF4, 0xD1, 0x11, 0x4E, 0x36, 0x79, 0x26, 0xF0,
		0x01, 0x06, 0x0F, 0x4F, 0x3E, 0x71, 0x01, 0xF4,
		0x7F, 0x46, 0x1E, 0xB1, 0x0B, 0x4E, 0x4E, 0x44,
		0x31, 0x60, 0x09, 0xE0, 0x0B, 0x4E, 0x4E, 0x44,
		0x36, 0x68, 0x32, 0x44, 0x09, 0x4E, 0x4E, 0x44,
		0x36, 0x68, 0xA4, 0x1B, 0x00, 0x2C, 0xC0, 0xD1,
		0x00, 0xBF, 0x00, 0xBE, 0x00, 0xBF, 0xDD, 0xE7,
		0x44, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
		0x4C, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00,
		0x00, 0xC0, 0x01, 0x40, 0x50, 0x00, 0x00, 0x00,
		0xA0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	/* Get working area for code */
	result = target_alloc_working_area(target,
										sizeof(write_code),
										&algorithm);
	if (result != ERROR_OK) {
		LOG_DEBUG("target_alloc_working_area() = %d\n", result);
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	/* Transfer write program to RAM */
	result = target_write_buffer(target,
								algorithm->address,
								sizeof(write_code),
								write_code);
	if (result != ERROR_OK) {
		LOG_DEBUG("target_write_buffer() = %d\n", result);
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
			LOG_DEBUG("target_alloc_working_area_try() = %d\n", result);
			target_free_working_area(target, algorithm);
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
	}

	/* Flash Memory type  */
	flash_bank_info = bank->driver_priv;
	if (flash_bank_info) {
		flash_type = flash_bank_info->cpu->flash_type;
	} else {
		LOG_ERROR("NuMicro flash driver: Unknown flash type\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	/* Set flash type parameter */
	if (flash_type == KM1M7XX_FLASH_TYPE_KM1M7C) {
		program_unit	= 16;
		cache_ctrl_flag	= 1;
	} else {
		program_unit	= 8;
		cache_ctrl_flag	= 0;
	}

	/* Flash Cache disable */
	if (cache_ctrl_flag) {
		target_read_u32(bank->target, CCR, &backup_ccr);
		disable_icache(bank);
		disable_dcache(bank);
	}

	/* Flash memory write enable */
	target_write_u32(bank->target, FEWEN,	(FEWEN_KEY_CODE | FEWEN_ENABLE));
	if (flash_type == KM1M7XX_FLASH_TYPE_KM1M7C) {
		target_write_u32(bank->target, FISPROSTR_KM1M7C,	FISPROSTR_ENABLE);
		target_write_u32(bank->target, FISPROEND_KM1M7C,	FISPROEND_ENABLE);
	} else {
		target_write_u32(bank->target, FISPROSTR,			FISPROSTR_ENABLE);
		target_write_u32(bank->target, FISPROEND,			FISPROEND_ENABLE);
	}

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

		LOG_INFO("Program at 0x%08x to 0x%08x",
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
			LOG_DEBUG("target_write_buffer() = %d\n", result);
			break;
		}

		/* Set parameter (Write data) */
		result = target_write_buffer(target,
									source->address,
									write_size,
									write_data);
		if (result != ERROR_OK) {
			LOG_DEBUG("target_write_buffer() = %d\n", result);
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
			LOG_DEBUG("target_run_algorithm() = %d\n", result);
			result = ERROR_FLASH_OPERATION_FAILED;
			break;
		}

		/* Get status */
		result = target_read_u32(target,
								algorithm->address + sizeof(write_code) - 4,
								&status);
		if (result != ERROR_OK) {
			LOG_DEBUG("target_read_u32() = %d\n", result);
			break;
		}

		/* Next */
		remain_size		-= write_size;
		write_address	+= write_size;
		write_data		+= write_size;
	}

	/* Flash Cache disable */
	if (cache_ctrl_flag) {
		enable_icache(bank);
		enable_dcache(bank);
	}

	/* Free allocated area */
	target_free_working_area(target, algorithm);
	target_free_working_area(target, source);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);

	return result;
}

static int km1m7xx_get_cpu_type(struct target *target, const struct km1mxxx_cpu_type **cpu)
{
	uint32_t part_id;
	int retval = ERROR_OK;

	/* Read PartID */
	retval = target_read_u32(target, KM1MXXX_SYS_BASE, &part_id);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to Get PartID\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}
	LOG_INFO("NuMicro flash driver: Device ID: 0x%08" PRIx32 "", part_id);

	/* If an alternative Part ID is specified, replace it. */
	if (km1m7xx_as_part_id != 0) {
		LOG_INFO("NuMicro flash driver: Connect to flash as part ID = 0x%08" PRIx32 "", km1m7xx_as_part_id);
		part_id = km1m7xx_as_part_id;
	}

	/* search part numbers */
	for (size_t i = 0; i < ARRAY_SIZE(km1m7xx_parts); i++) {
		if (part_id == km1m7xx_parts[i].partid) {
			*cpu = &km1m7xx_parts[i];
			LOG_INFO("NuMicro flash driver: Device Name: %s", (*cpu)->partname);
			return ERROR_OK;
		}
	}

	return ERROR_FAIL;
}

static int km1m7xx_get_flash_size(struct flash_bank *bank, const struct km1mxxx_cpu_type *cpu, uint32_t *flash_size)
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

static int km1m7xx_get_cpu_type_km1m7ab(struct target *target, const struct km1mxxx_cpu_type **cpu)
{
	int			retval = ERROR_OK;
	uint32_t	opt_reg00;
	uint32_t	iflash_size;

	/* Read Option register */
	retval = target_read_u32(target, 0x4001C160, &opt_reg00);
	if (retval != ERROR_OK)
		return ERROR_FAIL;

	iflash_size = ((opt_reg00 & 0x00FF0000) >> 4);

	/* Search cpu type */
	for (size_t i = 0; i < ARRAY_SIZE(km1m7xx_parts_km1m7ab); i++) {
		/* Size comparison with I-Flash(bank0) */
		if (iflash_size == km1m7xx_parts_km1m7ab[i].bank[0].size) {
			*cpu = &km1m7xx_parts_km1m7ab[i];
			LOG_INFO("Device Name: %s", (*cpu)->partname);
			return ERROR_OK;
		}
	}

	return ERROR_FAIL;
}

static int km1m7xx_probe(struct flash_bank *bank)
{
	int			cnt;
	uint32_t part_id = 0x00000000;
	uint32_t flash_size, offset = 0;
	uint32_t flash_sector_size = FLASH_SECTOR_SIZE_4K;
	const struct km1mxxx_cpu_type *cpu;
	struct target *target = bank->target;
	int retval = ERROR_OK;

	/* Read PartID */
	retval = target_read_u32(target, KM1MXXX_SYS_BASE, &part_id);
	if (retval != ERROR_OK || part_id == 0x00000000) {
		/**
		 * Run km1mxxx_probe() again later
		 * by leaving flash_bank_info->probed=0.
		 **/
		return ERROR_OK;
	}

	/* If an alternative Part ID is specified, replace it. */
	if (km1m7xx_as_part_id != 0) {
		part_id = km1m7xx_as_part_id;
	}

	if (part_id == 0x00000001 || part_id == 0x00000003) {
		/* For KM1M7A/B, read the initial value(0x00000001 or 0x00000003)
		   of CHIPCKCTR(0x40000000). */
		retval = km1m7xx_get_cpu_type_km1m7ab(target, &cpu);
	} else {
		/* Reads CPUID (except for KM1M7A/B) */
		retval = km1m7xx_get_cpu_type(target, &cpu);
	}
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to detect a known part\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	retval = km1m7xx_get_flash_size(bank, cpu, &flash_size);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to detect flash size\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}
	if (cpu->flash_type == KM1M7XX_FLASH_TYPE_KM1M7C)
		flash_sector_size = FLASH_SECTOR_SIZE_8K;

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

static int km1m7xx_protect(struct flash_bank *bank, int set, unsigned int first, unsigned int last)
{
	LOG_INFO("protect function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int km1m7xx_erase_check(struct flash_bank *bank)
{
	LOG_INFO("erase_check function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int km1m7xx_protect_check(struct flash_bank *bank)
{
	LOG_INFO("protect_check function is unsupported\n");
	return ERROR_OK;
}

static int km1m7xx_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	return ERROR_OK;
}

static int km1m7xx_auto_probe(struct flash_bank *bank)
{
	struct km1mxxx_flash_bank *flash_bank_info = bank->driver_priv;

	if (flash_bank_info->probed)
		return ERROR_OK;

	return km1m7xx_probe(bank);
}

COMMAND_HANDLER(km1m7xx_handle_erase_all_sectors_command)
{
	struct flash_bank	*bank;
	int					result;

	/* Erase all sectors of each bank */
	for (bank = flash_bank_list(); bank; bank = bank->next) {
		/* Get bank information */
		get_flash_bank_by_name(bank->name, &bank);

		/* Erase all sectors */
		result = km1m7xx_erase(bank, 0, (bank->num_sectors - 1));
		if (result != ERROR_OK)
			return result;
	}

	return ERROR_OK;
}

static const struct command_registration km1m7xx_subcommand_handlers[] = {
	{
		.name		= "erase_all_sectors",
		.handler	= km1m7xx_handle_erase_all_sectors_command,
		.mode		= COMMAND_EXEC,
		.usage		= "",
		.help		= "Erase all sectors",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration km1m7xx_command_handlers[] = {
	{
		.name		= "km1m7xx",
		.mode		= COMMAND_ANY,
		.help		= "km1m7xx command group",
		.usage		= "",
		.chain		= km1m7xx_subcommand_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver km1m7xx_flash = {
	.name					= "km1m7xx",
	.usage					= "",
	.commands				= km1m7xx_command_handlers,
	.flash_bank_command		= km1m7xx_flash_bank_command,
	.erase					= km1m7xx_erase,
	.protect				= km1m7xx_protect,
	.write					= km1m7xx_write,
	.read					= default_flash_read,
	.probe					= km1m7xx_probe,
	.auto_probe				= km1m7xx_auto_probe,
	.erase_check			= km1m7xx_erase_check,
	.protect_check			= km1m7xx_protect_check,
	.info					= km1m7xx_info,
	.free_driver_priv		= default_flash_free_driver_priv,
};
