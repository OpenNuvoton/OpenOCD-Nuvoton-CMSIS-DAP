// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2022 by Nuvoton Technology Corporation Japan            *
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
#define	FI_BASE_ADDRESS			0x4001C000

#define	FEWEN					0x4001C000
#define	FEWEN_KEY_CODE			0x2900
#define	FEWEN_ENABLE			0x004B

#define	SPROSTR					0x4001C018
#define	SPROSTR_ENABLE			0x00000000
#define	SPROEND					0x4001C01C
#define	SPROEND_ENABLE			0xFFFFFFFF

#define	FWCNT					0x4001C004
#define	FWCNT_ERASE				0x00000002
#define	FWCNT_START				0x00000001

#define	FMON					0x4001C008
#define	FMON_ERROR				0x0000FF00
#define	FMON_WBUSY				0x00000001

#define	PEADR					0x4001C00C

#define	IFCEN					0x4001C068
#define	IFCEN_DISABLE			0x00
#define	DFCEN					0x4001C06C
#define	DFCEN_DISABLE			0x00

/* Definition KM1M4XX Flash Memory Address */
#define KM1M4XX_APROM_BASE		0x00000000
#define KM1M4XX_DATA_BASE		0x10800000

/* Definition KM1M4X Flash Memory Type */
#define KM1M4XX_FLASH_TYPE_KM1M4B	0x00000000


#define KM1M4XX_BANKS(aprom_size, d_flash_size) \
	.flash_type = KM1M4XX_FLASH_TYPE_KM1M4B, \
	.n_banks = 2, \
	{ {KM1M4XX_APROM_BASE, (aprom_size)}, {KM1M4XX_DATA_BASE, (d_flash_size)} }

static const struct km1mxxx_cpu_type km1m4xx_parts[] = {
	/*PART NO*/			/*PART ID*/		/*Banks*/
	/* KM1M4B Series */
	{"KM1M4BF02KXW",	0x08400252,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF02KXE",	0x08400253,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF02GXY",	0x08400352,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF02GXG",	0x08400353,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF03KXW",	0x08400254,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF03KXE",	0x08400255,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF03GXY",	0x08400354,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF03GXG",	0x08400355,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF04KXW",	0x08400256,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF04KXE",	0x08400257,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF04GXY",	0x08400356,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF04GXG",	0x08400357,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF05KXW",	0x08400258,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF05KXE",	0x08400259,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF05GXY",	0x08400358,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF05GXG",	0x08400359,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF52KXW",	0x08401252,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF52KXE",	0x08401253,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF52GXY",	0x08401352,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF52GXG",	0x08401353,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF53KXW",	0x08401254,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF53KXE",	0x08401255,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF53GXY",	0x08401354,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF53GXG",	0x08401355,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF54KXW",	0x08401256,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF54KXE",	0x08401257,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF54GXY",	0x08401356,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF54GXG",	0x08401357,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF55KXW",	0x08401258,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF55KXE",	0x08401259,		KM1M4XX_BANKS(264 * 1024, 32 * 1024)},
	{"KM1M4BF55GXY",	0x08401358,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF55GXG",	0x08401359,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},

	{"KM1M4BF64GXW",	0x08402231,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF65GXW",	0x08402233,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF66GXW",	0x08402234,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
	{"KM1M4BF67GXW",	0x08402235,		KM1M4XX_BANKS(136 * 1024,  8 * 1024)},
};

static uint32_t km1m4xx_as_part_id;

/* Definition for static functions */
static int km1m4xx_get_cpu_type(struct target *target, const struct km1mxxx_cpu_type **cpu);
static int km1m4xx_get_flash_size(struct flash_bank *bank, const struct km1mxxx_cpu_type *cpu, uint32_t *flash_size);


/**
 * @brief	"flash bank" Command
 * @date	October, 2018
 * @note	[Usage]	flash bank $_FLASHNAME km1m4xx
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
FLASH_BANK_COMMAND_HANDLER(km1m4xx_flash_bank_command)
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
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[7], km1m4xx_as_part_id);
	} else {
		km1m4xx_as_part_id = 0;
	}

	bank->driver_priv = flash_bank_info;
	flash_bank_info->probed	= 0;

	return ERROR_OK;
}

static int km1m4xx_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	uint32_t	read_fwcnt		= 0;
	uint32_t	read_fmon		= 0;
	uint64_t	timeout			= 0;
	uint32_t	sector_index	= 0;
	uint32_t	address			= 0;

	/* Flash memory write enable */
	target_write_u32(bank->target, FEWEN,	(FEWEN_KEY_CODE | FEWEN_ENABLE));
	target_write_u32(bank->target, SPROSTR,	SPROSTR_ENABLE);
	target_write_u32(bank->target, SPROEND,	SPROEND_ENABLE);

	/* Flash Cache disable */
	target_write_u8(bank->target, IFCEN,	IFCEN_DISABLE);
	target_write_u8(bank->target, IFCEN,	DFCEN_DISABLE);

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
				LOG_DEBUG("NuMicro flash driver: %s Error : FMON = 0x%08x\n", __func__, read_fmon);
				return ERROR_FAIL;
			}

			/* Check timeout */
			if ((timeval_ms() - timeout) > TIMEOUT_ERASE) {
				LOG_DEBUG("NuMicro flash driver: %s timeout : FMON = 0x%08x\n", __func__, read_fmon);
				return ERROR_FAIL;
			}
		}

		/* Clear START bit of FWCNT */
		target_read_u32(bank->target, FWCNT, &read_fwcnt);
		read_fwcnt &= ~(FWCNT_ERASE | FWCNT_START);
		target_write_u32(bank->target, FWCNT, read_fwcnt);

		/* Check error */
		if ((read_fmon & FMON_ERROR) != 0) {
			LOG_DEBUG("NuMicro flash driver: %s Error : FMON = 0x%08x\n", __func__, read_fmon);
			return ERROR_FAIL;
		}
	}

	return ERROR_OK;
}

static int km1m4xx_write(struct flash_bank *bank, const uint8_t *buffer, uint32_t offset, uint32_t count)
{
	int						result			= ERROR_OK;
	struct target			*target			= bank->target;
	struct working_area		*algorithm		= NULL;
	struct working_area		*source			= NULL;
	struct armv7m_algorithm	armv7m_info;

	struct reg_param		reg_params[2];
	uint32_t				mem_params32[4]	= {0, 0, 0, 0};
	uint8_t					mem_params8[sizeof(mem_params32)];

	uint32_t				remain_size		= 0;
	uint32_t				buffer_size		= 0;
	uint32_t				write_address	= 0;
	uint32_t				write_size		= 0;
	uint32_t				program_unit	= 0;
	uint8_t					*write_data		= 0;
	uint32_t				status			= 0;

	uint32_t				align_error		= 0;
	uint8_t					*buffer_temp	= NULL;

	static const uint8_t km1m4xx_write_code[] = {
		0x70, 0xB5, 0x00, 0x22, 0x00, 0x20, 0x00, 0x23,
		0x00, 0x21, 0x00, 0x24, 0x1F, 0x4D, 0x4D, 0x44,
		0x2A, 0x68, 0x1F, 0x4D, 0x4D, 0x44, 0x28, 0x68,
		0x1E, 0x4D, 0x4D, 0x44, 0x2B, 0x68, 0x00, 0x25,
		0x1D, 0x4E, 0x4E, 0x44, 0x35, 0x60, 0x2B, 0xE0,
		0x1C, 0x4D, 0xEA, 0x60, 0x20, 0xC8, 0x1B, 0x4E,
		0x35, 0x61, 0x20, 0xC8, 0x75, 0x61, 0x00, 0x25,
		0x35, 0x71, 0x01, 0x25, 0x35, 0x71, 0x35, 0x46,
		0x29, 0x89, 0x29, 0x89, 0x29, 0x89, 0x16, 0x4C,
		0x29, 0x89, 0x00, 0xBF, 0x25, 0x1E, 0xA4, 0xF1,
		0x01, 0x04, 0x00, 0xD1, 0x70, 0xBD, 0x11, 0x4D,
		0x29, 0x89, 0x01, 0xF0, 0x01, 0x05, 0x00, 0x2D,
		0xF4, 0xD1, 0x0E, 0x4D, 0x2D, 0x79, 0x25, 0xF0,
		0x01, 0x05, 0x0C, 0x4E, 0x35, 0x71, 0x01, 0xF4,
		0x7F, 0x45, 0x1D, 0xB1, 0x08, 0x4D, 0x4D, 0x44,
		0x29, 0x60, 0x03, 0xE0, 0x08, 0x32, 0x08, 0x3B,
		0x00, 0x2B, 0xD1, 0xD1, 0x00, 0xBF, 0x00, 0xBE,
		0x00, 0xBF, 0xE3, 0xE7, 0x44, 0x00, 0x00, 0x00,
		0x48, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x00, 0x00,
		0x50, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x01, 0x40,
		0xA0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	};

	/* Get working area for code */
	result = target_alloc_working_area(target,
										sizeof(km1m4xx_write_code),
										&algorithm);
	if (result != ERROR_OK) {
		LOG_DEBUG("NuMicro flash driver: target_alloc_working_area() = %d\n", result);
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	/* Transfer write program to RAM */
	result = target_write_buffer(target,
								algorithm->address,
								sizeof(km1m4xx_write_code),
								km1m4xx_write_code);
	if (result != ERROR_OK) {
		LOG_DEBUG("NuMicro flash driver: target_write_buffer() = %d\n", result);
		target_free_working_area(target, algorithm);
		return result;
	}

	/* Get working area for data */
	buffer_size	= 16 * 1024;
	result		= ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
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

	/* Set flash type parameter */
	program_unit = 8;

	/* Flash memory write enable */
	target_write_u32(bank->target, FEWEN,	(FEWEN_KEY_CODE | FEWEN_ENABLE));
	target_write_u32(bank->target, SPROSTR,	SPROSTR_ENABLE);
	target_write_u32(bank->target, SPROEND,	SPROEND_ENABLE);

	/* Flash Cache disable */
	target_write_u8(bank->target, IFCEN,	IFCEN_DISABLE);
	target_write_u8(bank->target, IFCEN,	DFCEN_DISABLE);

	/**
	 *	Set parameter (Core Register)
	 *		Offset from last address of write program
	 *		SP		: <-  -0x14		: Stack Pointer
	 *		r9		: <-  -0x54		: .data Section
	 **/
	init_reg_param(&reg_params[0], "sp", 32, PARAM_OUT);
	init_reg_param(&reg_params[1], "r9", 32, PARAM_OUT);

	buf_set_u32(reg_params[0].value, 0, 32,
				(algorithm->address + sizeof(km1m4xx_write_code) - 0x14));
	buf_set_u32(reg_params[1].value, 0, 32,
				(algorithm->address + sizeof(km1m4xx_write_code) - 0x54));

	/**
	 *	Set parameter
	 *		Offset from last address of write program
	 *		(-0x10	:  -> Address      )
	 *		 -0x0C	:  -> BufferAddress
	 *		(-0x08	:  -> ByteCount    )
	 *		(-0x04	: <-  Result       )
	 **/
	mem_params32[1] = source->address;

	/**
	 *	Program in units
	 *		Address is restricted to alignment with the minimum write unit.
	 *		(Add 0xff to the beginning of the write data)
	 **/
	align_error = (bank->base + offset) % program_unit;
	if (align_error) {
		remain_size		= count + align_error;
		write_address	= bank->base + offset - align_error;

		buffer_temp = malloc(remain_size);
		memset(buffer_temp, 0xff, remain_size);
		memcpy((buffer_temp + align_error), buffer, count);
		write_data		= buffer_temp;
		write_size		= buffer_size;
	} else {
		remain_size		= count;
		write_address	= bank->base + offset;
		write_data		= (uint8_t *)buffer;
		write_size		= buffer_size;
		buffer_temp		= NULL;
	}

	while (remain_size != 0) {
		if (remain_size < buffer_size)
			write_size = remain_size;

		LOG_INFO("NuMicro flash driver: Program at 0x%08x to 0x%08x",
				write_address, (write_address + write_size - 1));

		/**
		 *	Set parameter
		 *		Offset from last address of write program
		 *		 -0x10	:  -> Address
		 *		(-0x0C	:  -> BufferAddress )
		 *		 -0x08	:  -> ByteCount
		 *		 -0x04	: <-  Result
		 **/
		mem_params32[0] = write_address;
		mem_params32[2] = write_size;
		mem_params32[3] = 0;
		target_buffer_set_u32_array(target,
									mem_params8,
									ARRAY_SIZE(mem_params32),
									mem_params32);
		result = target_write_buffer(target,
									algorithm->address + sizeof(km1m4xx_write_code) - 0x10,
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
		armv7m_info.common_magic	= ARMV7M_COMMON_MAGIC;
		armv7m_info.core_mode		= ARM_MODE_THREAD;
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
								algorithm->address + sizeof(km1m4xx_write_code) - 4,
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

	/* Free allocated area */
	if (buffer_temp != NULL) {
		free(buffer_temp);
	}
	target_free_working_area(target, algorithm);
	target_free_working_area(target, source);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);

	return result;
}


static int km1m4xx_get_cpu_type(struct target *target, const struct km1mxxx_cpu_type **cpu)
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
	if (km1m4xx_as_part_id != 0) {
		LOG_INFO("NuMicro flash driver: Connect to flash as part ID = 0x%08" PRIx32 "", km1m4xx_as_part_id);
		part_id = km1m4xx_as_part_id;
	}

	/* search part numbers */
	for (size_t i = 0; i < ARRAY_SIZE(km1m4xx_parts); i++) {
		if (part_id == km1m4xx_parts[i].partid) {
			*cpu = &km1m4xx_parts[i];
			LOG_INFO("NuMicro flash driver: Device Name: %s", (*cpu)->partname);
			return ERROR_OK;
		}
	}

	return ERROR_FAIL;
}

static int km1m4xx_get_flash_size(struct flash_bank *bank, const struct km1mxxx_cpu_type *cpu, uint32_t *flash_size)
{
	for (size_t i = 0; i < cpu->n_banks; i++) {
		if (bank->base == cpu->bank[i].base) {
			*flash_size = cpu->bank[i].size;
			LOG_INFO("NuMicro flash driver: bank base = " TARGET_ADDR_FMT ", size = 0x%08"
					PRIx32, bank->base, *flash_size);
			return ERROR_OK;
		}
	}
	return ERROR_FLASH_OPERATION_FAILED;
}

static int km1m4xx_probe(struct flash_bank *bank)
{
	int	cnt;
	uint32_t part_id = 0x00000000;
	uint32_t flash_size, offset = 0;
	const struct km1mxxx_cpu_type *cpu;
	struct target *target = bank->target;
	int retval = ERROR_OK;

	/* Check tatget access */
	retval = target_read_u32(target, KM1MXXX_SYS_BASE, &part_id);
	if (retval != ERROR_OK || part_id == 0x00000000) {
		/**
		 * Run km1mxxx_probe() again later
		 * by leaving flash_bank_info->probed=0.
		 **/
		return ERROR_OK;
	}

	retval = km1m4xx_get_cpu_type(target, &cpu);
	if (retval != ERROR_OK) {
		LOG_ERROR("NuMicro flash driver: Failed to detect a known part\n");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	retval = km1m4xx_get_flash_size(bank, cpu, &flash_size);
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

	struct km1mxxx_flash_bank	*flash_bank_info;
	flash_bank_info			= bank->driver_priv;
	flash_bank_info->probed	= 1;
	flash_bank_info->cpu	= cpu;

	return ERROR_OK;
}

static int km1m4xx_protect(struct flash_bank *bank, int set, unsigned int first, unsigned int last)
{
	LOG_INFO("NuMicro flash driver: protect function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int km1m4xx_erase_check(struct flash_bank *bank)
{
	LOG_INFO("NuMicro flash driver: erase_check function is unsupported\n");
	return ERROR_FLASH_OPER_UNSUPPORTED;
}

static int km1m4xx_protect_check(struct flash_bank *bank)
{
	LOG_INFO("NuMicro flash driver: protect_check function is unsupported\n");
	return ERROR_OK;
}

static int km1m4xx_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	return ERROR_OK;
}

static int km1m4xx_auto_probe(struct flash_bank *bank)
{
	struct km1mxxx_flash_bank *flash_bank_info = bank->driver_priv;

	if (flash_bank_info->probed)
		return ERROR_OK;

	return km1m4xx_probe(bank);
}

COMMAND_HANDLER(km1m4xx_handle_erase_all_sectors_command)
{
	struct flash_bank	*bank;
	int					result;

	/* Erase all sectors of each bank */
	for (bank = flash_bank_list(); bank; bank = bank->next) {
		/* Get bank information */
		get_flash_bank_by_name(bank->name, &bank);

		/* Erase all sectors */
		result = km1m4xx_erase(bank, 0, (bank->num_sectors - 1));
		if (result != ERROR_OK)
			return result;
	}

	return ERROR_OK;
}

static const struct command_registration km1m4xx_subcommand_handlers[] = {
	{
		.name		= "erase_all_sectors",
		.handler	= km1m4xx_handle_erase_all_sectors_command,
		.mode		= COMMAND_EXEC,
		.usage		= "",
		.help		= "Erase all sectors",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration km1m4xx_command_handlers[] = {
	{
		.name		= "km1m4xx",
		.mode		= COMMAND_ANY,
		.help		= "km1m4xx command group",
		.usage		= "",
		.chain		= km1m4xx_subcommand_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver km1m4xx_flash = {
	.name					= "km1m4xx",
	.usage					= "",
	.commands				= km1m4xx_command_handlers,
	.flash_bank_command		= km1m4xx_flash_bank_command,
	.erase					= km1m4xx_erase,
	.protect				= km1m4xx_protect,
	.write					= km1m4xx_write,
	.read					= default_flash_read,
	.probe					= km1m4xx_probe,
	.auto_probe				= km1m4xx_auto_probe,
	.erase_check			= km1m4xx_erase_check,
	.protect_check			= km1m4xx_protect_check,
	.info					= km1m4xx_info,
	.free_driver_priv		= default_flash_free_driver_priv,
};
