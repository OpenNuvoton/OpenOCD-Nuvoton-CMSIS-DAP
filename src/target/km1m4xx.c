/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   Copyright (C) 2006 by Magnus Lundin                                   *
 *   lundin@mlu.mine.nu                                                    *
 *                                                                         *
 *   Copyright (C) 2008 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
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
 *                                                                         *
 *                                                                         *
 *   Cortex-M3(tm) TRM, ARM DDI 0337E (r1p1) and 0337G (r2p0)              *
 *                                                                         *
 *-------------------------------------------------------------------------*
 *                                                                         *
 *   This file is based on cortex_m.c and adds functionality for the       *
 *   Nuvoton KM1M4 series.This file was created based on cortex_m.c.       *
 *                                                                         *
 *   Copyright (C) 2022 by Nuvoton Technology Corporation Japan            *
 *   Naotoshi Izumi <izumi.naotoshi@nuvoton.com>                           *
 *                                                                         *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "jtag/interface.h"
#include "breakpoints.h"
#include "cortex_m.h"
#include "arm_adi_v5.h"
#include "target_request.h"
#include "target_type.h"
#include "arm_disassembler.h"
#include "register.h"
#include "arm_opcodes.h"
#include "arm_semihosting.h"
#include <helper/time_support.h>
#include <helper/log.h>
#include <server/server.h>
#include <server/gdb_server.h>

#include "image.h"

/* NOTE:  most of this should work fine for the Cortex-M1 and
 * Cortex-M0 cores too, although they're ARMv6-M not ARMv7-M.
 * Some differences:  M0/M1 doesn't have FPB remapping or the
 * DWT tracing/profiling support.  (So the cycle counter will
 * not be usable; the other stuff isn't currently used here.)
 *
 * Although there are some workarounds for errata seen only in r0p0
 * silicon, such old parts are hard to find and thus not much tested
 * any longer.
 */

/* definition for security authentication */
static uint32_t	km1m4xx_key_set		= 0;
static uint32_t	km1m4xx_key_data[4]	= {	0xffffffff,
										0xffffffff,
										0xffffffff,
										0xffffffff};

/* forward declarations */
static int cortex_m_store_core_reg_u32(struct target *target,
		uint32_t num, uint32_t value);

static int cortexm_dap_read_coreregister_u32(struct target *target,
	uint32_t *value, int regnum)
{
	struct armv7m_common *armv7m = target_to_armv7m(target);
	int retval;
	uint32_t dcrdr;

	/* because the DCB_DCRDR is used for the emulated dcc channel
	 * we have to save/restore the DCB_DCRDR when used */
	if (target->dbg_msg_enabled) {
		retval = mem_ap_read_u32(armv7m->debug_ap, DCB_DCRDR, &dcrdr);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = mem_ap_write_u32(armv7m->debug_ap, DCB_DCRSR, regnum);
	if (retval != ERROR_OK)
		return retval;

	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DCRDR, value);
	if (retval != ERROR_OK)
		return retval;

	if (target->dbg_msg_enabled) {
		/* restore DCB_DCRDR - this needs to be in a separate
		 * transaction otherwise the emulated DCC channel breaks */
		if (retval == ERROR_OK)
			retval = mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DCRDR, dcrdr);
	}

	return retval;
}

static int cortexm_dap_write_coreregister_u32(struct target *target,
	uint32_t value, int regnum)
{
	struct armv7m_common *armv7m = target_to_armv7m(target);
	int retval;
	uint32_t dcrdr;

	/* because the DCB_DCRDR is used for the emulated dcc channel
	 * we have to save/restore the DCB_DCRDR when used */
	if (target->dbg_msg_enabled) {
		retval = mem_ap_read_u32(armv7m->debug_ap, DCB_DCRDR, &dcrdr);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = mem_ap_write_u32(armv7m->debug_ap, DCB_DCRDR, value);
	if (retval != ERROR_OK)
		return retval;

	retval = mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DCRSR, regnum | DCRSR_WNR);
	if (retval != ERROR_OK)
		return retval;

	if (target->dbg_msg_enabled) {
		/* restore DCB_DCRDR - this needs to be in a separate
		 * transaction otherwise the emulated DCC channel breaks */
		if (retval == ERROR_OK)
			retval = mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DCRDR, dcrdr);
	}

	return retval;
}

static int cortex_m_write_debug_halt_mask(struct target *target,
	uint32_t mask_on, uint32_t mask_off)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;

	/* mask off status bits */
	cortex_m->dcb_dhcsr &= ~((0xFFFFul << 16) | mask_off);
	/* create new register mask */
	cortex_m->dcb_dhcsr |= DBGKEY | C_DEBUGEN | mask_on;

	return mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DHCSR, cortex_m->dcb_dhcsr);
}

static int cortex_m_set_maskints(struct target *target, bool mask)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	if (!!(cortex_m->dcb_dhcsr & C_MASKINTS) != mask)
		return cortex_m_write_debug_halt_mask(target, mask ? C_MASKINTS : 0, mask ? 0 : C_MASKINTS);
	else
		return ERROR_OK;
}

static int cortex_m_set_maskints_for_halt(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	switch (cortex_m->isrmasking_mode) {
		case CORTEX_M_ISRMASK_AUTO:
			/* interrupts taken at resume, whether for step or run -> no mask */
			return cortex_m_set_maskints(target, false);

		case CORTEX_M_ISRMASK_OFF:
			/* interrupts never masked */
			return cortex_m_set_maskints(target, false);

		case CORTEX_M_ISRMASK_ON:
			/* interrupts always masked */
			return cortex_m_set_maskints(target, true);

		case CORTEX_M_ISRMASK_STEPONLY:
			/* interrupts masked for single step only -> mask now if MASKINTS
			 * erratum, otherwise only mask before stepping */
			return cortex_m_set_maskints(target, cortex_m->maskints_erratum);
	}
	return ERROR_OK;
}

static int cortex_m_set_maskints_for_run(struct target *target)
{
	switch (target_to_cm(target)->isrmasking_mode) {
		case CORTEX_M_ISRMASK_AUTO:
			/* interrupts taken at resume, whether for step or run -> no mask */
			return cortex_m_set_maskints(target, false);

		case CORTEX_M_ISRMASK_OFF:
			/* interrupts never masked */
			return cortex_m_set_maskints(target, false);

		case CORTEX_M_ISRMASK_ON:
			/* interrupts always masked */
			return cortex_m_set_maskints(target, true);

		case CORTEX_M_ISRMASK_STEPONLY:
			/* interrupts masked for single step only -> no mask */
			return cortex_m_set_maskints(target, false);
	}
	return ERROR_OK;
}

static int cortex_m_set_maskints_for_step(struct target *target)
{
	switch (target_to_cm(target)->isrmasking_mode) {
		case CORTEX_M_ISRMASK_AUTO:
			/* the auto-interrupt should already be done -> mask */
			return cortex_m_set_maskints(target, true);

		case CORTEX_M_ISRMASK_OFF:
			/* interrupts never masked */
			return cortex_m_set_maskints(target, false);

		case CORTEX_M_ISRMASK_ON:
			/* interrupts always masked */
			return cortex_m_set_maskints(target, true);

		case CORTEX_M_ISRMASK_STEPONLY:
			/* interrupts masked for single step only -> mask */
			return cortex_m_set_maskints(target, true);
	}
	return ERROR_OK;
}

static int cortex_m_clear_halt(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	int retval;

	/* clear step if any */
	cortex_m_write_debug_halt_mask(target, C_HALT, C_STEP);

	/* Read Debug Fault Status Register */
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, NVIC_DFSR, &cortex_m->nvic_dfsr);
	if (retval != ERROR_OK)
		return retval;

	/* Clear Debug Fault Status */
	retval = mem_ap_write_atomic_u32(armv7m->debug_ap, NVIC_DFSR, cortex_m->nvic_dfsr);
	if (retval != ERROR_OK)
		return retval;
	LOG_DEBUG(" NVIC_DFSR 0x%" PRIx32 "", cortex_m->nvic_dfsr);

	return ERROR_OK;
}

static int cortex_m_single_step_core(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	int retval;

	/* Mask interrupts before clearing halt, if not done already.  This avoids
	 * Erratum 377497 (fixed in r1p0) where setting MASKINTS while clearing
	 * HALT can put the core into an unknown state.
	 */
	if (!(cortex_m->dcb_dhcsr & C_MASKINTS)) {
		retval = mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DHCSR,
				DBGKEY | C_MASKINTS | C_HALT | C_DEBUGEN);
		if (retval != ERROR_OK)
			return retval;
	}
	retval = mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DHCSR,
			DBGKEY | C_MASKINTS | C_STEP | C_DEBUGEN);
	if (retval != ERROR_OK)
		return retval;
	LOG_DEBUG(" ");

	/* restore dhcsr reg */
	cortex_m_clear_halt(target);

	return ERROR_OK;
}

static int cortex_m_enable_fpb(struct target *target)
{
	int retval = target_write_u32(target, FP_CTRL, 3);
	if (retval != ERROR_OK)
		return retval;

	/* check the fpb is actually enabled */
	uint32_t fpctrl;
	retval = target_read_u32(target, FP_CTRL, &fpctrl);
	if (retval != ERROR_OK)
		return retval;

	if (fpctrl & 1)
		return ERROR_OK;

	return ERROR_FAIL;
}

static int cortex_m_endreset_event(struct target *target)
{
	unsigned int i;
	int retval;
	uint32_t dcb_demcr;
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	struct adiv5_dap *swjdp = cortex_m->armv7m.arm.dap;
	struct cortex_m_fp_comparator *fp_list = cortex_m->fp_comparator_list;
	struct cortex_m_dwt_comparator *dwt_list = cortex_m->dwt_comparator_list;

	/* REVISIT The four debug monitor bits are currently ignored... */
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DEMCR, &dcb_demcr);
	if (retval != ERROR_OK)
		return retval;
	LOG_DEBUG("DCB_DEMCR = 0x%8.8" PRIx32 "", dcb_demcr);

	/* this register is used for emulated dcc channel */
	retval = mem_ap_write_u32(armv7m->debug_ap, DCB_DCRDR, 0);
	if (retval != ERROR_OK)
		return retval;

	/* Enable debug requests */
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &cortex_m->dcb_dhcsr);
	if (retval != ERROR_OK)
		return retval;
	if (!(cortex_m->dcb_dhcsr & C_DEBUGEN)) {
		retval = cortex_m_write_debug_halt_mask(target, 0, C_HALT | C_STEP | C_MASKINTS);
		if (retval != ERROR_OK)
			return retval;
	}

	/* Restore proper interrupt masking setting for running CPU. */
	cortex_m_set_maskints_for_run(target);

	/* Enable features controlled by ITM and DWT blocks, and catch only
	 * the vectors we were told to pay attention to.
	 *
	 * Target firmware is responsible for all fault handling policy
	 * choices *EXCEPT* explicitly scripted overrides like "vector_catch"
	 * or manual updates to the NVIC SHCSR and CCR registers.
	 */
	retval = mem_ap_write_u32(armv7m->debug_ap, DCB_DEMCR, TRCENA | armv7m->demcr);
	if (retval != ERROR_OK)
		return retval;

	/* Paranoia: evidently some (early?) chips don't preserve all the
	 * debug state (including FPB, DWT, etc) across reset...
	 */

	/* Enable FPB */
	retval = cortex_m_enable_fpb(target);
	if (retval != ERROR_OK) {
		LOG_ERROR("Failed to enable the FPB");
		return retval;
	}

	cortex_m->fpb_enabled = true;

	/* Restore FPB registers */
	for (i = 0; i < cortex_m->fp_num_code + cortex_m->fp_num_lit; i++) {
		retval = target_write_u32(target, fp_list[i].fpcr_address, fp_list[i].fpcr_value);
		if (retval != ERROR_OK)
			return retval;
	}

	/* Restore DWT registers */
	for (i = 0; i < cortex_m->dwt_num_comp; i++) {
		retval = target_write_u32(target, dwt_list[i].dwt_comparator_address + 0,
				dwt_list[i].comp);
		if (retval != ERROR_OK)
			return retval;
		retval = target_write_u32(target, dwt_list[i].dwt_comparator_address + 4,
				dwt_list[i].mask);
		if (retval != ERROR_OK)
			return retval;
		retval = target_write_u32(target, dwt_list[i].dwt_comparator_address + 8,
				dwt_list[i].function);
		if (retval != ERROR_OK)
			return retval;
	}
	retval = dap_run(swjdp);
	if (retval != ERROR_OK)
		return retval;

	register_cache_invalidate(armv7m->arm.core_cache);

	/* make sure we have latest dhcsr flags */
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &cortex_m->dcb_dhcsr);

	return retval;
}

static int cortex_m_examine_debug_reason(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);

	/* THIS IS NOT GOOD, TODO - better logic for detection of debug state reason
	 * only check the debug reason if we don't know it already */

	if ((target->debug_reason != DBG_REASON_DBGRQ)
		&& (target->debug_reason != DBG_REASON_SINGLESTEP)) {
		if (cortex_m->nvic_dfsr & DFSR_BKPT) {
			target->debug_reason = DBG_REASON_BREAKPOINT;
			if (cortex_m->nvic_dfsr & DFSR_DWTTRAP)
				target->debug_reason = DBG_REASON_WPTANDBKPT;
		} else if (cortex_m->nvic_dfsr & DFSR_DWTTRAP)
			target->debug_reason = DBG_REASON_WATCHPOINT;
		else if (cortex_m->nvic_dfsr & DFSR_VCATCH)
			target->debug_reason = DBG_REASON_BREAKPOINT;
		else if (cortex_m->nvic_dfsr & DFSR_EXTERNAL)
			target->debug_reason = DBG_REASON_DBGRQ;
		else	/* HALTED */
			target->debug_reason = DBG_REASON_UNDEFINED;
	}

	return ERROR_OK;
}

static int cortex_m_examine_exception_reason(struct target *target)
{
	uint32_t shcsr = 0, except_sr = 0, cfsr = -1, except_ar = -1;
	struct armv7m_common *armv7m = target_to_armv7m(target);
	struct adiv5_dap *swjdp = armv7m->arm.dap;
	int retval;

	retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_SHCSR, &shcsr);
	if (retval != ERROR_OK)
		return retval;
	switch (armv7m->exception_number) {
		case 2:	/* NMI */
			break;
		case 3:	/* Hard Fault */
			retval = mem_ap_read_atomic_u32(armv7m->debug_ap, NVIC_HFSR, &except_sr);
			if (retval != ERROR_OK)
				return retval;
			if (except_sr & 0x40000000) {
				retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_CFSR, &cfsr);
				if (retval != ERROR_OK)
					return retval;
			}
			break;
		case 4:	/* Memory Management */
			retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_CFSR, &except_sr);
			if (retval != ERROR_OK)
				return retval;
			retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_MMFAR, &except_ar);
			if (retval != ERROR_OK)
				return retval;
			break;
		case 5:	/* Bus Fault */
			retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_CFSR, &except_sr);
			if (retval != ERROR_OK)
				return retval;
			retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_BFAR, &except_ar);
			if (retval != ERROR_OK)
				return retval;
			break;
		case 6:	/* Usage Fault */
			retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_CFSR, &except_sr);
			if (retval != ERROR_OK)
				return retval;
			break;
		case 11:	/* SVCall */
			break;
		case 12:	/* Debug Monitor */
			retval = mem_ap_read_u32(armv7m->debug_ap, NVIC_DFSR, &except_sr);
			if (retval != ERROR_OK)
				return retval;
			break;
		case 14:	/* PendSV */
			break;
		case 15:	/* SysTick */
			break;
		default:
			except_sr = 0;
			break;
	}
	retval = dap_run(swjdp);
	if (retval == ERROR_OK)
		LOG_DEBUG("%s SHCSR 0x%" PRIx32 ", SR 0x%" PRIx32
			", CFSR 0x%" PRIx32 ", AR 0x%" PRIx32,
			armv7m_exception_string(armv7m->exception_number),
			shcsr, except_sr, cfsr, except_ar);
	return retval;
}

static int cortex_m_debug_entry(struct target *target)
{
	int i;
	uint32_t xPSR;
	int retval;
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	struct arm *arm = &armv7m->arm;
	struct reg *r;

	LOG_DEBUG(" ");

	/* Do this really early to minimize the window where the MASKINTS erratum
	 * can pile up pending interrupts. */
	cortex_m_set_maskints_for_halt(target);

	cortex_m_clear_halt(target);
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &cortex_m->dcb_dhcsr);
	if (retval != ERROR_OK)
		return retval;

	retval = armv7m->examine_debug_reason(target);
	if (retval != ERROR_OK)
		return retval;

	/* Examine target state and mode
	 * First load register accessible through core debug port */
	int num_regs = arm->core_cache->num_regs;

	for (i = 0; i < num_regs; i++) {
		r = &armv7m->arm.core_cache->reg_list[i];
		if (!r->valid)
			arm->read_core_reg(target, r, i, ARM_MODE_ANY);
	}

	r = arm->cpsr;
	xPSR = buf_get_u32(r->value, 0, 32);

	/* For IT instructions xPSR must be reloaded on resume and clear on debug exec */
	if (xPSR & 0xf00) {
		r->dirty = r->valid;
		cortex_m_store_core_reg_u32(target, 16, xPSR & ~0xff);
	}

	/* Are we in an exception handler */
	if (xPSR & 0x1FF) {
		armv7m->exception_number = (xPSR & 0x1FF);

		arm->core_mode = ARM_MODE_HANDLER;
		arm->map = armv7m_msp_reg_map;
	} else {
		unsigned control = buf_get_u32(arm->core_cache
				->reg_list[ARMV7M_CONTROL].value, 0, 2);

		/* is this thread privileged? */
		arm->core_mode = control & 1
			? ARM_MODE_USER_THREAD
			: ARM_MODE_THREAD;

		/* which stack is it using? */
		if (control & 2)
			arm->map = armv7m_psp_reg_map;
		else
			arm->map = armv7m_msp_reg_map;

		armv7m->exception_number = 0;
	}

	if (armv7m->exception_number)
		cortex_m_examine_exception_reason(target);

	LOG_DEBUG("entered debug state in core mode: %s at PC 0x%" PRIx32 ", target->state: %s",
		arm_mode_name(arm->core_mode),
		buf_get_u32(arm->pc->value, 0, 32),
		target_state_name(target));

	if (armv7m->post_debug_entry) {
		retval = armv7m->post_debug_entry(target);
		if (retval != ERROR_OK)
			return retval;
	}

	return ERROR_OK;
}

static int cortex_m_poll(struct target *target)
{
	int detected_failure = ERROR_OK;
	int retval = ERROR_OK;
	enum target_state prev_target_state = target->state;
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;

	/* Read from Debug Halting Control and Status Register */
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &cortex_m->dcb_dhcsr);
	if (retval != ERROR_OK) {
		target->state = TARGET_UNKNOWN;
		return retval;
	}

	/* Recover from lockup.  See ARMv7-M architecture spec,
	 * section B1.5.15 "Unrecoverable exception cases".
	 */
	if (cortex_m->dcb_dhcsr & S_LOCKUP) {
		LOG_ERROR("%s -- clearing lockup after double fault",
			target_name(target));
		cortex_m_write_debug_halt_mask(target, C_HALT, 0);
		target->debug_reason = DBG_REASON_DBGRQ;

		/* We have to execute the rest (the "finally" equivalent, but
		 * still throw this exception again).
		 */
		detected_failure = ERROR_FAIL;

		/* refresh status bits */
		retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &cortex_m->dcb_dhcsr);
		if (retval != ERROR_OK)
			return retval;
	}

	if (cortex_m->dcb_dhcsr & S_RESET_ST) {
		if (target->state != TARGET_RESET) {
			target->state = TARGET_RESET;
			LOG_INFO("%s: external reset detected", target_name(target));
		}
		return ERROR_OK;
	}

	if (target->state == TARGET_RESET) {
		/* Cannot switch context while running so endreset is
		 * called with target->state == TARGET_RESET
		 */
		LOG_DEBUG("Exit from reset with dcb_dhcsr 0x%" PRIx32,
			cortex_m->dcb_dhcsr);
		retval = cortex_m_endreset_event(target);
		if (retval != ERROR_OK) {
			target->state = TARGET_UNKNOWN;
			return retval;
		}
		target->state = TARGET_RUNNING;
		prev_target_state = TARGET_RUNNING;
	}

	if (cortex_m->dcb_dhcsr & S_HALT) {
		target->state = TARGET_HALTED;

		if ((prev_target_state == TARGET_RUNNING) || (prev_target_state == TARGET_RESET)) {
			retval = cortex_m_debug_entry(target);
			if (retval != ERROR_OK)
				return retval;

			if (arm_semihosting(target, &retval) != 0)
				return retval;

			target_call_event_callbacks(target, TARGET_EVENT_HALTED);
		}
		if (prev_target_state == TARGET_DEBUG_RUNNING) {
			LOG_DEBUG(" ");
			retval = cortex_m_debug_entry(target);
			if (retval != ERROR_OK)
				return retval;

			target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
		}
	}

	/* REVISIT when S_SLEEP is set, it's in a Sleep or DeepSleep state.
	 * How best to model low power modes?
	 */

	if (target->state == TARGET_UNKNOWN) {
		/* check if processor is retiring instructions */
		if (cortex_m->dcb_dhcsr & S_RETIRE_ST) {
			target->state = TARGET_RUNNING;
			retval = ERROR_OK;
		}
	}

	/* Check that target is truly halted, since the target could be resumed externally */
	if ((prev_target_state == TARGET_HALTED) && !(cortex_m->dcb_dhcsr & S_HALT)) {
		/* registers are now invalid */
		register_cache_invalidate(armv7m->arm.core_cache);

		target->state = TARGET_RUNNING;
		LOG_WARNING("%s: external resume detected", target_name(target));
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		retval = ERROR_OK;
	}

	/* Did we detect a failure condition that we cleared? */
	if (detected_failure != ERROR_OK)
		retval = detected_failure;
	return retval;
}

static int cortex_m_halt(struct target *target)
{
	LOG_DEBUG("target->state: %s",
		target_state_name(target));

	if (target->state == TARGET_HALTED) {
		LOG_DEBUG("target was already halted");
		return ERROR_OK;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("target was in unknown state when halt was requested");

	if (target->state == TARGET_RESET) {
		if ((jtag_get_reset_config() & RESET_SRST_PULLS_TRST) && jtag_get_srst()) {
			LOG_ERROR("can't request a halt while in reset if nSRST pulls nTRST");
			return ERROR_TARGET_FAILURE;
		} else {
			/* we came here in a reset_halt or reset_init sequence
			 * debug entry was already prepared in cortex_m3_assert_reset()
			 */
			target->debug_reason = DBG_REASON_DBGRQ;

			return ERROR_OK;
		}
	}

	/* Write to Debug Halting Control and Status Register */
	cortex_m_write_debug_halt_mask(target, C_HALT, 0);

	/* Do this really early to minimize the window where the MASKINTS erratum
	 * can pile up pending interrupts. */
	cortex_m_set_maskints_for_halt(target);

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}

static int cortex_m_soft_reset_halt(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	uint32_t dcb_dhcsr = 0;
	int retval, timeout = 0;

	/* on single cortex_m MCU soft_reset_halt should be avoided as same functionality
	 * can be obtained by using 'reset halt' and 'cortex_m reset_config vectreset'.
	 * As this reset only uses VC_CORERESET it would only ever reset the cortex_m
	 * core, not the peripherals */
	LOG_DEBUG("soft_reset_halt is discouraged, please use 'reset halt' instead.");

	/* Set C_DEBUGEN */
	retval = cortex_m_write_debug_halt_mask(target, 0, C_STEP | C_MASKINTS);
	if (retval != ERROR_OK)
		return retval;

	/* Enter debug state on reset; restore DEMCR in endreset_event() */
	retval = mem_ap_write_u32(armv7m->debug_ap, DCB_DEMCR,
			TRCENA | VC_HARDERR | VC_BUSERR | VC_CORERESET);
	if (retval != ERROR_OK)
		return retval;

	/* Request a core-only reset */
	retval = mem_ap_write_atomic_u32(armv7m->debug_ap, NVIC_AIRCR,
			AIRCR_VECTKEY | AIRCR_VECTRESET);
	if (retval != ERROR_OK)
		return retval;
	target->state = TARGET_RESET;

	/* registers are now invalid */
	register_cache_invalidate(cortex_m->armv7m.arm.core_cache);

	while (timeout < 100) {
		retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &dcb_dhcsr);
		if (retval == ERROR_OK) {
			retval = mem_ap_read_atomic_u32(armv7m->debug_ap, NVIC_DFSR,
					&cortex_m->nvic_dfsr);
			if (retval != ERROR_OK)
				return retval;
			if ((dcb_dhcsr & S_HALT)
				&& (cortex_m->nvic_dfsr & DFSR_VCATCH)) {
				LOG_DEBUG("system reset-halted, DHCSR 0x%08x, "
					"DFSR 0x%08x",
					(unsigned) dcb_dhcsr,
					(unsigned) cortex_m->nvic_dfsr);
				cortex_m_poll(target);
				/* FIXME restore user's vector catch config */
				return ERROR_OK;
			} else
				LOG_DEBUG("waiting for system reset-halt, "
					"DHCSR 0x%08x, %d ms",
					(unsigned) dcb_dhcsr, timeout);
		}
		timeout++;
		alive_sleep(1);
	}

	return ERROR_OK;
}

static int cortex_m_resume(struct target *target, int current,
	target_addr_t address, int handle_breakpoints, int debug_execution)
{
	struct armv7m_common *armv7m = target_to_armv7m(target);
	struct breakpoint *breakpoint = NULL;
	uint32_t resume_pc;
	struct reg *r;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (!debug_execution) {
		target_free_all_working_areas(target);
		cortex_m_enable_breakpoints(target);
		cortex_m_enable_watchpoints(target);
	}

	if (debug_execution) {
		r = armv7m->arm.core_cache->reg_list + ARMV7M_PRIMASK;

		/* Disable interrupts */
		/* We disable interrupts in the PRIMASK register instead of
		 * masking with C_MASKINTS.  This is probably the same issue
		 * as Cortex-M3 Erratum 377493 (fixed in r1p0):  C_MASKINTS
		 * in parallel with disabled interrupts can cause local faults
		 * to not be taken.
		 *
		 * REVISIT this clearly breaks non-debug execution, since the
		 * PRIMASK register state isn't saved/restored...  workaround
		 * by never resuming app code after debug execution.
		 */
		buf_set_u32(r->value, 0, 1, 1);
		r->dirty = true;
		r->valid = true;

		/* Make sure we are in Thumb mode */
		r = armv7m->arm.cpsr;
		buf_set_u32(r->value, 24, 1, 1);
		r->dirty = true;
		r->valid = true;
	}

	/* current = 1: continue on current pc, otherwise continue at <address> */
	r = armv7m->arm.pc;
	if (!current) {
		buf_set_u32(r->value, 0, 32, address);
		r->dirty = true;
		r->valid = true;
	}

	/* if we halted last time due to a bkpt instruction
	 * then we have to manually step over it, otherwise
	 * the core will break again */

	if (!breakpoint_find(target, buf_get_u32(r->value, 0, 32))
		&& !debug_execution)
		armv7m_maybe_skip_bkpt_inst(target, NULL);

	resume_pc = buf_get_u32(r->value, 0, 32);

	armv7m_restore_context(target);

	/* the front-end may request us not to handle breakpoints */
	if (handle_breakpoints) {
		/* Single step past breakpoint at current address */
		breakpoint = breakpoint_find(target, resume_pc);
		if (breakpoint) {
			LOG_DEBUG("unset breakpoint at " TARGET_ADDR_FMT " (ID: %" PRIu32 ")",
				breakpoint->address,
				breakpoint->unique_id);
			cortex_m_unset_breakpoint(target, breakpoint);
			cortex_m_single_step_core(target);
			cortex_m_set_breakpoint(target, breakpoint);
		}
	}

	/* Restart core */
	cortex_m_set_maskints_for_run(target);
	cortex_m_write_debug_halt_mask(target, 0, C_HALT);

	target->debug_reason = DBG_REASON_NOTHALTED;

	/* registers are now invalid */
	register_cache_invalidate(armv7m->arm.core_cache);

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("target resumed at 0x%" PRIx32 "", resume_pc);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("target debug resumed at 0x%" PRIx32 "", resume_pc);
	}

	return ERROR_OK;
}

/* int irqstepcount = 0; */
static int cortex_m_step(struct target *target, int current,
	target_addr_t address, int handle_breakpoints)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	struct breakpoint *breakpoint = NULL;
	struct reg *pc = armv7m->arm.pc;
	bool bkpt_inst_found = false;
	int retval;
	bool isr_timed_out = false;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* current = 1: continue on current pc, otherwise continue at <address> */
	if (!current)
		buf_set_u32(pc->value, 0, 32, address);

	uint32_t pc_value = buf_get_u32(pc->value, 0, 32);

	/* the front-end may request us not to handle breakpoints */
	if (handle_breakpoints) {
		breakpoint = breakpoint_find(target, pc_value);
		if (breakpoint)
			cortex_m_unset_breakpoint(target, breakpoint);
	}

	armv7m_maybe_skip_bkpt_inst(target, &bkpt_inst_found);

	target->debug_reason = DBG_REASON_SINGLESTEP;

	armv7m_restore_context(target);

	target_call_event_callbacks(target, TARGET_EVENT_RESUMED);

	/* if no bkpt instruction is found at pc then we can perform
	 * a normal step, otherwise we have to manually step over the bkpt
	 * instruction - as such simulate a step */
	if (bkpt_inst_found == false) {
		if (cortex_m->isrmasking_mode != CORTEX_M_ISRMASK_AUTO) {
			/* Automatic ISR masking mode off: Just step over the next
			 * instruction, with interrupts on or off as appropriate. */
			cortex_m_set_maskints_for_step(target);
			cortex_m_write_debug_halt_mask(target, C_STEP, C_HALT);
		} else {
			/* Process interrupts during stepping in a way they don't interfere
			 * debugging.
			 *
			 * Principle:
			 *
			 * Set a temporary break point at the current pc and let the core run
			 * with interrupts enabled. Pending interrupts get served and we run
			 * into the breakpoint again afterwards. Then we step over the next
			 * instruction with interrupts disabled.
			 *
			 * If the pending interrupts don't complete within time, we leave the
			 * core running. This may happen if the interrupts trigger faster
			 * than the core can process them or the handler doesn't return.
			 *
			 * If no more breakpoints are available we simply do a step with
			 * interrupts enabled.
			 *
			 */

			/* 2012-09-29 ph
			 *
			 * If a break point is already set on the lower half word then a break point on
			 * the upper half word will not break again when the core is restarted. So we
			 * just step over the instruction with interrupts disabled.
			 *
			 * The documentation has no information about this, it was found by observation
			 * on STM32F1 and STM32F2. Proper explanation welcome. STM32F0 doesn't seem to
			 * suffer from this problem.
			 *
			 * To add some confusion: pc_value has bit 0 always set, while the breakpoint
			 * address has it always cleared. The former is done to indicate thumb mode
			 * to gdb.
			 *
			 */
			if ((pc_value & 0x02) && breakpoint_find(target, pc_value & ~0x03)) {
				LOG_DEBUG("Stepping over next instruction with interrupts disabled");
				cortex_m_write_debug_halt_mask(target, C_HALT | C_MASKINTS, 0);
				cortex_m_write_debug_halt_mask(target, C_STEP, C_HALT);
				/* Re-enable interrupts if appropriate */
				cortex_m_write_debug_halt_mask(target, C_HALT, 0);
				cortex_m_set_maskints_for_halt(target);
			} else {

				/* Set a temporary break point */
				if (breakpoint) {
					retval = cortex_m_set_breakpoint(target, breakpoint);
				} else {
					enum breakpoint_type type = BKPT_HARD;
					if (cortex_m->fp_rev == 0 && pc_value > 0x1FFFFFFF) {
						/* FPB rev.1 cannot handle such addr, try BKPT instr */
						type = BKPT_SOFT;
					}
					retval = breakpoint_add(target, pc_value, 2, type);
				}

				bool tmp_bp_set = (retval == ERROR_OK);

				/* No more breakpoints left, just do a step */
				if (!tmp_bp_set) {
					cortex_m_set_maskints_for_step(target);
					cortex_m_write_debug_halt_mask(target, C_STEP, C_HALT);
					/* Re-enable interrupts if appropriate */
					cortex_m_write_debug_halt_mask(target, C_HALT, 0);
					cortex_m_set_maskints_for_halt(target);
				} else {
					/* Start the core */
					LOG_DEBUG("Starting core to serve pending interrupts");
					int64_t t_start = timeval_ms();
					cortex_m_set_maskints_for_run(target);
					cortex_m_write_debug_halt_mask(target, 0, C_HALT | C_STEP);

					/* Wait for pending handlers to complete or timeout */
					do {
						retval = mem_ap_read_atomic_u32(armv7m->debug_ap,
								DCB_DHCSR,
								&cortex_m->dcb_dhcsr);
						if (retval != ERROR_OK) {
							target->state = TARGET_UNKNOWN;
							return retval;
						}
						isr_timed_out = ((timeval_ms() - t_start) > 500);
					} while (!((cortex_m->dcb_dhcsr & S_HALT) || isr_timed_out));

					/* only remove breakpoint if we created it */
					if (breakpoint)
						cortex_m_unset_breakpoint(target, breakpoint);
					else {
						/* Remove the temporary breakpoint */
						breakpoint_remove(target, pc_value);
					}

					if (isr_timed_out) {
						LOG_DEBUG("Interrupt handlers didn't complete within time, "
							"leaving target running");
					} else {
						/* Step over next instruction with interrupts disabled */
						cortex_m_set_maskints_for_step(target);
						cortex_m_write_debug_halt_mask(target,
							C_HALT | C_MASKINTS,
							0);
						cortex_m_write_debug_halt_mask(target, C_STEP, C_HALT);
						/* Re-enable interrupts if appropriate */
						cortex_m_write_debug_halt_mask(target, C_HALT, 0);
						cortex_m_set_maskints_for_halt(target);
					}
				}
			}
		}
	}

	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &cortex_m->dcb_dhcsr);
	if (retval != ERROR_OK)
		return retval;

	/* registers are now invalid */
	register_cache_invalidate(armv7m->arm.core_cache);

	if (breakpoint)
		cortex_m_set_breakpoint(target, breakpoint);

	if (isr_timed_out) {
		/* Leave the core running. The user has to stop execution manually. */
		target->debug_reason = DBG_REASON_NOTHALTED;
		target->state = TARGET_RUNNING;
		return ERROR_OK;
	}

	LOG_DEBUG("target stepped dcb_dhcsr = 0x%" PRIx32
		" nvic_icsr = 0x%" PRIx32,
		cortex_m->dcb_dhcsr, cortex_m->nvic_icsr);

	retval = cortex_m_debug_entry(target);
	if (retval != ERROR_OK)
		return retval;
	target_call_event_callbacks(target, TARGET_EVENT_HALTED);

	LOG_DEBUG("target stepped dcb_dhcsr = 0x%" PRIx32
		" nvic_icsr = 0x%" PRIx32,
		cortex_m->dcb_dhcsr, cortex_m->nvic_icsr);

	return ERROR_OK;
}

static int km1m4xx_m_assert_reset(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	enum cortex_m_soft_reset_config reset_config = cortex_m->soft_reset_config;

	LOG_DEBUG("target->state: %s",
		target_state_name(target));

	enum reset_types jtag_reset_config = jtag_get_reset_config();

	if (target_has_event_action(target, TARGET_EVENT_RESET_ASSERT)) {
		/* allow scripts to override the reset event */

		target_handle_event(target, TARGET_EVENT_RESET_ASSERT);
		register_cache_invalidate(cortex_m->armv7m.arm.core_cache);
		target->state = TARGET_RESET;

		return ERROR_OK;
	}

	/* some cores support connecting while srst is asserted
	 * use that mode is it has been configured */

	bool srst_asserted = false;

	if (!target_was_examined(target)) {
		if (jtag_reset_config & RESET_HAS_SRST) {
			adapter_assert_reset();
			if (target->reset_halt)
				LOG_ERROR("Target not examined, will not halt after reset!");
			return ERROR_OK;
		} else {
			LOG_ERROR("Target not examined, reset NOT asserted!");
			return ERROR_FAIL;
		}
	}

	if ((jtag_reset_config & RESET_HAS_SRST) &&
	    (jtag_reset_config & RESET_SRST_NO_GATING)) {
		adapter_assert_reset();
		srst_asserted = true;
	}

	/* Start of original procedure for KM1M4XX series */
	uint32_t	optreg0	= 0;
	uint32_t	cpuid	= 0;
	int			ret		= 0;
	uint32_t	optreg0_key	= 0x672c0000;

	/* Disable WDT */
	ret = target_read_u32(target, 0xf0102010, &optreg0);
	if (ret != ERROR_OK) {
		return ret;
	}
	ret = target_write_u32(target, 0xf0102010, ((optreg0 & 0xffff) | optreg0_key | 0x00000004));
	if (ret != ERROR_OK) {
		return ret;
	}

	ret = target_read_u32(target, 0xe000ed00, &cpuid);
	if (ret != ERROR_OK) {
		return ret;
	}

	LOG_INFO("CPUID = 0x%08x\n", cpuid);
	if (km1m4xx_key_set == 1) {
		/* Unlock DAP */
		target_write_u32(target, 0xf0102000, km1m4xx_key_data[0]);
		target_write_u32(target, 0xf0102004, km1m4xx_key_data[1]);
		target_write_u32(target, 0xf0102008, km1m4xx_key_data[2]);
		target_write_u32(target, 0xf010200c, km1m4xx_key_data[3]);

		/* Still if the CPUID is 0x00000000, the security can not be unlocked */
		ret = target_read_u32(target, 0xe000ed00, &cpuid);
		if (ret != ERROR_OK) {
			return ret;
		}
		LOG_INFO("CPUID = 0x%08x\n", cpuid);
		if (cpuid == 0x00000000) {
			LOG_ERROR("Cannot unlock security");
			return ERROR_FAIL;
		}
	}
	/* End of original procedure for KM1M4XX series */

	/* Enable debug requests */
	int retval;
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR, &cortex_m->dcb_dhcsr);
	/* Store important errors instead of failing and proceed to reset assert */

	if (retval != ERROR_OK || !(cortex_m->dcb_dhcsr & C_DEBUGEN))
		retval = cortex_m_write_debug_halt_mask(target, 0, C_HALT | C_STEP | C_MASKINTS);

	/* If the processor is sleeping in a WFI or WFE instruction, the
	 * C_HALT bit must be asserted to regain control */
	if (retval == ERROR_OK && (cortex_m->dcb_dhcsr & S_SLEEP))
		retval = cortex_m_write_debug_halt_mask(target, C_HALT, 0);

	mem_ap_write_u32(armv7m->debug_ap, DCB_DCRDR, 0);
	/* Ignore less important errors */

	if (!target->reset_halt) {
		/* Set/Clear C_MASKINTS in a separate operation */
		cortex_m_set_maskints_for_run(target);

		/* clear any debug flags before resuming */
		cortex_m_clear_halt(target);

		/* clear C_HALT in dhcsr reg */
		cortex_m_write_debug_halt_mask(target, 0, C_HALT);
	} else {
		/* Halt in debug on reset; endreset_event() restores DEMCR.
		 *
		 * REVISIT catching BUSERR presumably helps to defend against
		 * bad vector table entries.  Should this include MMERR or
		 * other flags too?
		 */
		int retval2;
		retval2 = mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DEMCR,
				TRCENA | VC_HARDERR | VC_BUSERR | VC_CORERESET);
		if (retval != ERROR_OK || retval2 != ERROR_OK)
			LOG_INFO("AP write error, reset will not halt");
	}

	if (jtag_reset_config & RESET_HAS_SRST) {
		/* default to asserting srst */
		if (!srst_asserted)
			adapter_assert_reset();

		/* srst is asserted, ignore AP access errors */
		retval = ERROR_OK;
	} else {
		/* Use a standard Cortex-M3 software reset mechanism.
		 * We default to using VECRESET as it is supported on all current cores
		 * (except Cortex-M0, M0+ and M1 which support SYSRESETREQ only!)
		 * This has the disadvantage of not resetting the peripherals, so a
		 * reset-init event handler is needed to perform any peripheral resets.
		 */
		if (!cortex_m->vectreset_supported
				&& reset_config == CORTEX_M_RESET_VECTRESET) {
			reset_config = CORTEX_M_RESET_SYSRESETREQ;
			LOG_WARNING("VECTRESET is not supported on this Cortex-M core, using SYSRESETREQ instead.");
			LOG_WARNING("Set 'cortex_m reset_config sysresetreq'.");
		}

		LOG_DEBUG("Using Cortex-M %s", (reset_config == CORTEX_M_RESET_SYSRESETREQ)
			? "SYSRESETREQ" : "VECTRESET");

		if (reset_config == CORTEX_M_RESET_VECTRESET) {
			LOG_WARNING("Only resetting the Cortex-M core, use a reset-init event "
				"handler to reset any peripherals or configure hardware srst support.");
		}

		int retval3;
		retval3 = mem_ap_write_atomic_u32(armv7m->debug_ap, NVIC_AIRCR,
				AIRCR_VECTKEY | ((reset_config == CORTEX_M_RESET_SYSRESETREQ)
				? AIRCR_SYSRESETREQ : AIRCR_VECTRESET));
		if (retval3 != ERROR_OK)
			LOG_DEBUG("Ignoring AP write error right after reset");

		retval3 = dap_dp_init(armv7m->debug_ap->dap);
		if (retval3 != ERROR_OK)
			LOG_ERROR("DP initialisation failed");

		else {
			/* I do not know why this is necessary, but it
			 * fixes strange effects (step/resume cause NMI
			 * after reset) on LM3S6918 -- Michael Schwingen
			 */
			uint32_t tmp;
			mem_ap_read_atomic_u32(armv7m->debug_ap, NVIC_AIRCR, &tmp);
		}
	}

	target->state = TARGET_RESET;
	jtag_sleep(50000);

	register_cache_invalidate(cortex_m->armv7m.arm.core_cache);

	/* now return stored error code if any */
	if (retval != ERROR_OK)
		return retval;

	if (target->reset_halt) {
		retval = target_halt(target);
		if (retval != ERROR_OK)
			return retval;
	}

	return ERROR_OK;
}

static int cortex_m_deassert_reset(struct target *target)
{
	struct armv7m_common *armv7m = &target_to_cm(target)->armv7m;

	LOG_DEBUG("target->state: %s",
		target_state_name(target));

	/* deassert reset lines */
	adapter_deassert_reset();

	enum reset_types jtag_reset_config = jtag_get_reset_config();

	if ((jtag_reset_config & RESET_HAS_SRST) &&
	    !(jtag_reset_config & RESET_SRST_NO_GATING) &&
		target_was_examined(target)) {
		int retval = dap_dp_init(armv7m->debug_ap->dap);
		if (retval != ERROR_OK) {
			LOG_ERROR("DP initialisation failed");
			return retval;
		}
	}

	return ERROR_OK;
}

static int cortex_m_load_core_reg_u32(struct target *target,
		uint32_t num, uint32_t *value)
{
	int retval;

	/* NOTE:  we "know" here that the register identifiers used
	 * in the v7m header match the Cortex-M3 Debug Core Register
	 * Selector values for R0..R15, xPSR, MSP, and PSP.
	 */
	switch (num) {
		case 0 ... 18:
			/* read a normal core register */
			retval = cortexm_dap_read_coreregister_u32(target, value, num);

			if (retval != ERROR_OK) {
				LOG_ERROR("JTAG failure %i", retval);
				return ERROR_JTAG_DEVICE_ERROR;
			}
			LOG_DEBUG("load from core reg %i  value 0x%" PRIx32 "", (int)num, *value);
			break;

		case ARMV7M_FPSCR:
			/* Floating-point Status and Registers */
			retval = target_write_u32(target, DCB_DCRSR, 0x21);
			if (retval != ERROR_OK)
				return retval;
			retval = target_read_u32(target, DCB_DCRDR, value);
			if (retval != ERROR_OK)
				return retval;
			LOG_DEBUG("load from FPSCR  value 0x%" PRIx32, *value);
			break;

		case ARMV7M_REGSEL_S0 ... ARMV7M_REGSEL_S31:
			/* Floating-point Status and Registers */
			retval = target_write_u32(target, DCB_DCRSR, num - ARMV7M_REGSEL_S0 + 0x40);
			if (retval != ERROR_OK)
				return retval;
			retval = target_read_u32(target, DCB_DCRDR, value);
			if (retval != ERROR_OK)
				return retval;
			LOG_DEBUG("load from FPU reg S%d  value 0x%" PRIx32,
				  (int)(num - ARMV7M_REGSEL_S0), *value);
			break;

		case ARMV7M_PRIMASK:
		case ARMV7M_BASEPRI:
		case ARMV7M_FAULTMASK:
		case ARMV7M_CONTROL:
			/* Cortex-M3 packages these four registers as bitfields
			 * in one Debug Core register.  So say r0 and r2 docs;
			 * it was removed from r1 docs, but still works.
			 */
			cortexm_dap_read_coreregister_u32(target, value, 20);

			switch (num) {
				case ARMV7M_PRIMASK:
					*value = buf_get_u32((uint8_t *)value, 0, 1);
					break;

				case ARMV7M_BASEPRI:
					*value = buf_get_u32((uint8_t *)value, 8, 8);
					break;

				case ARMV7M_FAULTMASK:
					*value = buf_get_u32((uint8_t *)value, 16, 1);
					break;

				case ARMV7M_CONTROL:
					*value = buf_get_u32((uint8_t *)value, 24, 2);
					break;
			}

			LOG_DEBUG("load from special reg %i value 0x%" PRIx32 "", (int)num, *value);
			break;

		default:
			return ERROR_COMMAND_SYNTAX_ERROR;
	}

	return ERROR_OK;
}

static int cortex_m_store_core_reg_u32(struct target *target,
		uint32_t num, uint32_t value)
{
	int retval;
	uint32_t reg;
	struct armv7m_common *armv7m = target_to_armv7m(target);

	/* NOTE:  we "know" here that the register identifiers used
	 * in the v7m header match the Cortex-M3 Debug Core Register
	 * Selector values for R0..R15, xPSR, MSP, and PSP.
	 */
	switch (num) {
		case 0 ... 18:
			retval = cortexm_dap_write_coreregister_u32(target, value, num);
			if (retval != ERROR_OK) {
				struct reg *r;

				LOG_ERROR("JTAG failure");
				r = armv7m->arm.core_cache->reg_list + num;
				r->dirty = r->valid;
				return ERROR_JTAG_DEVICE_ERROR;
			}
			LOG_DEBUG("write core reg %i value 0x%" PRIx32 "", (int)num, value);
			break;

		case ARMV7M_FPSCR:
			/* Floating-point Status and Registers */
			retval = target_write_u32(target, DCB_DCRDR, value);
			if (retval != ERROR_OK)
				return retval;
			retval = target_write_u32(target, DCB_DCRSR, 0x21 | (1<<16));
			if (retval != ERROR_OK)
				return retval;
			LOG_DEBUG("write FPSCR value 0x%" PRIx32, value);
			break;

		case ARMV7M_REGSEL_S0 ... ARMV7M_REGSEL_S31:
			/* Floating-point Status and Registers */
			retval = target_write_u32(target, DCB_DCRDR, value);
			if (retval != ERROR_OK)
				return retval;
			retval = target_write_u32(target, DCB_DCRSR, (num - ARMV7M_REGSEL_S0 + 0x40) | (1<<16));
			if (retval != ERROR_OK)
				return retval;
			LOG_DEBUG("write FPU reg S%d  value 0x%" PRIx32,
				  (int)(num - ARMV7M_REGSEL_S0), value);
			break;

		case ARMV7M_PRIMASK:
		case ARMV7M_BASEPRI:
		case ARMV7M_FAULTMASK:
		case ARMV7M_CONTROL:
			/* Cortex-M3 packages these four registers as bitfields
			 * in one Debug Core register.  So say r0 and r2 docs;
			 * it was removed from r1 docs, but still works.
			 */
			cortexm_dap_read_coreregister_u32(target, &reg, 20);

			switch (num) {
				case ARMV7M_PRIMASK:
					buf_set_u32((uint8_t *)&reg, 0, 1, value);
					break;

				case ARMV7M_BASEPRI:
					buf_set_u32((uint8_t *)&reg, 8, 8, value);
					break;

				case ARMV7M_FAULTMASK:
					buf_set_u32((uint8_t *)&reg, 16, 1, value);
					break;

				case ARMV7M_CONTROL:
					buf_set_u32((uint8_t *)&reg, 24, 2, value);
					break;
			}

			cortexm_dap_write_coreregister_u32(target, reg, 20);

			LOG_DEBUG("write special reg %i value 0x%" PRIx32 " ", (int)num, value);
			break;

		default:
			return ERROR_COMMAND_SYNTAX_ERROR;
	}

	return ERROR_OK;
}

static int cortex_m_read_memory(struct target *target, target_addr_t address,
	uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct armv7m_common *armv7m = target_to_armv7m(target);

	if (armv7m->arm.arch == ARM_ARCH_V6M) {
		/* armv6m does not handle unaligned memory access */
		if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
			return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	return mem_ap_read_buf(armv7m->debug_ap, buffer, size, count, address);
}

static int cortex_m_write_memory(struct target *target, target_addr_t address,
	uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct armv7m_common *armv7m = target_to_armv7m(target);

	if (armv7m->arm.arch == ARM_ARCH_V6M) {
		/* armv6m does not handle unaligned memory access */
		if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
			return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	return mem_ap_write_buf(armv7m->debug_ap, buffer, size, count, address);
}

static int cortex_m_init_target(struct command_context *cmd_ctx,
	struct target *target)
{
	armv7m_build_reg_cache(target);
	arm_semihosting_init(target);
	return ERROR_OK;
}

static int cortex_m_dcc_read(struct target *target, uint8_t *value, uint8_t *ctrl)
{
	struct armv7m_common *armv7m = target_to_armv7m(target);
	uint16_t dcrdr;
	uint8_t buf[2];
	int retval;

	retval = mem_ap_read_buf_noincr(armv7m->debug_ap, buf, 2, 1, DCB_DCRDR);
	if (retval != ERROR_OK)
		return retval;

	dcrdr = target_buffer_get_u16(target, buf);
	*ctrl = (uint8_t)dcrdr;
	*value = (uint8_t)(dcrdr >> 8);

	LOG_DEBUG("data 0x%x ctrl 0x%x", *value, *ctrl);

	/* write ack back to software dcc register
	 * signify we have read data */
	if (dcrdr & (1 << 0)) {
		target_buffer_set_u16(target, buf, 0);
		retval = mem_ap_write_buf_noincr(armv7m->debug_ap, buf, 2, 1, DCB_DCRDR);
		if (retval != ERROR_OK)
			return retval;
	}

	return ERROR_OK;
}

static int cortex_m_target_request_data(struct target *target,
	uint32_t size, uint8_t *buffer)
{
	uint8_t data;
	uint8_t ctrl;
	uint32_t i;

	for (i = 0; i < (size * 4); i++) {
		int retval = cortex_m_dcc_read(target, &data, &ctrl);
		if (retval != ERROR_OK)
			return retval;
		buffer[i] = data;
	}

	return ERROR_OK;
}

static int cortex_m_handle_target_request(void *priv)
{
	struct target *target = priv;
	if (!target_was_examined(target))
		return ERROR_OK;

	if (!target->dbg_msg_enabled)
		return ERROR_OK;

	if (target->state == TARGET_RUNNING) {
		uint8_t data;
		uint8_t ctrl;
		int retval;

		retval = cortex_m_dcc_read(target, &data, &ctrl);
		if (retval != ERROR_OK)
			return retval;

		/* check if we have data */
		if (ctrl & (1 << 0)) {
			uint32_t request;

			/* we assume target is quick enough */
			request = data;
			for (int i = 1; i <= 3; i++) {
				retval = cortex_m_dcc_read(target, &data, &ctrl);
				if (retval != ERROR_OK)
					return retval;
				request |= ((uint32_t)data << (i * 8));
			}
			target_request(target, request);
		}
	}

	return ERROR_OK;
}

static int cortex_m_init_arch_info(struct target *target,
	struct cortex_m_common *cortex_m, struct adiv5_dap *dap)
{
	struct armv7m_common *armv7m = &cortex_m->armv7m;

	armv7m_init_arch_info(target, armv7m);

	/* default reset mode is to use srst if fitted
	 * if not it will use CORTEX_M3_RESET_VECTRESET */
	cortex_m->soft_reset_config = CORTEX_M_RESET_VECTRESET;

	armv7m->arm.dap = dap;

	/* register arch-specific functions */
	armv7m->examine_debug_reason = cortex_m_examine_debug_reason;

	armv7m->post_debug_entry = NULL;

	armv7m->pre_restore_context = NULL;

	armv7m->load_core_reg_u32 = cortex_m_load_core_reg_u32;
	armv7m->store_core_reg_u32 = cortex_m_store_core_reg_u32;

	target_register_timer_callback(cortex_m_handle_target_request, 1,
		TARGET_TIMER_TYPE_PERIODIC, target);

	return ERROR_OK;
}

static int cortex_m_target_create(struct target *target, Jim_Interp *interp)
{
	struct adiv5_private_config *pc;

	pc = (struct adiv5_private_config *)target->private_config;
	if (adiv5_verify_config(pc) != ERROR_OK)
		return ERROR_FAIL;

	struct cortex_m_common *cortex_m = calloc(1, sizeof(struct cortex_m_common));
	if (cortex_m == NULL) {
		LOG_ERROR("No memory creating target");
		return ERROR_FAIL;
	}

	cortex_m->common_magic = CORTEX_M_COMMON_MAGIC;
	cortex_m->apsel = pc->ap_num;

	cortex_m_init_arch_info(target, cortex_m, pc->dap);

	return ERROR_OK;
}

COMMAND_HANDLER(km1m4xx_handle_calc_image_checksum_command)
{
	uint8_t			*buffer;
	size_t			buf_cnt;
	uint32_t		image_size;
	struct image	image;
	unsigned int	i;
	int 			retval;
	uint32_t		checksum = 0;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	image.base_address_set	= 0;
	image.base_address		= 0;
	image.start_address_set	= 0;

	retval = image_open(&image, CMD_ARGV[0], NULL);
	if (retval != ERROR_OK)
		return retval;

	image_size = 0x0;
	retval = ERROR_OK;
	for (i = 0; i < image.num_sections; i++) {
		buffer = malloc(image.sections[i].size);
		if (buffer == NULL) {
			command_print(CMD,
					"error allocating buffer for section (%d bytes)",
					(int)(image.sections[i].size));
			break;
		}
		retval = image_read_section(&image, i, 0x0, image.sections[i].size, buffer, &buf_cnt);
		if (retval != ERROR_OK) {
			free(buffer);
			break;
		}

		/* calculate checksum of image */
		retval = image_calculate_checksum(buffer, buf_cnt, &checksum);
		if (retval != ERROR_OK) {
			free(buffer);
			break;
		}

		LOG_INFO(	"checksum of section:0x%08x-0x%08x is 0x%08x\n",
					(uint32_t)image.sections[i].base_address,
					(uint32_t)(image.sections[i].base_address + buf_cnt - 1),
					checksum);

		free(buffer);
		image_size += buf_cnt;
	}
	return retval;
}

COMMAND_HANDLER(km1m4xx_handle_calc_memory_checksum_command)
{
	uint8_t			*buffer;
	size_t			buf_cnt;
	uint32_t		image_size;
	struct image	image;
	unsigned int	i;
	int 			retval;
	uint32_t		checksum = 0;
	uint32_t		mem_checksum = 0;
	struct target	*target = get_current_target(CMD_CTX);

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (!target) {
		LOG_ERROR("no target selected");
		return ERROR_FAIL;
	}

	image.base_address_set	= 0;
	image.base_address		= 0;
	image.start_address_set	= 0;

	retval = image_open(&image, CMD_ARGV[0], NULL);
	if (retval != ERROR_OK)
		return retval;

	image_size = 0x0;
	retval = ERROR_OK;
	for (i = 0; i < image.num_sections; i++) {
		buffer = malloc(image.sections[i].size);
		if (!buffer) {
			command_print(CMD,
					"error allocating buffer for section (%d bytes)",
					(int)(image.sections[i].size));
			break;
		}
		retval = image_read_section(&image, i, 0x0, image.sections[i].size, buffer, &buf_cnt);
		if (retval != ERROR_OK) {
			free(buffer);
			break;
		}

		/* calculate checksum of image */
		retval = image_calculate_checksum(buffer, buf_cnt, &checksum);
		if (retval != ERROR_OK) {
			free(buffer);
			break;
		}

		retval = target_checksum_memory(target, image.sections[i].base_address, buf_cnt, &mem_checksum);
		if (retval != ERROR_OK) {
			free(buffer);
			break;
		}

		LOG_INFO(	"checksum of section:0x%08x-0x%08x is (file)0x%08x, (memory)0x%08x\n",
					(uint32_t)image.sections[i].base_address,
					(uint32_t)(image.sections[i].base_address + buf_cnt - 1),
					checksum, mem_checksum);

		free(buffer);
		image_size += buf_cnt;
	}

	return retval;
}

COMMAND_HANDLER(km1m4xx_handle_keycode_file_command)
{
	FILE		*fp_keyfile;
	char		key_str[16];
	int			key_count;

	if (CMD_ARGC != 1) {
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	fp_keyfile = fopen(CMD_ARGV[0], "r");
	if (fp_keyfile == NULL) {
		return ERROR_FAIL;
	}

	key_count = 0;
	while (fgets(key_str, 15, fp_keyfile) != NULL) {
		km1m4xx_key_data[key_count++] = strtoul(key_str, NULL, 16);
	}
	fclose(fp_keyfile);

	km1m4xx_key_set = 1;

	return ERROR_OK;
}

COMMAND_HANDLER(km1m4xx_handle_keycode_data_command)
{
	char		key_str[16];
	int			key_count;

	if (CMD_ARGC != 4) {
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	for (key_count = 0; key_count < 4; key_count++) {
		if (strncmp(CMD_ARGV[key_count], "0x", 2) != 0) {
			strcpy(key_str, "0x");
		} else {
			key_str[0] = '\0';
		}
		strcat(key_str, CMD_ARGV[key_count]);
		COMMAND_PARSE_NUMBER(u32, key_str, km1m4xx_key_data[key_count]);
	}

	km1m4xx_key_set = 1;
	return ERROR_OK;
}

static const struct command_registration km1m4xx_subcommand_handlers[] = {
	{
		.name		= "calc_image_checksum",
		.handler	= km1m4xx_handle_calc_image_checksum_command,
		.mode		= COMMAND_ANY,
		.usage		= "filename",
		.help		= "calculate checksum of image file",
	},
	{
		.name		= "calc_memory_checksum",
		.handler	= km1m4xx_handle_calc_memory_checksum_command,
		.mode		= COMMAND_EXEC,
		.usage		= "filename",
		.help		= "calculate checksum of target memory and image file",
	},
	{
		.name		= "keycode_file",
		.handler	= km1m4xx_handle_keycode_file_command,
		.mode		= COMMAND_CONFIG,
		.usage		= "filename",
		.help		= "Set keycode file for authentication",
	},
	{
		.name		= "keycode_data",
		.handler	= km1m4xx_handle_keycode_data_command,
		.mode		= COMMAND_CONFIG,
		.usage		= "keycode0 keycode1 keycode2 keycode3",
		.help		= "Set 4 keycode data for authentication",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration km1m4xx_command_handlers[] = {
	{
		.chain = armv7m_command_handlers,
	},
	{
		.chain = armv7m_trace_command_handlers,
	},
	{
		.name = "km1m4xx",
		.mode = COMMAND_ANY,
		.help = "km1m4xx command group",
		.usage = "",
		.chain = km1m4xx_subcommand_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct target_type km1m4xx_target = {
	.name = "km1m4xx",

	.poll = cortex_m_poll,
	.arch_state = armv7m_arch_state,

	.target_request_data = cortex_m_target_request_data,

	.halt = cortex_m_halt,
	.resume = cortex_m_resume,
	.step = cortex_m_step,

	.assert_reset = km1m4xx_m_assert_reset,
	.deassert_reset = cortex_m_deassert_reset,
	.soft_reset_halt = cortex_m_soft_reset_halt,

	.get_gdb_arch = arm_get_gdb_arch,
	.get_gdb_reg_list = armv7m_get_gdb_reg_list,

	.read_memory = cortex_m_read_memory,
	.write_memory = cortex_m_write_memory,
	.checksum_memory = armv7m_checksum_memory,
	.blank_check_memory = armv7m_blank_check_memory,

	.run_algorithm = armv7m_run_algorithm,
	.start_algorithm = armv7m_start_algorithm,
	.wait_algorithm = armv7m_wait_algorithm,

	.add_breakpoint = cortex_m_add_breakpoint,
	.remove_breakpoint = cortex_m_remove_breakpoint,
	.add_watchpoint = cortex_m_add_watchpoint,
	.remove_watchpoint = cortex_m_remove_watchpoint,

	.commands = km1m4xx_command_handlers,
	.target_create = cortex_m_target_create,
	.target_jim_configure = adiv5_jim_configure,
	.init_target = cortex_m_init_target,
	.examine = cortex_m_examine,
	.deinit_target = cortex_m_deinit_target,

	.profiling = cortex_m_profiling,
};
