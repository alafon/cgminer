/*$T indentinput.h GC 1.140 10/16/13 10:20:01 */

/*
 * Copyright 2013 Avalon project Copyright 2013 Con Kolivas <kernel@kolivas.org>
 * This program is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation;
 * either version 3 of the License, or (at your option) any later version. See
 * COPYING for more details. Thank you guys!
 */
#ifndef HEXA_H
#define HEXA_H

#ifdef USE_HEXMINERA
#include "util.h"
//#define DBG_HEXA
#define DBG_TIME 10
/* hexminera_task/work_reply status Definitions: */
#define HEXA_STAT_IDLE					0       /* Idle or data already Sent to the buffer */
#define HEXA_STAT_NEW_WORK				1       /* Request for write in the buffer */
#define HEXA_STAT_WAITING				2       /* Wait For Buffer Empty Position */
#define HEXA_STAT_CLR_BUFF				3       /* Force Buffer Empty */
#define HEXA_STAT_STOP_REQ				4       /* Stop Request */
#define HEXA_STAT_NEW_WORK_CLEAR_OLD		5       /* Clear Buffers and after that fill the first buffer */
#define HEXA_STAT_UNUSED					6

#define HEXA_USB_RES_THRESH				7000    //about 1 sec
#define HEXA_DEFAULT_XCLKIN_CLOCK		32      /* In MHz */
#define HEXA_CLOCK_LOW_CFG				0x00030017
#define HEXA_CLOCK_HIGH_CFG				(0x0000002e << 3)       /* = 0x00000170 */
#define HEXMINERA_ARRAY_PIC_SIZE		64
#define HEXMINERA_ARRAY_SIZE			HEXMINERA_ARRAY_PIC_SIZE * 4
#define HEXMINERA_ARRAY_SIZE_REAL	HEXMINERA_ARRAY_SIZE - 2
#define HEXA_NONCE_CASH_SIZE			32
#define HEXMINERA_WORK_FACTOR		0.865   /* We need to be aggressive and fill PIC faster than time taken for a job
                                                 * to finish. After pic is full we are going to keep that way and leave no
                                                 * room for potential usb issues timeout:) */
#define HEXMINERA_PUSH_THRESH		4       /* At least 3 queued works available to be written to PIC */
#define HEXMINERA_ARRAY_MAX_POP		1
#define HEXA_USB_R_SIZE					1
#define MAX_REPL_PACKET					0x0f
#define HEXA_USB_R_BAD_ID					10
#define HEXA_USB_WR_SIZE					60
#define HEXA_HASH_BUF_SIZE				2048
#define HEXA_USB_WR_TIME_OUT				0
#define HEXMINERA_READ_TIMEOUT		140
#define HEXMINERA_BULK_READ_TIMEOUT		0
#define HEXA_MAX_START_DELAY_MS			1000
#define HEXA_MINER_THREADS			1
#define HEXA_DEFAULT_MINER_NUM		0x01
#define HEXA_DEFAULT_ASIC_NUM		0x10
#define HEXA_MIN_FREQUENCY			100
#define HEXA_MAX_FREQUENCY			11650
#define HEXA_DEFAULT_FREQUENCY		282
#define HEXA_DEFAULT_CORE_VOLTAGE	1200    /* in millivolts */
#define HEXA_MIN_COREMV				1000    /* in millivolts */

#define HEXA_USB_TIMING_AJUST_LOW_RES			20
//How often
//About one min
#define HEXA_USB_TIMING_AUTO			360
#define HEXA_USB_TIMING_TARGET    0.0015
//6ms
#define HEXA_USB_TIMING_AJUST			1800
/* Do not touch it!!! 1.6V is above the chip specs already */
#define HEXA_MAX_COREMV	1630    /* in millivolts */

struct chip_resultsa
{
  uint8_t nonce_cache_write_pos;
  uint32_t nonces[HEXA_NONCE_CASH_SIZE];
};

struct worka_result
{
  uint8_t startbyte;
  uint8_t datalength;
  uint8_t command;
  uint16_t address;
  uint32_t lastnonce;
  uint8_t lastnonceid;
  uint8_t status;
  uint16_t lastvoltage;
  uint16_t lasttemperature;
  uint16_t lastfanrpm;
  uint32_t serial;
  uint16_t openloadduty;
  uint16_t workingduty;
  uint16_t lastworkingduty;
  uint16_t clockforce;          /* Times Avalons Crashed */
  uint8_t pad[3];
} __attribute__ ((packed, aligned (4)));

struct hexminera_info
{
  int miner_count;
  int asic_count;
  int core_voltage;
  int frequency;
  //int idled;
  int nonces;
  int read_pos;
  int write_pos;
  int usb_r_errors;
  int usb_w_errors;
  //int dev_reset_count;
  int usb_reset_count;
  int pic_voltage_readings;
  int64_t usb_timing;
  int cg_queue_cached_works;
  int dupe[HEXA_DEFAULT_ASIC_NUM];
  int matching_work[HEXA_DEFAULT_ASIC_NUM];
  bool reset_work;
  bool wait_res;
  uint8_t wr_status;
  uint8_t wr_lastnonceid;
  uint32_t nonces_range[HEXA_DEFAULT_ASIC_NUM];
  pthread_t read_thr;
  pthread_t write_thr;
  pthread_t stat_thr;
  pthread_mutex_t lock;
  cgsem_t qsem;
  struct thr_info *thr;
  struct work **hexworks;
};


/*
 -----------------------------------------------------------------------------------------------------------------------
    2 + 3 + 1 + 1 + 1 + 1 + 1 + 8 + 1 + 1 + 1 + 2 = 23(uint32_t)=46(uint16_t)=
 -----------------------------------------------------------------------------------------------------------------------
 */

struct hexminera_task
{
  uint8_t startbyte;
  uint8_t datalength;
  uint8_t command;
  uint16_t address;
  uint32_t clockcfg[2];
  uint32_t merkle[3];
  uint32_t a1;
  uint32_t a0;
  uint32_t e2;
  uint32_t e1;
  uint32_t e0;
  uint8_t midstate[32];
  uint32_t a2;
  uint32_t startnonce;
  uint8_t id;
  uint8_t status;
  uint16_t hashclock;
  uint16_t chipcount;
  uint16_t refvoltage;
  uint16_t reftemperature;
  uint16_t reffanrpm;
  uint8_t csum;
  uint8_t pad[2];
} __attribute__ ((packed, aligned (4)));

#define HEXA_WORKANSWER_ADR	0x3000
#define HEXA_WORKQUEUE_ADR	0x4000
#define HEXA_PTCON_ADR		0x0C00
#define HEXA_START_STOP_ADR	0x646E
#define HEXMINERA_TASK_SIZE	(sizeof(struct hexminera_task)-2)
#define HEXA_MAX_WORK_SIZE		(sizeof(struct worka_result) - 3)
#define HEXA_BASE_WORK_SIZE		6       /* Min uint8_t startbyte + uint8_t datalength + uint8_t command + uint16_t
                                                 * address;
                                                 * + uint8_t csum */
#define HEXA_WORKANSWER_STAT_ADR HEXA_BASE_WORK_SIZE + 4
extern int opt_hexminera_core_voltage;
extern char *libhexa_set_config_voltage (char *arg);
extern struct hexminera_info **hexminera_info;
#endif /* USE_HEXMINERA */
#endif /* HEXA_H */
