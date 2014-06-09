/*$T indentinput.h GC 1.140 10/16/13 10:20:01 */
/*
 * Copyright 2013 Avalon project Copyright 2013 Con Kolivas <kernel@kolivas.org>
 * This program is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation;
 * either version 3 of the License, or (at your option) any later version. See
 * COPYING for more details. Thank you guys!
 */
#ifndef HEXM_H
#define HEXM_H
#ifdef USE_HEXMINERM
#include "util.h"
/* hexminerm_task/work_reply status Definitions: */
#define DBG_HEXM

#define HEXM_STAT_IDLE					0       /* Idle or data already Sent to the buffer */
#define HEXM_STAT_NEW_WORK				1       /* Request for write in the buffer */
#define HEXM_STAT_WAITING				2       /* Wait For Buffer Empty Position */
#define HEXM_STAT_CLR_BUFF				3       /* Force Buffer Empty */
#define HEXM_STAT_STOP_REQ				4       /* Stop Request */
#define HEXM_STAT_NEW_WORK_CLEAR_OLD		5       /* Clear Buffers and after that fill the first buffer */
#define HEXM_STAT_UNUSED					6
/* libhexm_eatHashData/BUF_reply status Definitions: */
#define HEXM_BUF_DATA 0
#define HEXM_BUF_ERR  1
#define HEXM_BUF_SKIP 2

#define HEXMINERM_ARRAY_PIC_SIZE		64
#define HEXMINERM_ARRAY_SIZE                  HEXMINERM_ARRAY_PIC_SIZE * 4
#define HEXMINERM_ARRAY_SIZE_REAL	HEXMINERM_ARRAY_SIZE - 2

#define HEXM_NONCE_CASH_SIZE				1

#define HEXM_USB_R_SIZE					64
#define HEXM_USB_WR_SIZE					64
#define HEXM_HASH_BUF_SIZE				2048*4

#define HEXMINERM_BULK_READ_TIMEOUT 1000
#define HEXM_USB_WR_TIME_OUT				500

#define HEXM_MINER_THREADS			1
#define HEXM_DEFAULT_MINER_NUM		0x01
#define HEXM_DEFAULT_ASIC_NUM		0x08
#define HEXM_MIN_FREQUENCY			0
#define HEXM_MAX_FREQUENCY			511
#define HEXM_DEFAULT_FREQUENCY		350
#define HEXM_DEFAULT_CORE_VOLTAGE	850     /* in millivolts */
#define HEXM_MIN_COREMV				300     /* in millivolts */
#define HEXM_MAX_COREMV	2101    /* in millivolts */
struct chip_resultsm
{
  uint8_t nonce_cache_write_pos;
  uint32_t nonces[HEXM_NONCE_CASH_SIZE];
};

struct hexminerm_task
{
  uint8_t startbyte;
  uint8_t datalength;
  uint8_t command;
  uint16_t address;
  uint8_t midstate[32];         //8x32
  uint32_t merkle[3];           //3x32
  //uint32_t difficulty;          //1x32
  uint16_t id;
  uint16_t status;              //1x32
  uint8_t csum;                 //1x32
  uint8_t pad[6];               //1x32
} __attribute__ ((packed, aligned (4)));

struct workm_result
{
  uint8_t startbyte;
  uint8_t datalength;
  uint8_t command;
  uint16_t address;
  uint32_t lastnonce;           //1x32
  uint8_t lastnonceid;          //1x32
  uint8_t status; //Not used
  uint16_t lastvoltage;         //1x32
  uint8_t lastchippos;          //1x32
  uint8_t buf_empty_space;      //16 bit words aligned with lastchippos
  uint8_t good_engines;
  uint8_t dum;                  //7
  uint8_t csum;
  uint8_t pad[2];
} __attribute__ ((packed, aligned (4)));

struct hexminerm_info
{

  bool shut_read;
  bool shut_write;
  bool shut_reset;
  bool reset_work;
  int usb_bad_reads;
  int write_pos;
  int roll;
  int chip_mask;
  int miner_count;
  int asic_count;
  int core_voltage;
  int frequency;
  int usb_r_errors;
  int usb_w_errors;
  int usb_reset_count;
  int b_reset_count;
  int pic_voltage_readings;
  int hash_read_pos;
  int hash_write_pos;
  int dupe[HEXM_DEFAULT_ASIC_NUM];
  int matching_work[HEXM_DEFAULT_ASIC_NUM];
  int engines[HEXM_DEFAULT_ASIC_NUM];
  unsigned int work_block_local;
  struct work *work;
  unsigned char *readbuf;
  struct workm_result *wr;
  struct chip_resultsm *array_nonce_cache;
  struct thr_info *thr;
  struct work **hexworks;
  time_t last_chip_valid_work[HEXM_DEFAULT_ASIC_NUM];
  int chip_con_resets[HEXM_DEFAULT_ASIC_NUM];
  bool chip_is_dead[HEXM_DEFAULT_ASIC_NUM];
  time_t power_checked;
  struct hexminerm_task *ht;
  
#ifdef DBG_HEXM
  pthread_mutex_t lock;
  pthread_t dbg_thr;
  int roled;
  int totworks;
  int read_pos;
  int buf_empty_was_64;
  int buf_empty_was_above_60;
  int buf_empty_was_below_5;
  int buf_empty_was_zero;
#endif

};



struct hexminerm_config_task
{
  uint8_t startbyte;
  uint8_t datalength;
  uint8_t command;
  uint16_t address;
  uint16_t hashclock;           //1x32
  uint16_t refvoltage;
  //uint32_t difficulty;          //1x32
  uint8_t chip_mask;
  uint8_t wr_interwal;
  uint8_t csum;                 //1x32
  uint8_t pad[4]; //difficulty;
} __attribute__ ((packed, aligned (4)));

#define HEXM_WORKANSWER_ADR	0x3000
#define HEXMINERM_TASK_SIZE	(sizeof(struct hexminerm_task)-6)
#define HEXM_MAX_WORK_SIZE		(sizeof(struct workm_result)-2)
#define HEXM_BASE_WORK_SIZE		6

extern int opt_hexminerm_core_voltage;
extern int opt_hexminerm_chip_mask;

extern char *libhexm_set_config_voltage (char *arg);
extern char *libhexm_set_config_chip_mask (char *arg);

extern struct hexminerm_info **hexminerm_info;
#endif /* USE_HEXMINERM */
#endif /* HEXM_H */
