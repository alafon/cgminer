/*$T indentinput.c GC 1.140 10/16/13 10:19:47 */
/*
 * Copyright 2013 Con Kolivas <kernel@kolivas.org> Copyright 2012-2013 Xiangfu
 * <xiangfu@openmobilefree.com> Copyright 2012 Luke Dashjr Copyright 2012 Andrew
 * Smith This program is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation;
 * either version 3 of the License, or (at your option) any later version. See
 * COPYING for more details. Thank you guys!
 */
#include "config.h"
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#ifndef WIN32
#include <sys/select.h>
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC	0
#endif
#else
#include "compat.h"
#include <windows.h>
#include <io.h>
#endif
#include "elist.h"
#include "miner.h"
#include "usbutils.h"
#include "driver-hexminera.h"
#include "util.h"
static int option_offset = -1;
extern unsigned int work_block;
extern struct work *copy_work_noffset_fast_no_id (struct work *base_work,
                                                  int noffset);
struct device_drv hexminera_drv;
int opt_hexminera_core_voltage = HEXA_DEFAULT_CORE_VOLTAGE;
#include "libhexa.c"

static int
hexminera_send_task (struct hexminera_task *ht, struct cgpu_info *hexminera)
{
  int ret = 0;
  size_t nr_len = HEXMINERA_TASK_SIZE;
  struct hexminera_info *info;
  info = hexminera->device_data;
  libhexa_csum (&ht->startbyte, &ht->csum, &ht->csum);
  ret = libhexa_sendHashData (hexminera, &ht->startbyte, nr_len);
  if (ret != nr_len)
    {
      libhexa_reset (hexminera);
      info->usb_w_errors++;
      return -1;
    }
  return ret;
}

static inline void
hexminera_create_task (bool reset_work, struct hexminera_task *ht,
                       struct work *work)
{
  if (reset_work)
    {
      ht->status = HEXA_STAT_NEW_WORK_CLEAR_OLD;
    }
  else
    {
      ht->status = HEXA_STAT_NEW_WORK;
    }
  memcpy (ht->midstate, work->midstate, 32);
  memcpy (ht->merkle, work->data + 64, 12);
  ht->id = (uint8_t) work->subid;
  libhexa_calc_hexminer (work, ht);
}

static inline void
hexminera_init_task (struct hexminera_task *ht, struct hexminera_info *info)
{
  //bzero (ht, sizeof (struct hexminera_task));
  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINERA_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (HEXA_WORKQUEUE_ADR);
  libhexa_generateclk (info->frequency, HEXA_DEFAULT_XCLKIN_CLOCK,
                       (uint32_t *) & ht->clockcfg[0]);
  libhexa_setvoltage (info->core_voltage, &ht->refvoltage);
  ht->chipcount = htole16 (info->asic_count);
  ht->hashclock = htole16 ((uint16_t) info->frequency);
  ht->startnonce = 0x00000000;
}

static void
do_write (struct thr_info *thr)
{

  struct cgpu_info *hexminera = thr->cgpu;
  struct hexminera_info *info = hexminera->device_data;
  struct work *tmpwork = NULL;

  int send_jobs, ret;

  int jobs_to_send = info->jobs_to_send;


  send_jobs = 0;

  while (!libhexa_usb_dead (hexminera) && (send_jobs < jobs_to_send))
    {


    again:
      if (!info->work)
        {
          info->roll = 0;
          info->work = get_work (thr, thr->id);
          info->work->ping = 1;
        }
      if (stale_work (info->work, false))
        {
          free_work (info->work);
          info->work = NULL;
          if (info->work_block_local != work_block)
            {
              info->reset_work = true;
              send_jobs = 0;
              jobs_to_send = 2;
              info->work_block_local = work_block;
            }
          goto again;
        }

      if (info->write_pos >= HEXMINERA_ARRAY_SIZE_REAL || info->reset_work)
        info->write_pos = 0;

      info->work->subid = info->write_pos;
      free_work (info->hexworks[info->write_pos]);
      info->hexworks[info->write_pos] =
        copy_work_noffset_fast_no_id (info->work, info->roll++);
      hexminera_create_task (info->reset_work, info->ht,
                             info->hexworks[info->write_pos]);

      if (info->work->drv_rolllimit)
        {
          info->work->drv_rolllimit--;
        }
      else
        {
          free_work (info->work);
          info->work = NULL;
        }

      ret = hexminera_send_task (info->ht, hexminera);
      info->write_pos++;
      send_jobs++;
      if (ret == HEXMINERA_TASK_SIZE && info->reset_work)
        {
          info->reset_work = false;
          gettimeofday (&info->last_wr, NULL);

        }
    }
}

static struct cgpu_info *
hexminera_detect_one (libusb_device * dev, struct usb_find_devices *found)
{
  int miner_count, asic_count, frequency;
  int this_option_offset = ++option_offset;
  struct hexminera_info *info;
  struct cgpu_info *hexminera;
  bool configured;
  int i = 0;
  hexminera = usb_alloc_cgpu (&hexminera_drv, HEXA_MINER_THREADS);
  if (!usb_init (hexminera, dev, found))
    {
      usb_uninit (hexminera);
      return NULL;
    }
  hexminera->device_data = calloc (sizeof (struct hexminera_info), 1);
  if (unlikely (!(hexminera->device_data)))
    {
      hexminera->device_data = NULL;
      usb_uninit (hexminera);
      return NULL;
    }
  configured =
    libhexa_get_options (this_option_offset, &asic_count, &frequency);
  if (opt_hexminera_core_voltage < HEXA_MIN_COREMV
      || opt_hexminera_core_voltage > HEXA_MAX_COREMV)
    {
      applog
        (LOG_ERR,
         "Invalid hexminera-voltage %d must be %dmV - %dmV",
         opt_hexminera_core_voltage, HEXA_MIN_COREMV, HEXA_MAX_COREMV);
      free (hexminera->device_data);
      hexminera->device_data = NULL;
      usb_uninit (hexminera);
      return NULL;
    }
  info = hexminera->device_data;
  info->hexworks = calloc (sizeof (struct work *), HEXMINERA_ARRAY_SIZE);
  if (unlikely (!(info->hexworks)))
    {
      free (hexminera->device_data);
      hexminera->device_data = NULL;
      usb_uninit (hexminera);
      return NULL;
    }
  //NEW

  info->wr = (struct worka_result *) malloc (sizeof (struct worka_result));
  info->array_nonce_cache = calloc (16, sizeof (struct chip_resultsa));

  info->readbuf = calloc (HEXA_HASH_BUF_SIZE, sizeof (unsigned char));

  info->write_pos = 0;
  info->hash_read_pos = 0;
  info->hash_write_pos = 0;
  info->shut_read = false;
  info->shut_write = false;
  info->shut_reset = false;
  info->work = NULL;
  info->work_block_local = -1;
  info->reset_work = true;
  info->jobs_to_send = 2;
  info->miner_count = HEXA_DEFAULT_MINER_NUM;
  info->asic_count = HEXA_DEFAULT_ASIC_NUM;
  info->frequency = HEXA_DEFAULT_FREQUENCY;
  info->pic_voltage_readings = HEXA_DEFAULT_CORE_VOLTAGE;
  info->core_voltage = opt_hexminera_core_voltage;
  if (configured)
    {
      info->asic_count = asic_count;
      info->frequency = frequency;
    }

  info->ht = calloc (sizeof (struct hexminera_task), 1);
  hexminera_init_task (info->ht, info);

  gettimeofday (&info->last_wr, NULL);

  info->wr->lastnonceid = 0;
  info->wsem_ustiming =
    (int64_t) (0x100000000ll / (16 * info->frequency * 0.97));
  while (i < HEXMINERA_ARRAY_SIZE)
    {
      info->hexworks[i] = calloc (1, sizeof (struct work));
      info->hexworks[i]->pool = NULL;
      i++;
    }
  libhexa_generatenrange_new ((unsigned char *) &info->nonces_range,
                              info->asic_count);


  if (!add_cgpu (hexminera))
    {
      free (info->hexworks);
      free (hexminera->device_data);
      hexminera->device_data = NULL;
      hexminera = usb_free_cgpu (hexminera);
      usb_uninit (hexminera);
      return NULL;
    }

  return hexminera;
}

static void
hexminera_detect (bool __maybe_unused hotplug)
{
  usb_detect (&hexminera_drv, hexminera_detect_one);
}

static void
do_hexminera_close (struct thr_info *thr)
{
  struct cgpu_info *hexminera = thr->cgpu;
  struct hexminera_info *info = hexminera->device_data;
  int i = 0;

  while (i < HEXMINERA_ARRAY_SIZE)
    {
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
  free (info->readbuf);
  free (info->array_nonce_cache);
  free (info->wr);
  if (info->work)
    free_work (info->work);

  free (info->ht);
  //usb_uninit(hexminera);
  //Hotplug fucks up on full mem free :)
  //free (hexminera->device_data);
  //hexminera->device_data = NULL;
  //thr->cgpu = usb_free_cgpu(hexminera);
}

static void
hexminera_shutdown (struct thr_info *thr)
{
  struct cgpu_info *hexminera = thr->cgpu;
  struct hexminera_info *info = hexminera->device_data;


  do_hexminera_close (thr);

  usb_nodev (hexminera);

}
static int
free_buff_space (int cur, int last)
{

  int ret = cur - last;
  if (ret > 0)
    return ret;
  ret += 254;
  return ret;
}

static int64_t
hexminera_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexminera = thr->cgpu;
  struct hexminera_info *info = hexminera->device_data;
  int notdupe, found, i, lastchippos;
  uint32_t nonce;
  int ret_r = 0;
  int64_t hash_count = 0;
  int64_t tdif;
  int rminder = 0;
  struct timeval now;
  struct timeval diff;

  if (info->work_block_local != work_block)
    {
      info->reset_work = true;
      info->jobs_to_send = 4;
      info->work_block_local = work_block;
      if (info->work)
        {
          free_work (info->work);
          info->work = NULL;
        }
      gettimeofday (&info->last_wr, NULL);
      do_write (thr);
      goto done_wr;

    }

  gettimeofday (&now, NULL);
  tdif = timediff (&now, &info->last_wr);
  info->jobs_to_send = (int) (tdif / info->wsem_ustiming);
  rminder = (int) (tdif % info->wsem_ustiming);
  if (info->jobs_to_send > 0)
    {
      gettimeofday (&info->last_wr, NULL);
      now.tv_sec = 0;
      now.tv_usec = rminder;
      timersub (&info->last_wr, &now, &diff);
      memcpy (&info->last_wr, &diff, sizeof (struct timeval));
      if (info->jobs_to_send > 4)
        {
          info->jobs_to_send = 2;
        }
      do_write (thr);

    }

done_wr:


  if (libhexa_usb_dead (hexminera))
    {

      hexminera->shutdown = true;
      return -1;

    }
  if ((info->hash_write_pos + HEXA_USB_R_SIZE + MAX_REPL_PACKET) >=
      HEXA_HASH_BUF_SIZE)
    {
      info->hash_write_pos = info->hash_write_pos - info->hash_read_pos;
      memcpy (info->readbuf, info->readbuf + info->hash_read_pos,
              info->hash_write_pos);
      info->hash_read_pos = 0;
    }
  if (info->hash_write_pos - info->hash_read_pos >= HEXA_BASE_WORK_SIZE + 2)
    {
    again:
      ret_r =
        libhexa_eatHashData (info->wr, info->readbuf, &info->hash_read_pos,
                             &info->hash_write_pos);
      if (ret_r > HEXA_BUF_DATA)
        goto out;

      if (info->wr->datalength == 1)
        goto done;
      if (info->wr->lastnonceid > HEXMINERA_ARRAY_SIZE_REAL)
        info->wr->lastnonceid = 0;
      nonce = htole32 (info->wr->lastnonce);
      i = 0;
      while (i < info->asic_count)
        {
          if (nonce < info->nonces_range[++i])
            {
              lastchippos = --i;
              break;
            }
        }
      if (i == info->asic_count)
        lastchippos = info->asic_count - 1;
      notdupe =
        libhexa_cachenonce (&info->array_nonce_cache[lastchippos], nonce);
      if (lastchippos > 0)
        notdupe &= libhexa_cachenonce (&info->array_nonce_cache[0], nonce);

      if (notdupe)
        {
          found = hexminera_predecode_nonce (hexminera, thr, nonce,
                                             info->wr->lastnonceid);
          if (found > 0)
            {
              if (hash_count == 0)
                libhexa_getvoltage (htole16 (info->wr->lastvoltage),
                                    &info->pic_voltage_readings);
              hash_count += found;
              info->matching_work[lastchippos]++;
            }
          else
            {
              inc_hw_errors (thr);
            }
        }
      else
        {
          info->dupe[lastchippos]++;
        }
    out:
      if (ret_r == HEXA_BUF_ERR)
        {
          info->usb_r_errors++;
        }
    done:
      if (info->hash_write_pos - info->hash_read_pos > HEXA_MAX_WORK_SIZE)
        goto again;
    }
  ret_r =
    libhexa_readHashData (hexminera, info->readbuf, &info->hash_write_pos,
                          HEXMINERA_BULK_READ_TIMEOUT, true);

  hash_count = (int64_t) (0xffffffffull * hash_count);

  if (libhexa_usb_dead (hexminera))
    {
      hexminera->shutdown = true;
      return -1;
    }
  cgsleep_us (100);
  return hash_count;
}

static void
get_hexminera_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminera)
{
  if (!hexminera->device_data)
    return;

  struct hexminera_info *info = hexminera->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminera_api_stats (struct cgpu_info *cgpu)
{
  struct api_data *root = NULL;
  struct hexminera_info *info = cgpu->device_data;
  if (!info)
    return NULL;

  uint64_t dh64, dr64;
  double dev_runtime;
  struct timeval now;
  int i;
  char displayed_hashes[16], displayed_rolling[16];
  double hwp =
    (cgpu->hw_errors +
     cgpu->diff1) ? (double) (cgpu->hw_errors) / (double) (cgpu->hw_errors +
                                                           cgpu->diff1) : 0;
  if (cgpu->dev_start_tv.tv_sec == 0)
    dev_runtime = total_secs;
  else
    {
      cgtime (&now);
      dev_runtime = tdiff (&now, &(cgpu->dev_start_tv));
    }
  if (dev_runtime < 1.0)
    dev_runtime = 1.0;
  dh64 = (double) cgpu->total_mhashes / dev_runtime * 1000000ull;
  dr64 = (double) cgpu->rolling * 1000000ull;
  suffix_string (dh64, displayed_hashes, sizeof (displayed_hashes), 4);
  suffix_string (dr64, displayed_rolling, sizeof (displayed_rolling), 4);
  root = api_add_string (root, "MHS 5s", displayed_rolling, true);
  root = api_add_string (root, "MHS av", displayed_hashes, true);
  root = api_add_int (root, "Hardware Errors", &(cgpu->hw_errors), true);
  root = api_add_percent (root, "Hardware Errors%", &hwp, true);
  root = api_add_int (root, "USB Read Errors", &(info->usb_r_errors), true);
  root = api_add_int (root, "USB Write Errors", &(info->usb_w_errors), true);
  root =
    api_add_int (root, "USB Reset Count", &(info->usb_reset_count), true);

  root =
    api_add_time (root, "Last Share Time", &(cgpu->last_share_pool_time),
                  true);
  root = api_add_int (root, "Chip Count", &(info->asic_count), true);
  root = api_add_int (root, "Frequency", &(info->frequency), true);
  root = api_add_int (root, "Core Voltage", &(info->core_voltage), true);
  root =
    api_add_int (root, "PIC Voltage Readings", &(info->pic_voltage_readings),
                 true);
  for (i = 0; i < info->asic_count; i++)
    {
      char mcw[24];
      sprintf (mcw, "Chip%d Nonces", i + 1);
      root = api_add_int (root, mcw, &(info->matching_work[i]), true);
      sprintf (mcw, "Chip%d Dupes", i + 1);
      root = api_add_int (root, mcw, &(info->dupe[i]), true);
    }
  return root;
}

struct device_drv hexminera_drv = {
  .drv_id = DRIVER_hexminera,
  .dname = "hexminera",
  .name = "HEXa",
  .drv_detect = hexminera_detect,
  .hash_work = hash_driver_work,
  .scanwork = hexminera_scanhash,
  .get_api_stats = hexminera_api_stats,
  .get_statline_before = get_hexminera_statline_before,
  .thread_shutdown = hexminera_shutdown,
};
