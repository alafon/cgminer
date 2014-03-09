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
#include "driver-hexminerc.h"
#include "util.h"

static int option_offset = -1;
struct device_drv hexminerc_drv;
int opt_hexminerc_core_voltage = HEXC_DEFAULT_CORE_VOLTAGE;
#include "libhexc.c"

static void
hexminerc_flush_work (struct cgpu_info *hexminerc)
{
  struct hexminerc_info *info = hexminerc->device_data;

  mutex_lock (&info->lock);
  info->read_pos = 0;
  info->write_pos = 0;
  info->cg_queue_cached_works = 0;
  info->reset_work = true;
  mutex_unlock (&info->lock);

  cgsem_post (&info->qsem);
#ifdef HEXC_POWER_BLOCK
  // libhexc_set_word (hexminerc, HEXC_WORKQUEUE_ADR+80, 0x0004);
#endif
#ifdef DBG_HEXC
  applog (LOG_ERR, "HEXc%i hexminerc_flush_work", hexminerc->device_id);
#endif

}

static int
hexminerc_send_task (struct hexminerc_task *ht, struct cgpu_info *hexminerc)
{
  int ret = 0;
  size_t nr_len = HEXMINERC_TASK_SIZE;
  struct hexminerc_info *info;
  info = hexminerc->device_data;

  libhexc_csum (&ht->startbyte, &ht->csum, &ht->csum);


  ret = libhexc_sendHashData (hexminerc, &ht->startbyte, nr_len);

  if (ret != nr_len)
    {
      libhexc_reset (hexminerc);
      info->usb_w_errors++;
      return -1;
    }

  return ret;
}

static inline void
hexminerc_create_task (bool reset_work, struct hexminerc_task *ht,
                       struct work *work)
{
  if (reset_work)
    {
      ht->status = HEXC_STAT_NEW_WORK_CLEAR_OLD;
    }
  else
    {
      ht->status = HEXC_STAT_NEW_WORK;
    }
  memcpy (ht->midstate, work->midstate, 32);
  memcpy (ht->merkle, work->data + 64, 12);
  ht->id = (uint8_t) work->subid;
  libhexc_calc_hexminer (work, ht);
}

static inline void
hexminerc_init_task (struct hexminerc_task *ht, struct hexminerc_info *info)
{
  bzero (ht, sizeof (struct hexminerc_task));
  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINERC_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (HEXC_WORKQUEUE_ADR);
  libhexc_generateclk (info->frequency, HEXC_DEFAULT_XCLKIN_CLOCK,
                       (uint32_t *) & ht->clockcfg[0]);
  libhexc_setvoltage (info->core_voltage, &ht->refvoltage);
  ht->chipcount = htole16 (info->asic_count);
  ht->hashclock = htole16 ((uint16_t) info->frequency);
  ht->startnonce = 0x00000000;
}

static void *
hexminerc_send_tasks (void *userdata)
{
  struct cgpu_info *hexminerc = (struct cgpu_info *) userdata;
  struct hexminerc_info *info = hexminerc->device_data;
  struct hexminerc_task *ht;
  char threadname[24];
  int ret;
  bool work_state;
  cgtimer_t ts_start;
  snprintf (threadname, 24, "hexc_send/%d", hexminerc->device_id);
  RenameThread (threadname);
  libhexc_reset (hexminerc);
  ht = (struct hexminerc_task *) malloc (sizeof (struct hexminerc_task));
  hexminerc_init_task (ht, info);

  while (!libhexc_usb_dead (hexminerc))
    {
      ret = 0;
      cgsleep_prepare_r (&ts_start);
      mutex_lock (&info->lock);

#ifdef DBG_HEXC
      if (time (NULL) - hexminerc->last_device_valid_work > DBG_TIMEC)
        {

          applog (LOG_ERR,
                  "last=%i HEXc%i info->read_pos=%i, info->cg_queue_cached_works=%i,info->wr_status=%i",
                  (int) (time (NULL) - hexminerc->last_device_valid_work),
                  hexminerc->device_id, info->read_pos,
                  info->cg_queue_cached_works, info->wr_status);
        }
#endif
      if (info->cg_queue_cached_works > 0 && info->wr_status == HEXC_STAT_IDLE
          || info->wr_status == HEXC_STAT_NEW_WORK)
        {
#ifdef DBG_HEXC
          if (info->reset_work)
            applog (LOG_ERR, "HEXc%i HEXA_STAT_NEW_WORK_CLEAR_OLD",
                    hexminerc->device_id);
#endif
          hexminerc_create_task (info->reset_work, ht,
                                 info->hexworks[info->read_pos++]);
          if (info->read_pos >= HEXMINERC_ARRAY_SIZE_REAL)
            info->read_pos = 0;
          info->cg_queue_cached_works--;
          work_state = info->reset_work;
          mutex_unlock (&info->lock);
#ifdef HEXC_POWER_BLOCK
          //if(work_state) libhexc_set_word (hexminerc, HEXC_WORKQUEUE_ADR+80, 0x0004);
#endif
          ret = hexminerc_send_task (ht, hexminerc);
          mutex_lock (&info->lock);
          if (ret != HEXMINERC_TASK_SIZE && work_state)
            {
              info->read_pos = 0;
              info->write_pos = 0;
              info->cg_queue_cached_works = 0;
              info->reset_work = true;
            }
          else
            {
              if (work_state)
                info->reset_work = false;
            }

        }
      mutex_unlock (&info->lock);

      if (ret == HEXMINERC_TASK_SIZE)
        {
          cgsleep_us_r (&ts_start, info->usb_timing);
        }
      else
        {
          //Do not waste time make it faster :)
          cgsleep_ms (1);
        }

    }
  free (ht);
  pthread_exit (NULL);
}

static struct cgpu_info *
hexminerc_detect_one (libusb_device * dev, struct usb_find_devices *found)
{
  int miner_count, asic_count, frequency;
  int this_option_offset = ++option_offset;
  struct hexminerc_info *info;
  struct cgpu_info *hexminerc;
  bool configured;
  int i = 0;
  hexminerc = usb_alloc_cgpu (&hexminerc_drv, HEXC_MINER_THREADS);
  if (!usb_init (hexminerc, dev, found))
    {
      usb_uninit (hexminerc);
      return NULL;
    }
  hexminerc->device_data = calloc (sizeof (struct hexminerc_info), 1);
  if (unlikely (!(hexminerc->device_data)))
    {
      hexminerc->device_data = NULL;
      usb_uninit (hexminerc);
      return NULL;
    }
  configured =
    libhexc_get_options (this_option_offset, &asic_count, &frequency);
  if (opt_hexminerc_core_voltage < HEXC_MIN_COREMV
      || opt_hexminerc_core_voltage > HEXC_MAX_COREMV)
    {
      applog
        (LOG_ERR,
         "Invalid hexminerc-voltage %d must be %dmV - %dmV",
         opt_hexminerc_core_voltage, HEXC_MIN_COREMV, HEXC_MAX_COREMV);
      free (hexminerc->device_data);
      hexminerc->device_data = NULL;
      usb_uninit (hexminerc);
      return NULL;
    }
  info = hexminerc->device_data;
  info->hexworks = calloc (sizeof (struct work *), HEXMINERC_ARRAY_SIZE);
  if (unlikely (!(info->hexworks)))
    {
      free (hexminerc->device_data);
      hexminerc->device_data = NULL;
      usb_uninit (hexminerc);
      return NULL;
    }

  info->reset_work = true;
  info->read_pos = 0;
  info->write_pos = 0;
  info->cg_queue_cached_works = 0;
  info->wr_status = HEXC_STAT_IDLE;
  info->miner_count = HEXC_DEFAULT_MINER_NUM;
  info->asic_count = HEXC_DEFAULT_ASIC_NUM;
  info->frequency = HEXC_DEFAULT_FREQUENCY;
  info->pic_voltage_readings = HEXC_DEFAULT_CORE_VOLTAGE;
  info->core_voltage = opt_hexminerc_core_voltage;
  if (configured)
    {
      info->asic_count = asic_count;
      info->frequency = frequency;
    }
  info->usb_timing =
    (int64_t) (0x100000000ll / info->asic_count / info->frequency *
               HEXMINERC_WORK_FACTOR);
  if (!add_cgpu (hexminerc))
    {
      free (info->hexworks);
      free (hexminerc->device_data);
      hexminerc->device_data = NULL;
      hexminerc = usb_free_cgpu (hexminerc);
      usb_uninit (hexminerc);
      return NULL;
    }
  while (i < HEXMINERC_ARRAY_SIZE)
    info->hexworks[i++] = calloc (1, sizeof (struct work));
  libhexc_generatenrange_new ((unsigned char *) &info->nonces_range,
                              info->asic_count);
  return hexminerc;
}

static void
hexminerc_detect (bool __maybe_unused hotplug)
{
  usb_detect (&hexminerc_drv, hexminerc_detect_one);
}

static void
do_hexminerc_close (struct thr_info *thr)
{
  struct cgpu_info *hexminerc = thr->cgpu;
  struct hexminerc_info *info = hexminerc->device_data;
  int i = 0;
  cgsleep_ms (200);
  pthread_join (info->read_thr, NULL);
  pthread_join (info->write_thr, NULL);
  pthread_mutex_destroy (&info->lock);
  cgsem_destroy (&info->qsem);
  while (i < HEXMINERC_ARRAY_SIZE)
    {
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
  //Hotplug Story
  //free (hexminerc->device_data);
  //hexminerc->device_data = NULL;
  //thr->cgpu = usb_free_cgpu(hexminerc);
}

static void
hexminerc_shutdown (struct thr_info *thr)
{
  struct cgpu_info *hexminerc = thr->cgpu;
  struct hexminerc_info *info = hexminerc->device_data;

  cgsem_post (&info->qsem);
  do_hexminerc_close (thr);
}

static void *
hexminerc_get_results (void *userdata)
{
  struct cgpu_info *hexminerc = (struct cgpu_info *) userdata;
  struct hexminerc_info *info = hexminerc->device_data;
  unsigned char readbuf[HEXC_HASH_BUF_SIZE];
  struct workc_result *wr;
  struct chip_resultsc *array_nonce_cache;
  struct thr_info *thr = info->thr;
  int i, lastchippos;
  int usb_r_reset = 0;
  int found;
  cgtimer_t ts_start;
  bool notdupe;
  uint32_t nonce;
  char threadname[24];
  int ret_r = 0, hash_read_pos = 0, hash_write_pos = 0, amount = 0;
  wr = (struct workc_result *) malloc (sizeof (struct workc_result));
  array_nonce_cache = calloc (16, sizeof (struct chip_resultsc));
  bzero (array_nonce_cache, 16 * sizeof (struct chip_resultsc));
  bzero (wr, sizeof (struct workc_result));
  snprintf (threadname, 24, "hexc_recv/%d", hexminerc->device_id);
  RenameThread (threadname);
  while (!libhexc_usb_dead (hexminerc))
    {
      cgsleep_prepare_r (&ts_start);
      /* Rotate */
      if (hash_write_pos + HEXC_USB_R_SIZE >= HEXC_HASH_BUF_SIZE)
        {
          hash_write_pos = hash_write_pos - hash_read_pos;
          memcpy (readbuf, readbuf + hash_read_pos, hash_write_pos);
          hash_read_pos = 0;
        }
      if (hash_write_pos - hash_read_pos >= HEXC_BASE_WORK_SIZE + 2)
        {
        again:
          ret_r =
            libhexc_eatHashData (wr, readbuf, &hash_read_pos,
                                 &hash_write_pos);
          if (ret_r > HEXC_BUF_DATA)
            goto out;

          info->wr_status = wr->status;
          if (wr->datalength == 1)
            goto done;

          if (wr->lastnonceid > HEXMINERC_ARRAY_SIZE_REAL)
            wr->lastnonceid = 0;

          nonce = htole32 (wr->lastnonce);
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
            libhexc_cachenonce (&array_nonce_cache[lastchippos], nonce);
          if (lastchippos > 0)
            notdupe &= libhexc_cachenonce (&array_nonce_cache[0], nonce);

          if (notdupe)
            {
              found = hexminerc_predecode_nonce (hexminerc, thr, nonce,
                                                 wr->lastnonceid);
              if (found > 0)
                {
                  if (info->nonces == 0)
                    libhexc_getvoltage (htole16 (wr->lastvoltage),
                                        &info->pic_voltage_readings);
                  mutex_lock (&info->lock);
                  info->nonces += found;
                  mutex_unlock (&info->lock);
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
          if (ret_r == HEXC_BUF_ERR)
            {
              info->usb_r_errors++;
            }
        done:
          if (hash_write_pos - hash_read_pos >= HEXC_MAX_WORK_SIZE)
            goto again;
        }
#ifdef DBG_HEXC
      if (time (NULL) - hexminerc->last_device_valid_work > DBG_TIMEC)
        {

          applog (LOG_ERR,
                  "last=%i HEXc%i info->read_pos=%i, info->cg_queue_cached_works=%i,info->wr_status=%i",
                  (int) (time (NULL) - hexminerc->last_device_valid_work),
                  hexminerc->device_id, info->read_pos,
                  info->cg_queue_cached_works, info->wr_status);
        }
#endif
      ret_r =
        libhexc_readHashData (hexminerc, readbuf, &hash_write_pos,
                              HEXMINERC_BULK_READ_TIMEOUT, true);
      if (ret_r != LIBUSB_SUCCESS)
        {
          usb_r_reset++;
          if (usb_r_reset > HEXC_USB_RES_THRESH)
            {
              libhexc_reset (hexminerc);
              usb_r_reset = 0;
            }
        }
      else
        {
          usb_r_reset = 0;
        }
      cgsleep_us_r (&ts_start, HEXMINERC_READ_TIMEOUT);

    }
  free (wr);
  free (array_nonce_cache);
  pthread_exit (NULL);
}

static bool
hexminerc_prepare (struct thr_info *thr)
{
  struct cgpu_info *hexminerc = thr->cgpu;
  struct hexminerc_info *info = hexminerc->device_data;
  info->thr = thr;
  mutex_init (&info->lock);
  cgsem_init (&info->qsem);
#ifdef HEXC_POWER_BLOCK
  libhexc_set_word (hexminerc, HEXC_WORKQUEUE_ADR + 80, 0x0004);
#endif
  if (pthread_create
      (&info->write_thr, NULL, hexminerc_send_tasks, (void *) hexminerc))
    quit (1, "Failed to create hexminerc write_thr");

  if (pthread_create
      (&info->read_thr, NULL, hexminerc_get_results, (void *) hexminerc))
    quit (1, "Failed to create hexminerc read_thr");
  return true;
}

static int64_t
hexminerc_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexminerc = thr->cgpu;
  struct hexminerc_info *info = hexminerc->device_data;
  struct work *work = NULL;
  int64_t ms_timeout;
  int64_t hash_count = 0;

  /* 200 ms */
  //ms_timeout = 200;
  ms_timeout = (int64_t) (info->usb_timing / 1000 * 0.7);

  mutex_lock (&info->lock);
  /* Rotate buffer */
  if (info->write_pos >= HEXMINERC_ARRAY_SIZE_REAL)
    info->write_pos = 0;

  while (!(info->cg_queue_cached_works > HEXMINERC_PUSH_THRESH ||
           info->write_pos >= HEXMINERC_ARRAY_SIZE_REAL))
    {
      mutex_unlock (&info->lock);
      work = get_work (thr, thr->id);
      mutex_lock (&info->lock);
      if (work == NULL)
        break;
      work->subid = info->write_pos;
      free_work (info->hexworks[info->write_pos]);
      info->hexworks[info->write_pos++] = work;
      info->cg_queue_cached_works++;
    }
  hash_count = 0xffffffffull * (uint64_t) info->nonces;
  info->nonces = 0;
  mutex_unlock (&info->lock);
  cgsem_mswait (&info->qsem, ms_timeout);

  if (libhexc_usb_dead (hexminerc))
    return -1;

  return hash_count;
}

static void
get_hexminerc_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminerc)
{
  struct hexminerc_info *info = hexminerc->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminerc_api_stats (struct cgpu_info *cgpu)
{
  struct api_data *root = NULL;
  struct hexminerc_info *info = cgpu->device_data;
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
      /*~ */
      char mcw[24];
      /*~ */
      sprintf (mcw, "Chip%d Nonces", i + 1);
      root = api_add_int (root, mcw, &(info->matching_work[i]), true);
      sprintf (mcw, "Chip%d Dupes", i + 1);
      root = api_add_int (root, mcw, &(info->dupe[i]), true);
    }
  return root;
}

static bool
hexminerc_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexminerc = thr->cgpu;
  unsigned int wait;

  /* Pause each new thread at least 100ms between initialising
   * so the devices aren't making calls all at the same time. */
  wait = thr->id * HEXC_MAX_START_DELAY_MS;
  //applog(LOG_DEBUG, "%s%d: Delaying start by %dms",
  //      hexminerc->drv->name, hexminerc->device_id, wait / 1000);
  cgsleep_ms (wait);

  return true;
}

struct device_drv hexminerc_drv = {
  .drv_id = DRIVER_hexminerc,
  .dname = "hexminerc",
  .name = "HEXc",
  .drv_detect = hexminerc_detect,
  .thread_prepare = hexminerc_prepare,
  //.thread_init = hexminerc_thread_init,
  .hash_work = hash_queued_work,
  .scanwork = hexminerc_scanhash,
  .flush_work = hexminerc_flush_work,
  .get_api_stats = hexminerc_api_stats,
  .get_statline_before = get_hexminerc_statline_before,
  .thread_shutdown = hexminerc_shutdown,
};
