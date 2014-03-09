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
#include "driver-hexminerb.h"
#include "util.h"

static int option_offset = -1;
struct device_drv hexminerb_drv;
int opt_hexminerb_core_voltage = HEXB_DEFAULT_CORE_VOLTAGE;
#include "libhexb.c"
/*
    We use a replacement algorithm to only remove references to work done from the buffer when we need the extra space
    for new work. Thanks to Avalon code with some mods
 */

static void
hexminerb_flush_work (struct cgpu_info *hexminerb)
{
  struct hexminerb_info *info = hexminerb->device_data;
  mutex_lock (&info->lock);
  info->read_pos = 0;
  info->write_pos = 0;
  info->cg_queue_cached_works = 0;
  info->reset_work = true;
  mutex_unlock (&info->lock);

  cgsem_post (&info->qsem);
#ifdef DBG_HEXB
  applog (LOG_ERR, "HEXb%i hexminerb_flush_work", hexminerb->device_id);
#endif

}

static int
hexminerb_send_task (struct hexminerb_task *ht, struct cgpu_info *hexminerb)
{
  int ret = 0;
  size_t nr_len = HEXMINERB_TASK_SIZE;
  struct hexminerb_info *info;
  info = hexminerb->device_data;

  libhexb_csum (&ht->startbyte, &ht->csum, &ht->csum);


  ret = libhexb_sendHashData (hexminerb, &ht->startbyte, nr_len);

  if (ret != nr_len)
    {
      libhexb_reset (hexminerb);
      info->usb_w_errors++;
      return -1;
    }

  return ret;
}


static inline void
hexminerb_create_task (bool reset_work, struct hexminerb_task *ht,
                       struct work *work)
{
  if (reset_work)
    {
      ht->status = HEXB_STAT_NEW_WORK_CLEAR_OLD;
    }
  else
    {
      ht->status = HEXB_STAT_NEW_WORK;
    }
  memcpy (ht->midstate, work->midstate, 32);
  memcpy (ht->merkle, work->data + 64, 12);
  ht->id = (uint8_t) work->subid;
  BITFURY_MS3compute (work, ht);
}

static inline void
hexminerb_init_task (struct hexminerb_task *ht, struct hexminerb_info *info)
{
  bzero (ht, sizeof (struct hexminerb_task));
  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINERB_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (HEXB_WORKQUEUE_ADR);
  libhexb_setvoltage (info->core_voltage, &ht->refvoltage);
  ht->chipcount = htole16 (info->asic_count);
  ht->hashclock = htole16 ((uint16_t) info->frequency);
}
static void *
hexminerb_send_tasks (void *userdata)
{
  struct cgpu_info *hexminerb = (struct cgpu_info *) userdata;
  struct hexminerb_info *info = hexminerb->device_data;
  struct hexminerb_task *ht;
  int ret;
  bool work_state;
  cgtimer_t ts_start;
  char threadname[24];
  snprintf (threadname, 24, "hexb_send/%d", hexminerb->device_id);
  RenameThread (threadname);
  libhexb_reset (hexminerb);
  ht = (struct hexminerb_task *) malloc (sizeof (struct hexminerb_task));
  hexminerb_init_task (ht, info);

  while (!libhexb_usb_dead (hexminerb))
    {
      ret = 0;
      cgsleep_prepare_r (&ts_start);
      mutex_lock (&info->lock);


#ifdef DBG_HEXB
      if (time (NULL) - hexminerb->last_device_valid_work > DBG_TIMEB)
        {
          applog (LOG_ERR,
                  "last=%i HEXb%i info->read_pos=%i, info->cg_queue_cached_works=%i,info->wr_status=%i",
                  (int) (time (NULL) - hexminerb->last_device_valid_work),
                  hexminerb->device_id, info->read_pos,
                  info->cg_queue_cached_works, info->wr_status);
        }
#endif

      if (info->cg_queue_cached_works > 0
          && (info->wr_status == HEXB_STAT_IDLE
              || info->wr_status == HEXB_STAT_NEW_WORK))
        {
#ifdef DBG_HEXB
          if (info->reset_work)
            applog (LOG_ERR, "HEXb%i HEXA_STAT_NEW_WORK_CLEAR_OLD",
                    hexminerb->device_id);
#endif
          hexminerb_create_task (info->reset_work, ht,
                                 info->hexworks[info->read_pos++]);
          if (info->read_pos >= HEXMINERB_ARRAY_SIZE_REAL)
            info->read_pos = 0;
          info->cg_queue_cached_works--;
          work_state = info->reset_work;
          mutex_unlock (&info->lock);

          ret = hexminerb_send_task (ht, hexminerb);

          mutex_lock (&info->lock);

          if (ret != HEXMINERB_TASK_SIZE && work_state)
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

      //cgsem_post(&info->qsem);

      if (ret == HEXMINERB_TASK_SIZE)
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
hexminerb_detect_one (libusb_device * dev, struct usb_find_devices *found)
{

  int miner_count, asic_count, frequency;
  int this_option_offset = ++option_offset;
  struct hexminerb_info *info;
  struct cgpu_info *hexminerb;
  bool configured;
  int i = 0;

  hexminerb = usb_alloc_cgpu (&hexminerb_drv, HEXB_MINER_THREADS);
  if (!usb_init (hexminerb, dev, found))
    {
      usb_uninit (hexminerb);
      return NULL;
    }
  hexminerb->device_data = calloc (sizeof (struct hexminerb_info), 1);

  if (unlikely (!(hexminerb->device_data)))
    {
      hexminerb->device_data = NULL;
      usb_uninit (hexminerb);
      return NULL;
    }
  configured =
    libhexb_get_options (this_option_offset, &asic_count, &frequency);
  if (opt_hexminerb_core_voltage < HEXB_MIN_COREMV
      || opt_hexminerb_core_voltage > HEXB_MAX_COREMV)
    {

      applog
        (LOG_ERR,
         "Invalid hexminerb-voltage %d must be %dmV - %dmV",
         opt_hexminerb_core_voltage, HEXB_MIN_COREMV, HEXB_MAX_COREMV);
      free (hexminerb->device_data);
      hexminerb->device_data = NULL;
      usb_uninit (hexminerb);
      return NULL;
    }
  info = hexminerb->device_data;
  info->hexworks = calloc (sizeof (struct work *), HEXMINERB_ARRAY_SIZE);
  if (unlikely (!(info->hexworks)))
    {
      free (hexminerb->device_data);
      hexminerb->device_data = NULL;
      usb_uninit (hexminerb);
      return NULL;
    }

  info->reset_work = true;
  info->usb_timing = 45 * 1000;

  info->wr_status = HEXB_STAT_IDLE;
  info->miner_count = HEXB_DEFAULT_MINER_NUM;
  info->asic_count = HEXB_DEFAULT_ASIC_NUM;
  info->frequency = HEXB_DEFAULT_FREQUENCY;
  info->pic_voltage_readings = HEXB_DEFAULT_CORE_VOLTAGE;
  info->core_voltage = opt_hexminerb_core_voltage;
  if (configured)
    {
      info->asic_count = asic_count;
      info->frequency = frequency;
    }
  if (!add_cgpu (hexminerb))
    {
      free (info->hexworks);
      free (hexminerb->device_data);
      hexminerb->device_data = NULL;
      hexminerb = usb_free_cgpu (hexminerb);
      usb_uninit (hexminerb);
      return NULL;
    }
  while (i < HEXMINERB_ARRAY_SIZE)
    info->hexworks[i++] = calloc (1, sizeof (struct work));
  return hexminerb;
}

static void
hexminerb_detect (bool __maybe_unused hotplug)
{
  usb_detect (&hexminerb_drv, hexminerb_detect_one);
}

static void
do_hexminerb_close (struct thr_info *thr)
{
  struct cgpu_info *hexminerb = thr->cgpu;
  struct hexminerb_info *info = hexminerb->device_data;
  int i = 0;
  cgsleep_ms (200);
  pthread_join (info->read_thr, NULL);
  pthread_join (info->write_thr, NULL);
  pthread_mutex_destroy (&info->lock);

  cgsem_destroy (&info->qsem);
  while (i < HEXMINERB_ARRAY_SIZE)
    {
      //if (info->hexworks[i] != NULL)
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
  //usb_uninit(hexminerb);
  //Hotplug fucks on full mem free :) 
  //free (hexminerb->device_data);
  //hexminerb->device_data = NULL;
  //thr->cgpu = usb_free_cgpu(hexminerb);

}

static void
hexminerb_shutdown (struct thr_info *thr)
{
  struct cgpu_info *hexminerb = thr->cgpu;
  struct hexminerb_info *info = hexminerb->device_data;

  //if (!hexminerb->shutdown) hexminerb->shutdown = true;

  cgsem_post (&info->qsem);
  do_hexminerb_close (thr);
}

static void *
hexminerb_get_results (void *userdata)
{
  struct cgpu_info *hexminerb = (struct cgpu_info *) userdata;
  struct hexminerb_info *info = hexminerb->device_data;
  unsigned char readbuf[HEXB_HASH_BUF_SIZE];
  struct workb_result *wr;
  struct chip_resultsb *array_nonce_cache;
  struct thr_info *thr = info->thr;
  cgtimer_t ts_start;
  uint32_t nonce;
  int found;
  char threadname[24];
  int ret_r = 0, hash_read_pos = 0, hash_write_pos = 0, amount =
    0, usb_r_reset = 0;
  wr = (struct workb_result *) malloc (sizeof (struct workb_result));
  array_nonce_cache = calloc (16, sizeof (struct chip_resultsb));
  bzero (array_nonce_cache, 16 * sizeof (struct chip_resultsb));
  bzero (wr, sizeof (struct workb_result));
  snprintf (threadname, 24, "hexb_recv/%d", hexminerb->device_id);
  RenameThread (threadname);
  while (!libhexb_usb_dead (hexminerb))
    {
      cgsleep_prepare_r (&ts_start);
      /* Rotate */

      if (hash_write_pos + HEXB_USB_R_SIZE >= HEXB_HASH_BUF_SIZE)
        {
          hash_write_pos = hash_write_pos - hash_read_pos;
          memcpy (readbuf, readbuf + hash_read_pos, hash_write_pos);
          hash_read_pos = 0;
        }
      if (hash_write_pos - hash_read_pos >= HEXB_BASE_WORK_SIZE + 2)
        {
        again:
          ret_r =
            libhexb_eatHashData (wr, readbuf, &hash_read_pos,
                                 &hash_write_pos);
          if (ret_r > HEXB_BUF_DATA)
            goto out;

          info->wr_status = wr->status;
          if (wr->datalength == 1)
            goto done;

          if (wr->lastnonceid > HEXMINERB_ARRAY_SIZE_REAL)
            wr->lastnonceid = 0;

          if (wr->prevnonceid > HEXMINERB_ARRAY_SIZE_REAL)
            wr->prevnonceid = 0;

          if (wr->lastchippos > 15)
            wr->lastchippos = 15;

          if (libhexb_cachenonce
              (&array_nonce_cache[wr->lastchippos], wr->lastnonce))
            {
              nonce = decnonce (htole32 (wr->lastnonce));

              found = hexminerb_predecode_nonce (hexminerb, thr, nonce,
                                                 wr->lastnonceid);

              if (found == 0)
                found = hexminerb_predecode_nonce (hexminerb, thr, nonce,
                                                   wr->prevnonceid);


              if (found > 0)
                {
                  if (info->nonces == 0)
                    libhexb_getvoltage (htole16 (wr->lastvoltage),
                                        &info->pic_voltage_readings);
                  mutex_lock (&info->lock);
                  info->nonces += found;
                  mutex_unlock (&info->lock);
                  info->matching_work[wr->lastchippos]++;
                }
              else
                {
                  //Due to implementation there is no way for now to count them. 
                  //The number is inaccurate and too big!

                  //inc_hw_errors (thr);
                }
            }
          else
            {
              info->dupe[wr->lastchippos]++;
            }
        out:
          if (ret_r == HEXB_BUF_ERR)
            {
              info->usb_r_errors++;
            }
        done:
          //More nonces 
          if (hash_write_pos - hash_read_pos >= HEXB_MAX_WORK_SIZE)
            goto again;
        }
#ifdef DBG_HEXB
      if (time (NULL) - hexminerb->last_device_valid_work > DBG_TIMEB)
        {

          applog (LOG_ERR,
                  "last=%i HEXb%i info->read_pos=%i, info->cg_queue_cached_works=%i,info->wr_status=%i",
                  (int) (time (NULL) - hexminerb->last_device_valid_work),
                  hexminerb->device_id, info->read_pos,
                  info->cg_queue_cached_works, info->wr_status);
        }
#endif

      ret_r =
        libhexb_readHashData (hexminerb, readbuf, &hash_write_pos,
                              HEXMINERB_BULK_READ_TIMEOUT, true);

      if (ret_r != LIBUSB_SUCCESS)
        {
          usb_r_reset++;
          if (usb_r_reset > HEXB_USB_RES_THRESH)
            {
              libhexb_reset (hexminerb);
              usb_r_reset = 0;
            }

        }
      else
        {
          usb_r_reset = 0;
        }

      //  if(libhexb_usb_dead(hexminerb)) break;
      cgsleep_us_r (&ts_start, HEXMINERB_READ_TIMEOUT);
    }

  free (wr);
  free (array_nonce_cache);
  pthread_exit (NULL);
}

static bool
hexminerb_prepare (struct thr_info *thr)
{
  struct cgpu_info *hexminerb = thr->cgpu;
  struct hexminerb_info *info = hexminerb->device_data;

  info->thr = thr;
  mutex_init (&info->lock);
  cgsem_init (&info->qsem);

  if (pthread_create
      (&info->write_thr, NULL, hexminerb_send_tasks, (void *) hexminerb))
    quit (1, "Failed to create hexminerb write_thr");
  if (pthread_create
      (&info->read_thr, NULL, hexminerb_get_results, (void *) hexminerb))
    quit (1, "Failed to create hexminerb read_thr");
  return true;
}

static int64_t
hexminerb_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexminerb = thr->cgpu;
  struct hexminerb_info *info = hexminerb->device_data;
  struct work *work = NULL;
  int64_t ms_timeout;
  int64_t hash_count = 0;
  /* 200 ms */
  //if(thr->work_restart) goto res;
  //ms_timeout = 200;
  ms_timeout = (int64_t) (info->usb_timing / 1000 * 0.7);

  mutex_lock (&info->lock);
  /* Rotate buffer */
  if (info->write_pos >= HEXMINERB_ARRAY_SIZE_REAL)
    info->write_pos = 0;

  while (!(info->cg_queue_cached_works > HEXMINERB_PUSH_THRESH ||
           info->write_pos >= HEXMINERB_ARRAY_SIZE_REAL))
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

  if (libhexb_usb_dead (hexminerb))
    {
      //if(!hexminerb->shutdown) hexminerb->shutdown = true;
      return -1;
    }

  return hash_count;
}

static void
get_hexminerb_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminerb)
{
  //if (libhexb_usb_dead(hexminerb)) tailsprintf(buf, bufsiz, "               | ");
  struct hexminerb_info *info = hexminerb->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminerb_api_stats (struct cgpu_info *cgpu)
{

  struct api_data *root = NULL;
  struct hexminerb_info *info = cgpu->device_data;
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

static bool
hexminerb_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexminerb = thr->cgpu;
  unsigned int wait;

  /* Pause each new thread at least 100ms between initialising
   * so the devices aren't making calls all at the same time. */
  wait = thr->id * HEXB_MAX_START_DELAY_MS;
//      applog(LOG_DEBUG, "%s%d: Delaying start by %dms",
  //              hexminerb->drv->name, hexminerb->device_id, wait / 1000);
  cgsleep_ms (wait);

  return true;
}

struct device_drv hexminerb_drv = {
  .drv_id = DRIVER_hexminerb,
  .dname = "hexminerb",
  .name = "HEXb",
  .drv_detect = hexminerb_detect,
  .thread_prepare = hexminerb_prepare,
  //.thread_init = hexminerb_thread_init,
  .hash_work = hash_queued_work,
  .scanwork = hexminerb_scanhash,
  .flush_work = hexminerb_flush_work,
  .get_api_stats = hexminerb_api_stats,
  .get_statline_before = get_hexminerb_statline_before,
  .thread_shutdown = hexminerb_shutdown,
};
