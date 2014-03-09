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
#include "driver-hexminer8.h"

#include "util.h"

static int option_offset = -1;
struct device_drv hexminer8_drv;

int opt_hexminer8_chip_mask = 0xFF;
int opt_hexminer8_set_config_diff_to_one = 1;
int opt_hexminer8_core_voltage = HEX8_DEFAULT_CORE_VOLTAGE;

#include "libhex8.c"

/*
    We use a replacement algorithm to only remove references to work done from the buffer when we need the extra space
    for new work. Thanks to Avalon code with some mods
 */

static void
hexminer8_flush_work (struct cgpu_info *hexminer8)
{
  struct hexminer8_info *info = hexminer8->device_data;

  mutex_lock (&info->lock);
  info->read_pos = 0;
  info->write_pos = 0;
  info->cg_queue_cached_works = 0;
  info->reset_work = true;
  mutex_unlock (&info->lock);

  cgsem_post (&info->qsem);

#ifdef HEX8_POWER_BLOCK
  //#define HEXC_STAT_STOP_REQ                          4
  //libhex8_set_word (hexminer8, 0x3080+HEXMINER8_TASK_SIZE - 8, 0x0004);
#endif
}

static int
hexminer8_send_task (struct hexminer8_task *ht, struct cgpu_info *hexminer8)
{
  int ret = 0;
  size_t nr_len = HEXMINER8_TASK_SIZE;
  struct hexminer8_info *info;
  info = hexminer8->device_data;

  libhex8_csum (&ht->startbyte, &ht->csum, &ht->csum);
  ret = libhex8_sendHashData (hexminer8, &ht->startbyte, nr_len);

  if (ret != nr_len)
    {
      libhex8_reset (hexminer8);
      info->usb_w_errors++;
      return -1;
    }

  return ret;
}

static inline void
hexminer8_create_task (bool reset_work, struct hexminer8_task *ht,
                       struct work *work, bool diff1,
                       uint32_t * asic_difficulty, double *cached_diff)
{
  if (reset_work)
    {
      ht->status = htole16 ((uint16_t) HEX8_STAT_NEW_WORK_CLEAR_OLD);
    }
  else
    {
      ht->status = htole16 ((uint16_t) HEX8_STAT_NEW_WORK);
    }
  memcpy (ht->midstate, work->midstate, 32);
  memcpy (ht->merkle, work->data + 64, 12);
  ht->id = htole16 ((uint16_t) work->subid);
  //Try to save some CPU cycles not fancy primary/backup scenarios... 
  if (!diff1)
    {
      if (*cached_diff != work->work_difficulty)
        {
          *cached_diff = work->work_difficulty;
#if defined(__BIG_ENDIAN__) || defined(MIPSEB)
          *asic_difficulty = libhex8_get_target (work->work_difficulty);
#else
          *asic_difficulty =
            be32toh (libhex8_get_target (work->work_difficulty));
#endif
        }
      ht->difficulty = *asic_difficulty;
    }

}

static inline void
hexminer8_init_task_c (struct hexminer8_config_task *htc,
                       struct hexminer8_info *info)
{
  bzero (htc, sizeof (struct hexminer8_config_task));

  htc->startbyte = 0x53;
  htc->datalength =
    (uint8_t) ((sizeof (struct hexminer8_config_task) - 6) / 2);
  htc->command = 0x57;
  htc->address = htole16 (0x30C0);
  htc->hashclock = htole16 ((uint16_t) info->frequency);
  libhex8_setvoltage (info->core_voltage, &htc->refvoltage);
  htc->difficulty = htole32 (0xFFFF001D);
  htc->chip_mask = (uint8_t) info->chip_mask;

  libhex8_csum (&htc->startbyte, &htc->csum, &htc->csum);
}

static inline void
hexminer8_init_task (struct hexminer8_task *ht, struct hexminer8_info *info)
{
  bzero (ht, sizeof (struct hexminer8_task));

  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINER8_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (0x3080);
  ht->difficulty = htole32 (0xFFFF001D);
}

static void *
hexminer8_send_tasks (void *userdata)
{
  struct cgpu_info *hexminer8 = (struct cgpu_info *) userdata;
  struct hexminer8_info *info = hexminer8->device_data;
  struct hexminer8_task *ht;
  struct hexminer8_config_task *htc;
  char threadname[24];

  int ret;
  bool work_state = false;
#ifndef TWS_HEX8
  cgtimer_t ts_start;
#endif
  snprintf (threadname, 24, "hex8_send/%d", hexminer8->device_id);
  RenameThread (threadname);

  htc =
    (struct hexminer8_config_task *)
    malloc (sizeof (struct hexminer8_config_task));
  hexminer8_init_task_c (htc, info);

  ret =
    libhex8_sendHashData (hexminer8, &htc->startbyte,
                          sizeof (struct hexminer8_config_task));

  if (ret != sizeof (struct hexminer8_config_task))
    applog (LOG_ERR, "HEX8 %i Send config failed", hexminer8->device_id);

  ht = (struct hexminer8_task *) malloc (sizeof (struct hexminer8_task));
  hexminer8_init_task (ht, info);

  while (!libhex8_usb_dead (hexminer8))
    {
      ret = 0;
      work_state = false;
#ifndef TWS_HEX8
      cgsleep_prepare_r (&ts_start);
#endif
      mutex_lock (&info->lock);

      if ((info->buf_empty_space > 5 || info->reset_work)
          && info->cg_queue_cached_works > 0)
        {
          hexminer8_create_task (info->reset_work, ht,
                                 info->hexworks[info->read_pos++],
                                 info->diff1, &info->asic_difficulty,
                                 &info->cached_diff);

          if (info->read_pos >= HEXMINER8_ARRAY_SIZE_REAL)
            info->read_pos = 0;
          info->cg_queue_cached_works--;
          work_state = info->reset_work;
          mutex_unlock (&info->lock);
#ifdef HEX8_POWER_BLOCK
          //#define HEXC_STAT_STOP_REQ                          4
          // if( work_state) libhex8_set_word (hexminer8, 0x3080+HEXMINER8_TASK_SIZE - 8, 0x0004);
#endif
          ret = hexminer8_send_task (ht, hexminer8);

          if (ret != HEXMINER8_TASK_SIZE && work_state)
            {
              mutex_lock (&info->lock);
              info->read_pos = 0;
              info->write_pos = 0;
              info->cg_queue_cached_works = 0;
              info->reset_work = true;
              mutex_unlock (&info->lock);
              goto done_locks;
            }
          if (work_state)
            {
              mutex_lock (&info->lock);
              info->reset_work = false;
              mutex_unlock (&info->lock);
              goto done_locks;
            }
          goto done_locks;
        }
      mutex_unlock (&info->lock);

    done_locks:

      if (!work_state && ret == HEXMINER8_TASK_SIZE
          && info->buf_empty_space < 25)
        {
#ifdef TWS_HEX8
          cgsem_mswait (&info->wsem, info->wsem_timing);
#else
          cgsleep_us_r (&ts_start, info->usb_timing);
#endif
        }
      else
        {
          //Do not waste time make it faster :)
          if (info->cg_queue_cached_works < 3)
            cgsem_post (&info->qsem);
          cgsleep_us (500);
        }
    }
  free (ht);
  free (htc);
  pthread_exit (NULL);
}

static struct cgpu_info *
hexminer8_detect_one (libusb_device * dev, struct usb_find_devices *found)
{
  int miner_count, asic_count, frequency;
  int this_option_offset = ++option_offset;
  struct hexminer8_info *info;
  struct cgpu_info *hexminer8;

  bool configured;
  int i = 0;

  hexminer8 = usb_alloc_cgpu (&hexminer8_drv, HEX8_MINER_THREADS);
  if (!usb_init (hexminer8, dev, found))
    {
      usb_uninit (hexminer8);
      return NULL;
    }
  hexminer8->device_data = calloc (sizeof (struct hexminer8_info), 1);

  if (unlikely (!(hexminer8->device_data)))
    {
      hexminer8->device_data = NULL;
      usb_uninit (hexminer8);
      return NULL;
    }
  configured =
    libhex8_get_options (this_option_offset, &asic_count, &frequency);
  if (opt_hexminer8_core_voltage < HEX8_MIN_COREMV
      || opt_hexminer8_core_voltage > HEX8_MAX_COREMV)
    {

      applog
        (LOG_ERR,
         "Invalid hexminer8-voltage %d must be %dmV - %dmV",
         opt_hexminer8_core_voltage, HEX8_MIN_COREMV, HEX8_MAX_COREMV);
      free (hexminer8->device_data);
      hexminer8->device_data = NULL;
      usb_uninit (hexminer8);
      return NULL;
    }
  info = hexminer8->device_data;
  info->hexworks = calloc (sizeof (struct work *), HEXMINER8_ARRAY_SIZE);
  if (unlikely (!(info->hexworks)))
    {
      free (hexminer8->device_data);
      hexminer8->device_data = NULL;
      usb_uninit (hexminer8);
      return NULL;
    }

  info->reset_work = true;
  info->miner_count = HEX8_DEFAULT_MINER_NUM;
  info->asic_count = HEX8_DEFAULT_ASIC_NUM;
  info->frequency = HEX8_DEFAULT_FREQUENCY;
  info->pic_voltage_readings = HEX8_DEFAULT_CORE_VOLTAGE;
  info->core_voltage = opt_hexminer8_core_voltage;
  info->chip_mask = opt_hexminer8_chip_mask;
  info->diff1 = (bool) opt_hexminer8_set_config_diff_to_one;
  info->buf_empty_space = 63;

  if (configured)
    {
      info->asic_count = asic_count;
      info->frequency = frequency;
    }
#ifndef TWS_HEX8
  info->usb_timing =
    (int64_t) (0x100000000ll / (info->asic_count * info->frequency * 4 * 32) *
               0.95);
#else
  info->wsem_timing =
    (int) (0x100000000ll / (info->asic_count * info->frequency * 4 * 32) *
           0.95 / 1000);
#endif
  info->scanhash_timing =
    (int) (0x100000000ll / (info->asic_count * info->frequency * 4 * 32) *
           0.95 * 0.7 / 1000);

  info->cached_diff = -1;
  if (!add_cgpu (hexminer8))
    {
      free (info->hexworks);
      free (hexminer8->device_data);
      hexminer8->device_data = NULL;
      hexminer8 = usb_free_cgpu (hexminer8);
      usb_uninit (hexminer8);
      return NULL;
    }

  while (i < HEXMINER8_ARRAY_SIZE)
    info->hexworks[i++] = calloc (1, sizeof (struct work));

#ifdef RST_HEX8
  i = 0;
  while (i < HEX8_DEFAULT_ASIC_NUM)
    {
      info->last_chip_valid_diff[i] = 1;
      info->engines[i] = 32;
      info->last_chip_valid_work[i++] = time (NULL);
    }
#endif
  return hexminer8;
}

static void
hexminer8_detect (bool __maybe_unused hotplug)
{
  usb_detect (&hexminer8_drv, hexminer8_detect_one);
}

static void
do_hexminer8_close (struct thr_info *thr)
{
  struct cgpu_info *hexminer8 = thr->cgpu;
  struct hexminer8_info *info = hexminer8->device_data;
  int i = 0;
  cgsleep_ms (200);
  pthread_join (info->read_thr, NULL);
  pthread_join (info->write_thr, NULL);
#ifdef DBG_HEX8
  pthread_join (info->dbg_thr, NULL);
#endif
#ifdef RST_HEX8
  pthread_join (info->rst_thr, NULL);
#endif
  pthread_mutex_destroy (&info->lock);

  cgsem_destroy (&info->qsem);
#ifdef TWS_HEX8
  cgsem_destroy (&info->wsem);
#endif
#ifdef RST_HEX8
  cgsem_destroy (&info->rsem);
#endif
  while (i < HEXMINER8_ARRAY_SIZE)
    {
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
  //usb_uninit(hexminer8);
  //Hotplug fucks on full mem free :) 
  //free (hexminer8->device_data);
  //hexminer8->device_data = NULL;
  //thr->cgpu = usb_free_cgpu(hexminer8);

}

static void
hexminer8_shutdown (struct thr_info *thr)
{
  struct cgpu_info *hexminer8 = thr->cgpu;
  struct hexminer8_info *info = hexminer8->device_data;

  //if (!hexminer8->shutdown) hexminer8->shutdown = true;

  cgsem_post (&info->qsem);
#ifdef TWS_HEX8
  cgsem_post (&info->wsem);
#endif
#ifdef RST_HEX8
  cgsem_post (&info->rsem);
#endif
  do_hexminer8_close (thr);
}

static void *
hexminer8_get_results (void *userdata)
{
  struct cgpu_info *hexminer8 = (struct cgpu_info *) userdata;
  struct hexminer8_info *info = hexminer8->device_data;
  unsigned char readbuf[HEX8_HASH_BUF_SIZE];
  struct work8_result *wr;
  struct chip_results8 *array_nonce_cache;
  struct thr_info *thr = info->thr;
  struct timeval now;
  uint32_t nonce;
  int found;
  char threadname[24];

  //libhex8_reset (hexminer8);
  int ret_r = 0, hash_read_pos = 0, hash_write_pos = 0, amount =
    0, usb_r_reset = 0;

  wr = (struct work8_result *) malloc (sizeof (struct work8_result));
  array_nonce_cache = calloc (16, sizeof (struct chip_results8));
  bzero (array_nonce_cache, 16 * sizeof (struct chip_results8));
  bzero (wr, sizeof (struct work8_result));
  snprintf (threadname, 24, "hex8_recv/%d", hexminer8->device_id);
  RenameThread (threadname);
  while (!libhex8_usb_dead (hexminer8))
    {
      /* Rotate */

      if (hash_write_pos + HEX8_USB_R_SIZE >= HEX8_HASH_BUF_SIZE)
        {
          hash_write_pos = hash_write_pos - hash_read_pos;
          memcpy (readbuf, readbuf + hash_read_pos, hash_write_pos);
          hash_read_pos = 0;
        }
      if (hash_write_pos - hash_read_pos > 7)
        {
        again:
          ret_r =
            libhex8_eatHashData (wr, readbuf, &hash_read_pos,
                                 &hash_write_pos);
          if (ret_r > HEX8_BUF_DATA)
            goto out;

          info->buf_empty_space = wr->buf_empty_space;

#ifdef DBG_HEX8
          if (wr->buf_empty_space > 60)
            {
              mutex_lock (&info->lock);
              if (wr->buf_empty_space == 64)
                info->buf_empty_was_64++;
              info->buf_empty_was_above_60++;
              mutex_unlock (&info->lock);
            }
          if (wr->buf_empty_space < 5)
            {
              mutex_lock (&info->lock);
              info->buf_empty_was_below_5++;
              if (wr->buf_empty_space == 0)
                info->buf_empty_was_zero++;
              mutex_unlock (&info->lock);
            }
#endif


          if (wr->datalength == 1)
            goto done;


          if (wr->lastnonceid > HEXMINER8_ARRAY_SIZE_REAL)
            wr->lastnonceid = 0;

          if (wr->lastchippos >= HEX8_DEFAULT_ASIC_NUM)
            wr->lastchippos = 7;

          info->engines[(uint8_t) wr->lastchippos] = wr->good_engines;

          if (libhex8_cachenonce
              (&array_nonce_cache[wr->lastchippos], wr->lastnonce))
            {
              nonce = htole32 (wr->lastnonce);
              found = hexminer8_predecode_nonce (hexminer8, thr, nonce,
                                                 wr->lastnonceid,
                                                 info->diff1);

              if (found > 0)
                {
#ifdef RST_HEX8
                  info->last_chip_valid_work[(uint8_t) wr->lastchippos] =
                    time (NULL);
                  info->last_chip_valid_diff[(uint8_t) wr->lastchippos] =
                    found;
#endif
                  if (info->nonces == 0)
                    libhex8_getvoltage (htole16 (wr->lastvoltage),
                                        &info->pic_voltage_readings);

                  mutex_lock (&info->lock);
                  info->nonces += found;
                  mutex_unlock (&info->lock);
                  info->matching_work[wr->lastchippos]++;
                }
              else
                {
                  inc_hw_errors (thr);
                }
            }
          else
            {
              info->dupe[wr->lastchippos]++;
            }
        out:
          if (ret_r == HEX8_BUF_ERR)
            {
              info->usb_r_errors++;
            }
        done:
          if (hash_write_pos - hash_read_pos >= HEX8_MAX_WORK_SIZE)
            goto again;
        }

      ret_r =
        libhex8_readHashData (hexminer8, readbuf, &hash_write_pos,
                              HEXMINER8_BULK_READ_TIMEOUT, true);


      if (ret_r != LIBUSB_SUCCESS)
        {
          usb_r_reset++;
          if (usb_r_reset > HEX8_USB_RES_THRESH)
            {
              libhex8_reset (hexminer8);
              usb_r_reset = 0;
            }

        }
      else
        {
          usb_r_reset = 0;
        }


    }

  free (wr);
  free (array_nonce_cache);
  pthread_exit (NULL);
}

#ifdef DBG_HEX8
static void *
hexminer8_get_stats (void *userdata)
{
  struct cgpu_info *hexminer8 = (struct cgpu_info *) userdata;
  struct hexminer8_info *info = hexminer8->device_data;
  char threadname[24];
  snprintf (threadname, 24, "hex8_dbg/%d", hexminer8->device_id);
  RenameThread (threadname);
  while (!libhex8_usb_dead (hexminer8))
    {

      cgsleep_ms (20 * 1000);

      applog (LOG_ERR,
              "HEX8 %i was_64 %i, was_above_60 %i was_zero %i, was_below_5 %i",
              hexminer8->device_id, info->buf_empty_was_64,
              info->buf_empty_was_above_60, info->buf_empty_was_zero,
              info->buf_empty_was_below_5);
      if (info->buf_empty_was_above_60 > 0)
        {
          mutex_lock (&info->lock);
          info->buf_empty_was_64 = 0;
          info->buf_empty_was_above_60 = 0;
          mutex_unlock (&info->lock);
        }

      if (info->buf_empty_was_below_5 > 0)
        {
          mutex_lock (&info->lock);
          info->buf_empty_was_below_5 = 0;
          info->buf_empty_was_zero = 0;
          mutex_unlock (&info->lock);
        }
    }
  pthread_exit (NULL);
}
#endif

#ifdef RST_HEX8
//diff 1 only otherwise variation is killing us
//There is easy way speaking of diff1
//Not working yet just for debugging
static void *
hexminer8_rst (void *userdata)
{
  struct cgpu_info *hexminer8 = (struct cgpu_info *) userdata;
  struct hexminer8_info *info = hexminer8->device_data;
  char threadname[24];
  snprintf (threadname, 24, "hex8_rst/%d", hexminer8->device_id);
  RenameThread (threadname);
  time_t now;
  int i;
  int last_work_sec_ago, next_work_time_in_seconds;
  double estimated_nonces_per_minute;

  while (!libhex8_usb_dead (hexminer8))
    {
      i = 0;

      cgsem_mswait (&info->rsem, 60 * 1000);

      now = time (NULL);
      while (i < HEX8_DEFAULT_ASIC_NUM)
        {

          estimated_nonces_per_minute =
            (double) (1000 /
                      (double) (0x100000000ll / info->frequency / 4 /
                                info->engines[i] / 1000) * 60);
          last_work_sec_ago = (int) (now - info->last_chip_valid_work[i]);
          next_work_time_in_seconds =
            (int) (info->last_chip_valid_diff[i] /
                   estimated_nonces_per_minute * 60 * (1.5 +
                                                       (int) info->
                                                       last_chip_valid_diff[i]
                                                       / 100));
          if (next_work_time_in_seconds - last_work_sec_ago < 0)
            {
              applog (LOG_ERR, "Chip%i HANG ", i + 1);
              applog (LOG_ERR,
                      "estimated_nonces_per_minute %f,last_work_sec_ago %i,next_work_time_in_seconds %i",
                      estimated_nonces_per_minute, last_work_sec_ago,
                      next_work_time_in_seconds);
            }
          i++;

        }
      applog (LOG_ERR, "RST OK ");
    }
  pthread_exit (NULL);
}
#endif

static bool
hexminer8_prepare (struct thr_info *thr)
{
  struct cgpu_info *hexminer8 = thr->cgpu;
  struct hexminer8_info *info = hexminer8->device_data;

  info->thr = thr;
  mutex_init (&info->lock);
  cgsem_init (&info->qsem);
#ifdef TWS_HEX8
  cgsem_init (&info->wsem);
#endif
#ifdef RST_HEX8
  cgsem_init (&info->rsem);
#endif
#ifdef HEX8_POWER_BLOCK
  //#define HEXC_STAT_STOP_REQ                          4
  libhex8_set_word (hexminer8, 0x3080 + HEXMINER8_TASK_SIZE - 8, 0x0004);
#endif
  if (pthread_create
      (&info->read_thr, NULL, hexminer8_get_results, (void *) hexminer8))
    quit (1, "Failed to create hexminer8 read_thr");

  if (pthread_create
      (&info->write_thr, NULL, hexminer8_send_tasks, (void *) hexminer8))
    quit (1, "Failed to create hexminer8 write_thr");

#ifdef DBG_HEX8
  if (pthread_create
      (&info->dbg_thr, NULL, hexminer8_get_stats, (void *) hexminer8))
    quit (1, "Failed to create hexminer8 dbg_thr");
#endif

#ifdef RST_HEX8
  if (pthread_create
      (&info->rst_thr, NULL, hexminer8_rst, (void *) hexminer8))
    quit (1, "Failed to create hexminer8 rst_thr");
#endif
  return true;
}



static int64_t
hexminer8_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexminer8 = thr->cgpu;
  struct hexminer8_info *info = hexminer8->device_data;
  struct work *work = NULL;
  int64_t hash_count = 0;

  mutex_lock (&info->lock);
  /* Rotate buffer */

  if (info->write_pos >= HEXMINER8_ARRAY_SIZE_REAL)
    info->write_pos = 0;

  while (!(info->cg_queue_cached_works > HEXMINER8_PUSH_THRESH ||
           info->write_pos >= HEXMINER8_ARRAY_SIZE_REAL))
    {
      mutex_unlock (&info->lock);
#ifdef TWS_HEX8
      if (info->reset_work && info->cg_queue_cached_works > 0)
        cgsem_post (&info->wsem);
#endif

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
  cgsem_mswait (&info->qsem, info->scanhash_timing);

  if (libhex8_usb_dead (hexminer8))
    return -1;

  return hash_count;
}

static void
get_hexminer8_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminer8)
{
  //if (libhex8_usb_dead(hexminer8)) tailsprintf(buf, bufsiz, "               | ");
  struct hexminer8_info *info = hexminer8->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminer8_api_stats (struct cgpu_info *cgpu)
{

  struct api_data *root = NULL;
  struct hexminer8_info *info = cgpu->device_data;
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
      sprintf (mcw, "Chip%d Engines", i + 1);
      root = api_add_int (root, mcw, &(info->engines[i]), true);
      sprintf (mcw, "Chip%d Dupes", i + 1);
      root = api_add_int (root, mcw, &(info->dupe[i]), true);
    }

  return root;
}

static bool
hexminer8_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexminer8 = thr->cgpu;
  unsigned int wait;

  /* Pause each new thread at least 100ms between initialising
   * so the devices aren't making calls all at the same time. */
  wait = thr->id * HEX8_MAX_START_DELAY_MS;
//      applog(LOG_DEBUG, "%s%d: Delaying start by %dms",
  //              hexminer8->drv->name, hexminer8->device_id, wait / 1000);
  cgsleep_ms (wait);

  return true;
}

struct device_drv hexminer8_drv = {
  .drv_id = DRIVER_hexminer8,
  .dname = "hexminer8",
  .name = "HEX8",
  .drv_detect = hexminer8_detect,
  .thread_prepare = hexminer8_prepare,
  //.thread_init = hexminer8_thread_init,
  .hash_work = hash_queued_work,
  .scanwork = hexminer8_scanhash,
  .flush_work = hexminer8_flush_work,
  .get_api_stats = hexminer8_api_stats,
  .get_statline_before = get_hexminer8_statline_before,
  .thread_shutdown = hexminer8_shutdown,
};
