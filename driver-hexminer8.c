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
extern unsigned int work_block;
extern struct work *copy_work_noffset_fast_no_id (struct work *base_work,
                                                  int noffset);
static int option_offset = -1;
struct device_drv hexminer8_drv;
extern bool no_work;
int opt_hexminer8_chip_mask = 0xFF;
int opt_hexminer8_set_config_diff_to_one = 1;
int opt_hexminer8_core_voltage = HEX8_DEFAULT_CORE_VOLTAGE;

#include "libhex8.c"

/*
    We use a replacement algorithm to only remove references to work done from the buffer when we need the extra space
    for new work. Thanks to Avalon code with some mods
 */



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
  //if (!diff1)
  {
    if (work->ping || work->work_difficulty <= (double) 1)
      {
        ht->difficulty = htole32 (0xFFFF001D);
        work->ping = 1;
        return;
      }
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

  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINER8_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (0x3080);
  ht->difficulty = htole32 (0xFFFF001D);
  ht->status = htole16 ((uint16_t) HEX8_STAT_NEW_WORK_CLEAR_OLD);
}

static bool
need_reset (struct cgpu_info *hexminer8)
{

  struct hexminer8_info *info = hexminer8->device_data;

  if (no_work)
    return false;

  time_t now = time (NULL);
  bool ret = false;
  int i = 0;
  int secs = 15;

  if (!info->diff1)
    secs = 60;


  while (i < info->asic_count)
    {

      if (!info->chip_is_dead[i]
          && (info->chip_con_resets[i] < 5 && info->matching_work[i]
              && info->engines[i])
          && (info->last_chip_valid_work[i] +
              (int) (secs * 32 / info->engines[i]) < now))
        {
#ifdef DBG_HEX8
          applog (LOG_ERR, "HEX8 %i Chip[%i] last valid work %i secs ago",
                  hexminer8->device_id, i + 1,
                  (int) (now - info->last_chip_valid_work[i]));
#else
          ret = true;
#endif
          info->chip_con_resets[i]++;
          info->last_chip_valid_work[i] = now;
          if (info->chip_con_resets[i] == 5)
            {
              info->chip_is_dead[i] = true;
              info->engines[i] = 0;

            }
          break;
        }
      info->chip_con_resets[i] = 0;
      i++;
    }

  info->timing_adjusted = true;
  reajust_timings (hexminer8);

  return ret;
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

  info->wr = (struct work8_result *) malloc (sizeof (struct work8_result));
  info->array_nonce_cache = calloc (16, sizeof (struct chip_results8));
  info->readbuf = calloc (HEX8_HASH_BUF_SIZE, sizeof (unsigned char));

  info->write_pos = 0;
  info->hash_read_pos = 0;
  info->hash_write_pos = 0;

  info->shut_read = false;
  info->shut_write = false;
  info->shut_reset = false;
  info->work = NULL;
  info->cached_diff = -1;
  info->miner_count = HEX8_DEFAULT_MINER_NUM;
  info->asic_count = HEX8_DEFAULT_ASIC_NUM;
  info->frequency = HEX8_DEFAULT_FREQUENCY;
  info->pic_voltage_readings = HEX8_DEFAULT_CORE_VOLTAGE;
  info->core_voltage = opt_hexminer8_core_voltage;
  info->chip_mask = opt_hexminer8_chip_mask;
  info->diff1 = (bool) opt_hexminer8_set_config_diff_to_one;
  info->wr->buf_empty_space = 63;
  info->work_block_local = -1;
  info->reset_work = true;
  info->jobs_to_send = 12;
  info->roll = 0;
  info->timing_adjusted = false;
  if (configured)
    {
      info->asic_count = asic_count;
      info->frequency = frequency;
    }

  gettimeofday (&info->last_wr, NULL);
  info->wsem_ustiming =
    (int64_t) (0x100000000ll / (info->asic_count * info->frequency * 4 * 32));

  info->ping_period =
    (int) (1000 * 1000 / info->wsem_ustiming * 60 / info->asic_count / 17);

  info->ht = calloc (sizeof (struct hexminer8_task), 1);
  hexminer8_init_task (info->ht, info);


  info->ping_counter = 0;
  info->random_job = 0;


  //hexminer8_init_task (ht, info);

  while (i < HEXMINER8_ARRAY_SIZE)
    {
      info->hexworks[i] = calloc (1, sizeof (struct work));
      info->hexworks[i]->pool = NULL;
      i++;
    }

  i = 0;
  info->power_checked = time (NULL);

  while (i < HEX8_DEFAULT_ASIC_NUM)
    info->chip_is_dead[i++] = false;


  if (!add_cgpu (hexminer8))
    {
      free (info->hexworks);
      free (hexminer8->device_data);
      hexminer8->device_data = NULL;
      hexminer8 = usb_free_cgpu (hexminer8);
      usb_uninit (hexminer8);
      return NULL;
    }


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


  //pthread_join (info->write_thr, NULL);
#ifdef DBG_HEX8
  pthread_join (info->dbg_thr, NULL);
  pthread_mutex_destroy (&info->lock);
#endif

  while (i < HEXMINER8_ARRAY_SIZE)
    {
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
  free (info->readbuf);
  free (info->array_nonce_cache);
  free (info->wr);
  free (info->ht);
  if (info->work)
    free_work (info->work);
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

  do_hexminer8_close (thr);

  usb_nodev (hexminer8);
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

      cgsleep_ms (30 * 1000);
      if (info->buf_empty_was_above_60 > 0 || info->buf_empty_was_below_5 > 0)
        applog (LOG_ERR,
                "HEX8 %i was_64 %i, was_above_60 %i was_zero %i, was_below_5 %i",
                hexminer8->device_id, info->buf_empty_was_64,
                info->buf_empty_was_above_60, info->buf_empty_was_zero,
                info->buf_empty_was_below_5);

      // applog (LOG_ERR,
      // "HEX8 %i roled %i, getworks %i", hexminer8->device_id,
      // info->roled, info->totworks);


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
      // applog (LOG_ERR,
      //"HEX8 %i MS Timing %i", hexminer8->device_id,
      //    (int)(30 * 1000 / info->send_jobs));

      if (info->maxwait > 4)
        applog (LOG_ERR,
                "HEX8 %i maxwait=%i, ping_jobs=%i, send_jobs=%i, per=%f",
                hexminer8->device_id, info->maxwait, info->ping_jobs,
                info->send_jobs,
                (double) (((double) info->ping_jobs /
                           (double) info->send_jobs) * (double) 100));

      mutex_lock (&info->lock);
      info->ping_jobs = 0;
      info->send_jobs = 0;
      info->maxwait = 0;
      mutex_unlock (&info->lock);
    }
  pthread_exit (NULL);
}
#endif



static bool
hexminer8_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexminer8 = thr->cgpu;
  struct hexminer8_info *info = hexminer8->device_data;

  info->thr = thr;


#ifdef DBG_HEX8
  mutex_init (&info->lock);
  if (pthread_create
      (&info->dbg_thr, NULL, hexminer8_get_stats, (void *) hexminer8))
    quit (1, "Failed to create hexminer8 dbg_thr");
#endif

//Power

  libhex8_set_word (hexminer8, 0x3080 + HEXMINER8_TASK_SIZE - 8, 0x0004);
  cgsleep_ms (100);

  struct hexminer8_config_task *htc;

  htc = calloc (sizeof (struct hexminer8_config_task), 1);

  hexminer8_init_task_c (htc, info);

  int ret = libhex8_sendHashData (hexminer8, &htc->startbyte,
                                  sizeof (struct hexminer8_config_task));

  if (ret != sizeof (struct hexminer8_config_task))
    applog (LOG_ERR, "HEX8 %i Send config failed", hexminer8->device_id);


  free (htc);
  ret = hexminer8_send_task (info->ht, hexminer8);


  cgsleep_ms (200);
  return true;
}
static void
do_write_hex8 (struct thr_info *thr)
{

  struct cgpu_info *hexminer8 = thr->cgpu;
  struct hexminer8_info *info = hexminer8->device_data;
  struct timeval tm;
  struct work *tmpwork = NULL;
  bool power;
  int jobs_to_send = info->jobs_to_send;
  int send_jobs, ret;



  if ((time (NULL) - info->power_checked) > 20)
    {
      info->power_checked = time (NULL);
      power = need_reset (hexminer8);

      if (power)
        {
          info->b_reset_count++;

          libhex8_set_word (hexminer8, 0x3080 + HEXMINER8_TASK_SIZE - 8,
                            0x0004);
          cgsleep_ms (100);

          struct hexminer8_config_task *htc;
          htc = calloc (sizeof (struct hexminer8_config_task), 1);
          hexminer8_init_task_c (htc, info);
          ret =
            libhex8_sendHashData (hexminer8, &htc->startbyte,
                                  sizeof (struct hexminer8_config_task));
          free (htc);
          hexminer8_init_task (info->ht, info);
          ret = hexminer8_send_task (info->ht, hexminer8);
          cgsleep_ms (200);
          gettimeofday (&info->last_wr, NULL);
          info->reset_work = true;
          jobs_to_send = 12;
        }
    }
  send_jobs = 0;
  while (!libhex8_usb_dead (hexminer8) && (send_jobs < jobs_to_send))
    {

    again:
      if (!info->work)
        {
          info->roll = 0;
          info->work = get_work (thr, thr->id);
          info->work->ping = (info->reset_work || info->diff1
                              || !info->timing_adjusted);

#ifdef DBG_HEX8
          info->totworks++;

#endif
        }

      if (stale_work (info->work, false))
        {
          free_work (info->work);
          info->work = NULL;
          if (info->work_block_local != work_block)
            {
              info->reset_work = true;
              send_jobs = 0;
              jobs_to_send = 12;
              info->work_block_local = work_block;
            }
          goto again;
        }

      if (info->write_pos >= HEXMINER8_ARRAY_SIZE_REAL || info->reset_work)
        info->write_pos = 0;

      info->work->subid = info->write_pos;
      tmpwork = copy_work_noffset_fast_no_id (info->work, info->roll++);
      if (info->ping_counter == info->random_job)
        tmpwork->ping = 1;
#ifdef DBG_HEX8
      if (tmpwork->ping == 1)
        {
          mutex_lock (&info->lock);

          info->ping_jobs++;
          mutex_unlock (&info->lock);
        }
#endif
      hexminer8_create_task (info->reset_work, info->ht,
                             tmpwork,
                             info->diff1, &info->asic_difficulty,
                             &info->cached_diff);

      free_work (info->hexworks[info->write_pos]);
      info->hexworks[info->write_pos] = tmpwork;


      if (!info->diff1)
        {
          info->ping_counter++;
          if (info->ping_counter == info->ping_period)
            {
              info->ping_counter = 0;
              gettimeofday (&tm, NULL);
              srandom (tm.tv_sec + tm.tv_usec * 1000000ul);
              info->random_job = rand () % info->ping_period;
            }
        }
      if (info->work->drv_rolllimit)
        {
          info->work->drv_rolllimit--;
#ifdef DBG_HEX8
          info->roled++;
#endif
        }
      else
        {
          free_work (info->work);
          info->work = NULL;
        }



#ifdef DBG_HEX8
      mutex_lock (&info->lock);
      info->send_jobs++;

      mutex_unlock (&info->lock);
      if (info->reset_work)
        applog (LOG_ERR, "HEX8 %i  Reset info->work Task!",
                hexminer8->device_id);
#endif


      ret = hexminer8_send_task (info->ht, hexminer8);
      info->write_pos++;
      send_jobs++;

      if (ret == HEXMINER8_TASK_SIZE && info->reset_work)
        {
          info->reset_work = false;
          gettimeofday (&info->last_wr, NULL);

        }
    }
}

static int64_t
hexminer8_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexminer8 = thr->cgpu;
  struct hexminer8_info *info = hexminer8->device_data;

  uint32_t nonce;
  double found;
  double hash_count = 0;
  int i = 0;
  int ret_r = 0;
  int64_t rethash_count = 0;
  int64_t tdif;
  int rminder = 0;
  struct timeval now;
  struct timeval diff;

  if (info->work_block_local != work_block)
    {
      info->reset_work = true;
      info->jobs_to_send = 12;
      info->work_block_local = work_block;
      if (info->work)
        {
          free_work (info->work);
          info->work = NULL;
        }
      gettimeofday (&info->last_wr, NULL);
      do_write_hex8 (thr);
      goto done_wr;

    }

  gettimeofday (&now, NULL);
  tdif = timediff (&now, &info->last_wr);
  info->jobs_to_send = (int) (tdif / info->wsem_ustiming);
  rminder = (int) (tdif % info->wsem_ustiming);

  if (info->jobs_to_send > 0 || info->wr->buf_empty_space > 50)
    {
      gettimeofday (&info->last_wr, NULL);

#ifdef DBG_HEX8

      if (info->maxwait < info->jobs_to_send)
        {
          mutex_lock (&info->lock);
          info->maxwait = info->jobs_to_send;
          mutex_unlock (&info->lock);

        }
#endif

      if (info->wr->buf_empty_space < 40)
        {
#ifdef DBG_HEX8
          applog (LOG_ERR, "HEX8 %i Sikp Jobs jobs=%i, buf_empty_space=%i",
                  hexminer8->device_id, info->jobs_to_send,
                  info->wr->buf_empty_space);
#endif
          goto done_wr;
        }
      now.tv_sec = 0;
      now.tv_usec = rminder;
      timersub (&info->last_wr, &now, &diff);
      memcpy (&info->last_wr, &diff, sizeof (struct timeval));
      if (info->wr->buf_empty_space > 50)
        {
#ifdef DBG_HEX8
          applog (LOG_ERR, "HEX8 %i INC Jobs jobs=%i, buf_empty_space=%i",
                  hexminer8->device_id, info->jobs_to_send,
                  info->wr->buf_empty_space);
#endif
          info->jobs_to_send++;
        }
      if (info->jobs_to_send > 12)
        {
          info->jobs_to_send = 12;
        }
      do_write_hex8 (thr);

    }

done_wr:


  if (libhex8_usb_dead (hexminer8))
    {

      hexminer8->shutdown = true;
      return -1;

    }
  if (info->hash_write_pos + HEX8_USB_R_SIZE >= HEX8_HASH_BUF_SIZE)
    {
      info->hash_write_pos = info->hash_write_pos - info->hash_read_pos;
      memcpy (info->readbuf, info->readbuf + info->hash_read_pos,
              info->hash_write_pos);
      info->hash_read_pos = 0;
    }
  if (info->hash_write_pos - info->hash_read_pos > 7)
    {
    again:
      ret_r =
        libhex8_eatHashData (info->wr, info->readbuf, &info->hash_read_pos,
                             &info->hash_write_pos);
      if (ret_r > HEX8_BUF_DATA)
        goto out;



#ifdef DBG_HEX8
      if (info->wr->buf_empty_space > 60)
        {
          mutex_lock (&info->lock);
          if (info->wr->buf_empty_space == 64)
            info->buf_empty_was_64++;
          info->buf_empty_was_above_60++;
          mutex_unlock (&info->lock);
        }
      if (info->wr->buf_empty_space < 5)
        {
          mutex_lock (&info->lock);
          info->buf_empty_was_below_5++;
          if (info->wr->buf_empty_space == 0)
            info->buf_empty_was_zero++;
          mutex_unlock (&info->lock);
        }
#endif


      if (info->wr->datalength == 1)
        goto done;

      if (info->wr->lastnonceid > HEXMINER8_ARRAY_SIZE_REAL)
        info->wr->lastnonceid = 0;

      if (info->wr->lastchippos >= HEX8_DEFAULT_ASIC_NUM)
        info->wr->lastchippos = 7;

      if (libhex8_cachenonce
          (&info->array_nonce_cache[info->wr->lastchippos],
           info->wr->lastnonce))
        {
          nonce = htole32 (info->wr->lastnonce);

          found = hexminer8_predecode_nonce (hexminer8, thr, nonce,
                                             info->wr->lastnonceid,
                                             info->diff1);

          if (found > 0)
            {

              info->engines[(uint8_t) info->wr->lastchippos] =
                info->wr->good_engines;
              info->last_chip_valid_work[(uint8_t) info->wr->lastchippos] =
                time (NULL);
              if (hash_count == 0)
                libhex8_getvoltage (htole16 (info->wr->lastvoltage),
                                    &info->pic_voltage_readings);

              hash_count += found;
              info->matching_work[info->wr->lastchippos]++;
            }
          else
            {
              inc_hw_errors_hex8 (thr, (int) found);
            }
        }
      else
        {
          info->dupe[info->wr->lastchippos]++;
        }
    out:
      if (ret_r == HEX8_BUF_ERR)
        {
          info->usb_r_errors++;
        }
    done:
      if (info->hash_write_pos - info->hash_read_pos >= HEX8_MAX_WORK_SIZE)
        goto again;
    }

  ret_r =
    libhex8_readHashData (hexminer8, info->readbuf, &info->hash_write_pos,
                          HEXMINER8_BULK_READ_TIMEOUT, true);

  if (ret_r != LIBUSB_SUCCESS)
    {
      info->usb_bad_reads++;
    }
  else
    {
      info->usb_bad_reads = 0;
    }

  if (info->usb_bad_reads > 20)
    libhex8_reset (hexminer8);

  rethash_count = (0xffffffffull * (int64_t) hash_count);


  if (libhex8_usb_dead (hexminer8))
    {
      hexminer8->shutdown = true;
      return -1;

    }

  return rethash_count;
}

static void
get_hexminer8_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminer8)
{
  if (!hexminer8->device_data)
    return;
  struct hexminer8_info *info = hexminer8->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminer8_api_stats (struct cgpu_info *cgpu)
{

  struct api_data *root = NULL;
  struct hexminer8_info *info = cgpu->device_data;
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
    api_add_int (root, "Miner Reset Count", &(info->b_reset_count), true);
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

struct device_drv hexminer8_drv = {
  .drv_id = DRIVER_hexminer8,
  .dname = "hexminer8",
  .name = "HEX8",
  .drv_detect = hexminer8_detect,
  .thread_init = hexminer8_thread_init,
  .hash_work = hash_driver_work,
  .scanwork = hexminer8_scanhash,
  .get_api_stats = hexminer8_api_stats,
  .get_statline_before = get_hexminer8_statline_before,
  .thread_shutdown = hexminer8_shutdown,
};
