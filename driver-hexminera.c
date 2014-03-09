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
struct device_drv hexminera_drv;
int opt_hexminera_core_voltage = HEXA_DEFAULT_CORE_VOLTAGE;
#include "libhexa.c"

static void
hexminera_flush_work (struct cgpu_info *hexminera)
{
  struct hexminera_info *info = hexminera->device_data;

  mutex_lock (&info->lock);
  info->read_pos = 0;
  info->write_pos = 0;
  info->cg_queue_cached_works = 0;
  info->reset_work = true;
  mutex_unlock (&info->lock);

  cgsem_post (&info->qsem);
#ifdef DBG_HEXA
  applog (LOG_ERR, "HEXa%i hexminera_flush_work", hexminera->device_id);
#endif
}

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
      mutex_lock (&info->lock);
      info->usb_w_errors++;
      mutex_unlock (&info->lock);
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

static void *
hexminera_get_stats (void *userdata)
{
  struct cgpu_info *hexminera = (struct cgpu_info *) userdata;
  struct hexminera_info *info = hexminera->device_data;
  char threadname[24];
  snprintf (threadname, 24, "hexa_stats/%d", hexminera->device_id);
  RenameThread (threadname);
  while (!libhexa_usb_dead (hexminera))
    {

      cgsleep_ms (400);
      libhexa_get_words (hexminera, HEXA_WORKANSWER_ADR + 4, 1);
      if ((info->wr_status == HEXA_STAT_WAITING
           || info->wr_status == HEXA_STAT_NEW_WORK_CLEAR_OLD)
          && ((time (NULL) - hexminera->last_device_valid_work) > 5))
        {
          libhexa_reset (hexminera);
          mutex_lock (&info->lock);
          info->wait_res = true;
          info->read_pos = 0;
          info->write_pos = 0;
          info->cg_queue_cached_works = 0;
          info->reset_work = true;
          mutex_unlock (&info->lock);

          cgsem_post (&info->qsem);
        }
    }
  pthread_exit (NULL);
}

static void *
hexminera_send_tasks (void *userdata)
{
  struct cgpu_info *hexminera = (struct cgpu_info *) userdata;
  struct hexminera_info *info = hexminera->device_data;
  struct hexminera_task *ht;
  int start_count, end_count, ret;
  cgtimer_t ts_start;
  bool work_state;
  char threadname[24];
  snprintf (threadname, 24, "hexa_send/%d", hexminera->device_id);
  RenameThread (threadname);
  libhexa_reset (hexminera);

  ht = (struct hexminera_task *) malloc (sizeof (struct hexminera_task));
  bzero (ht, sizeof (struct hexminera_task));
  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINERA_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (HEXA_WORKQUEUE_ADR);
  ht->chipcount = htole16 (info->asic_count);
  ht->hashclock = htole16 ((uint16_t) info->frequency);
  ht->startnonce = 0x00000000;
  libhexa_generateclk (info->frequency, HEXA_DEFAULT_XCLKIN_CLOCK,
                       (uint32_t *) & ht->clockcfg[0]);
  libhexa_setvoltage (info->core_voltage, &ht->refvoltage);

  while (!libhexa_usb_dead (hexminera))
    {
      ret = 0;
      cgsleep_prepare_r (&ts_start);
      mutex_lock (&info->lock);
      start_count = info->read_pos;
      end_count =
        info->read_pos + MIN (info->cg_queue_cached_works,
                              HEXMINERA_ARRAY_MAX_POP);
#ifdef DBG_HEXA
      if (time (NULL) - hexminera->last_device_valid_work > DBG_TIME)
        {

          applog (LOG_ERR,
                  "last=%i  HEXa%i info->read_pos=%i, info->cg_queue_cached_works=%i,info->wr_status=%i",
                  (int) (time (NULL) - hexminera->last_device_valid_work),
                  hexminera->device_id, info->read_pos,
                  info->cg_queue_cached_works, info->wr_status);
        }
#endif
      while (info->read_pos < HEXMINERA_ARRAY_SIZE_REAL
             && info->hexworks[info->read_pos] != NULL
             && start_count < end_count && (info->wr_status == HEXA_STAT_IDLE
                                            || info->wr_status ==
                                            HEXA_STAT_NEW_WORK
                                            || info->wait_res))
        {
          //  start_count < end_count && (info->wr_status == HEXA_STAT_IDLE || info->wr_status==HEXA_STAT_WAITING || info->wr_status==HEXA_STAT_NEW_WORK)) {
#ifdef DBG_HEXA
          if (info->reset_work)
            applog (LOG_ERR, "HEXa%i HEXA_STAT_NEW_WORK_CLEAR_OLD",
                    hexminera->device_id);
#endif
          hexminera_create_task (info->reset_work, ht,
                                 info->hexworks[info->read_pos++]);
          info->cg_queue_cached_works--;
          work_state = info->reset_work;
          mutex_unlock (&info->lock);
          ret = hexminera_send_task (ht, hexminera);
          mutex_lock (&info->lock);
          if (ret != HEXMINERA_TASK_SIZE && work_state)
            {
              info->read_pos = 0;
              info->write_pos = 0;
              info->cg_queue_cached_works = 0;
              info->reset_work = true;
            }
          else
            {
              if (work_state)
                {
                  info->reset_work = false;
                  info->wait_res = false;
                }
            }
          start_count++;
        }
      mutex_unlock (&info->lock);
      cgsem_post (&info->qsem);

      //if(get_stat) libhexa_get_words (hexminera, HEXA_WORKANSWER_ADR + 4, 1);
      if (ret == HEXMINERA_TASK_SIZE)
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

  info->reset_work = true;
  info->read_pos = 0;
  info->write_pos = 0;
  info->wait_res = false;
  info->cg_queue_cached_works = 0;
  info->wr_status = HEXA_STAT_IDLE;
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
  info->usb_timing =
    (int64_t) (0x100000000ll / info->asic_count / info->frequency *
               HEXMINERA_WORK_FACTOR);
  if (!add_cgpu (hexminera))
    {
      free (info->hexworks);
      free (hexminera->device_data);
      hexminera->device_data = NULL;
      hexminera = usb_free_cgpu (hexminera);
      usb_uninit (hexminera);
      return NULL;
    }
  while (i < HEXMINERA_ARRAY_SIZE)
    info->hexworks[i++] = calloc (1, sizeof (struct work));
  libhexa_generatenrange_new ((unsigned char *) &info->nonces_range,
                              info->asic_count);
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
  cgsleep_ms (200);
  pthread_join (info->read_thr, NULL);
  pthread_join (info->write_thr, NULL);
  pthread_join (info->stat_thr, NULL);
  pthread_mutex_destroy (&info->lock);
  cgsem_destroy (&info->qsem);
  while (i < HEXMINERA_ARRAY_SIZE)
    {
      //if(info->hexworks[i] != NULL) 
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
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
  if (!hexminera->shutdown)
    hexminera->shutdown = true;
  cgsem_post (&info->qsem);
  do_hexminera_close (thr);
}

static void *
hexminera_get_results (void *userdata)
{
  struct cgpu_info *hexminera = (struct cgpu_info *) userdata;
  struct hexminera_info *info = hexminera->device_data;
  unsigned char readbuf[HEXA_HASH_BUF_SIZE];
  struct worka_result *wr;
  struct chip_resultsa *array_nonce_cache;
  struct thr_info *thr = info->thr;
  int i, lastchippos;
  int usb_r_reset = 0;
  bool notdupe;
  cgtimer_t ts_start;
  int found;
  uint32_t nonce;
  char threadname[24];
  int ret_r = 0, hash_read_pos = 0, hash_write_pos = 0, amount = 0;
  float auto_times = 0, busy_times = 0, a_count = 0, a_val = 0, err_rate = 0;
  wr = (struct worka_result *) malloc (sizeof (struct worka_result));
  array_nonce_cache = calloc (16, sizeof (struct chip_resultsa));

  bzero (array_nonce_cache, 16 * sizeof (struct chip_resultsa));
  bzero (wr, sizeof (struct worka_result));
  snprintf (threadname, 24, "hexa_recv/%d", hexminera->device_id);
  RenameThread (threadname);
  while (!libhexa_usb_dead (hexminera))
    {

      cgsleep_prepare_r (&ts_start);
      /* Rotate */
      ret_r = 0;
      if ((hash_write_pos + HEXA_USB_R_SIZE + MAX_REPL_PACKET) >=
          HEXA_HASH_BUF_SIZE)
        {
          hash_write_pos = hash_write_pos - hash_read_pos;
          memcpy (readbuf, readbuf + hash_read_pos, hash_write_pos);
          hash_read_pos = 0;
        }
      if (hash_write_pos - hash_read_pos >= HEXA_BASE_WORK_SIZE + 2)
        {
        again:
          ret_r =
            libhexa_eatHashData (wr, readbuf, &hash_read_pos,
                                 &hash_write_pos);
          if (ret_r == 1 && wr->status < HEXA_STAT_UNUSED)
            {

              if (wr->status == HEXA_STAT_WAITING)
                busy_times++;

              auto_times++;
              mutex_lock (&info->lock);
              if (auto_times > HEXA_USB_TIMING_AUTO)
                {
                  //Not an error some debug stuff
#ifdef DBG_HEXA
                  applog (LOG_ERR, "HEXa%i  From %i us", hexminera->device_id,
                          (int) info->usb_timing);
#endif

                  a_count++;
                  a_val = HEXA_USB_TIMING_AJUST / a_count;
                  err_rate = busy_times / auto_times * 100;
                  if (a_val < HEXA_USB_TIMING_AJUST_LOW_RES)
                    a_val = HEXA_USB_TIMING_AJUST_LOW_RES;
                  if (err_rate > HEXA_USB_TIMING_TARGET)
                    {
                      if (err_rate > 0.5)
                        {
                          //Be aggressive
                          info->usb_timing += 2800;
                        }
                      else
                        {
                          info->usb_timing += a_val;
                        }
                    }
                  else
                    {
                      info->usb_timing -= a_val;
                    }
                  //Not an error some debug stuff
#ifdef DBG_HEXA
                  applog (LOG_ERR, "HEXa%i To %i us err %f%%",
                          hexminera->device_id, (int) info->usb_timing,
                          err_rate);
#endif

                  busy_times = 0;
                  auto_times = 0;
                  //Do not go above
                  if (info->usb_timing >
                      (int64_t) (0x100000000ll / info->asic_count /
                                 info->frequency))
                    info->usb_timing =
                      (int64_t) (0x100000000ll / info->asic_count /
                                 info->frequency * 0.995);
                }
              info->wr_status = wr->status;
              mutex_unlock (&info->lock);
            }
          else
            {
              goto out;
            }
          if (wr->address != HEXA_WORKANSWER_ADR)
            goto out;
          if (wr->lastnonceid > HEXMINERA_ARRAY_SIZE_REAL)
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
            libhexa_cachenonce (&array_nonce_cache[lastchippos], nonce);
          if (lastchippos > 0)
            notdupe &= libhexa_cachenonce (&array_nonce_cache[0], nonce);
          if (notdupe)
            {

              //applog(LOG_ERR," work_id=%i", work_id);
              found = hexminera_predecode_nonce (hexminera, thr, nonce,
                                                 wr->lastnonceid);
              if (found > 0)
                {
                  mutex_lock (&info->lock);
                  if (info->nonces == 0)
                    libhexa_getvoltage (htole16 (wr->lastvoltage),
                                        &info->pic_voltage_readings);
                  info->nonces += found;
                  info->matching_work[lastchippos]++;
                  mutex_unlock (&info->lock);
                }
              else
                {
                  inc_hw_errors (thr);
                }
            }
          else
            {
              mutex_lock (&info->lock);
              info->dupe[lastchippos]++;
              mutex_unlock (&info->lock);
            }


        out:
          if (ret_r == 2)
            {
              mutex_lock (&info->lock);
              info->usb_r_errors++;
              mutex_unlock (&info->lock);
            }
          if (hash_write_pos - hash_read_pos > HEXA_MAX_WORK_SIZE)
            goto again;
        }
#ifdef DBG_HEXA
      if (time (NULL) - hexminera->last_device_valid_work > DBG_TIME)
        {

          applog (LOG_ERR,
                  "last=%i HEXa%i hash_write_pos=%i, hash_read_pos=%i, info->wr_status=%i",
                  (int) (time (NULL) - hexminera->last_device_valid_work),
                  hexminera->device_id, hash_write_pos, hash_read_pos,
                  info->wr_status);
        }
#endif
      ret_r =
        libhexa_readHashData (hexminera, readbuf, &hash_write_pos,
                              HEXMINERA_BULK_READ_TIMEOUT, true);
      if (ret_r != LIBUSB_SUCCESS)
        {
          usb_r_reset++;
          if (usb_r_reset > HEXA_USB_RES_THRESH)
            {
              libhexa_reset (hexminera);

              usb_r_reset = 0;
            }
        }
      else
        {
          usb_r_reset = 0;
        }
      //   if(libhexa_usb_dead(hexminera)) break;
      cgsleep_us_r (&ts_start, HEXMINERA_READ_TIMEOUT);
    }
  free (wr);
  free (array_nonce_cache);
  pthread_exit (NULL);
}

static bool
hexminera_prepare (struct thr_info *thr)
{
  struct cgpu_info *hexminera = thr->cgpu;
  struct hexminera_info *info = hexminera->device_data;
  info->thr = thr;
  mutex_init (&info->lock);
  cgsem_init (&info->qsem);
  if (pthread_create
      (&info->write_thr, NULL, hexminera_send_tasks, (void *) hexminera))
    quit (1, "Failed to create hexminera write_thr");
  if (pthread_create
      (&info->read_thr, NULL, hexminera_get_results, (void *) hexminera))
    quit (1, "Failed to create hexminera read_thr");
  if (pthread_create
      (&info->stat_thr, NULL, hexminera_get_stats, (void *) hexminera))
    quit (1, "Failed to create hexminera stat_thr");

  return true;
}

static int64_t
hexminera_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexminera = thr->cgpu;
  struct hexminera_info *info = hexminera->device_data;
  struct work *work = NULL;
  int64_t ms_timeout;
  int64_t hash_count = 0;
  /* 600 ms */

  ms_timeout = 600;
  mutex_lock (&info->lock);
  /* Rotate buffer */
  if (info->read_pos >= HEXMINERA_ARRAY_SIZE_REAL
      && info->write_pos >= HEXMINERA_ARRAY_SIZE_REAL)
    {
      info->write_pos = 0;
      info->read_pos = 0;
      info->cg_queue_cached_works = 0;
    }
  while (!(info->cg_queue_cached_works > HEXMINERA_PUSH_THRESH ||
           info->write_pos >= HEXMINERA_ARRAY_SIZE_REAL))
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

  if (libhexa_usb_dead (hexminera))
    {
      if (!hexminera->shutdown)
        hexminera->shutdown = true;
      return -1;
    }

  return hash_count;
}

static void
get_hexminera_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminera)
{
  struct hexminera_info *info = hexminera->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminera_api_stats (struct cgpu_info *cgpu)
{
  struct api_data *root = NULL;
  struct hexminera_info *info = cgpu->device_data;
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
  //root = api_add_int (root, "Idled for 60 sec", &(info->idled), true);    
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
hexminera_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexminera = thr->cgpu;
  unsigned int wait;

  /* Pause each new thread at least 100ms between initialising
   * so the devices aren't making calls all at the same time. */
  wait = thr->id * HEXA_MAX_START_DELAY_MS;
  //applog(LOG_DEBUG, "%s%d: Delaying start by %dms",
  //hexminera->drv->name, hexminera->device_id, wait / 1000);
  cgsleep_ms (wait);

  return true;
}

struct device_drv hexminera_drv = {
  .drv_id = DRIVER_hexminera,
  .dname = "hexminera",
  .name = "HEXa",
  .drv_detect = hexminera_detect,
  .thread_prepare = hexminera_prepare,
  //.thread_init = hexminera_thread_init,
  .hash_work = hash_queued_work,
  .scanwork = hexminera_scanhash,
  .flush_work = hexminera_flush_work,
  .get_api_stats = hexminera_api_stats,
  .get_statline_before = get_hexminera_statline_before,
  .thread_shutdown = hexminera_shutdown,
};
