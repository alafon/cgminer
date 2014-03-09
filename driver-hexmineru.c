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
#include "driver-hexmineru.h"
#include "util.h"
//static int option_offset = -1;
struct device_drv hexmineru_drv;
#include "libhexu.c"
#include "lib_mcp2210_hexu.c"



/*
    We use a replacement algorithm to only remove references to work done from the buffer when we need the extra space
    for new work. Thanks to Avalon code with some mods
 */

static void
hexmineru_flush_work (struct cgpu_info *hexmineru)
{
  struct hexmineru_info *info = hexmineru->device_data;
  cgsem_post (&info->qsem);
}
static inline void
hexmineru_create_task (uint32_t * vec, struct hexmineru_task *ht,
                       struct work *work)
{
  libhexu_work_to_bitfury_payload (ht, work);
  libhexu_bitfury_payload_to_atrvec (vec, ht);
}
static void *
hexmineru_read_write_tasks (void *userdata)
{
  struct cgpu_info *hexmineru = (struct cgpu_info *) userdata;
  struct hexmineru_info *info = hexmineru->device_data;
  char threadname[24];
  snprintf (threadname, 24, "hexu_read_write/%d", hexmineru->device_id);
  struct chip_resultsu *array_nonce_cache;
  struct thr_info *thr = info->thr;
  array_nonce_cache = calloc (1, sizeof (struct chip_resultsu));
  uint32_t nonce;
  bool job_switch = true;
  //bool n_cache;
  uint32_t buf_switch = 0xffffffff;
  uint32_t atrvec[19] = {
    0xb0e72d8e, 0x1dc5b862, 0xe9e7c4a6, 0x3050f1f5, 0x8a1a6b7e, 0x7ec384e8, 0x42c1c3fc, 0x8ed158a1,     /* MIDSTATE */
    0, 0, 0, 0, 0, 0, 0, 0,
    0x8a0bb7b7, 0x33af304f, 0x0b290c1a, /* WDATA: hashMerleRoot[7], nTime, nBits */
  };

  size_t spipos = 0;
  unsigned char wr_spi[80];

  uint32_t read_spi[256] = { 0 };

  int i, found, c_found, c_job_id, l_job_id;
  c_job_id = 0;
  l_job_id = 0;
  RenameThread (threadname);
  libhexu_libbitfury_ms3_compute (&atrvec[0]);
  libhexu_spi_emit_break (&spipos, (unsigned char *) wr_spi);
  libhexu_spi_emit_data (&spipos, (unsigned char *) wr_spi, 0x3000,
                         &atrvec[0], 76);

  while (!libhexu_usb_dead (hexmineru))
    {
      //cgtimer_t ts_start;
      //cgsleep_prepare_r (&ts_start);

      if (job_switch && info->cg_queue_cached_works > 0)
        {
          spipos = 1;
          mutex_lock (&info->lock);
          l_job_id = c_job_id;
          c_job_id = info->read_pos;
          memcpy (&atrvec[0], &info->atrvecs[info->read_pos++][0], 76);
          if (info->read_pos >= HEXMINERU_ARRAY_SIZE_REAL)
            info->read_pos = 0;
          info->cg_queue_cached_works--;
          mutex_unlock (&info->lock);
          libhexu_spi_emit_data (&spipos, (unsigned char *) wr_spi, 0x3000,
                                 &atrvec[0], 76);
        }

      if (libhexu_nanofury_spi_txrx
          (hexmineru, &spipos, (unsigned char *) wr_spi,
           (unsigned char *) read_spi, false))
        {
          if (read_spi[17] == buf_switch)
            {
              job_switch = false;
            }
          else
            {
              job_switch = true;
              buf_switch = read_spi[17];
            }

          //Skip first and last - only crap there 

          found = 0;
          //n_cache = false;
          for (i = 1; i < 17; i++)
            {
              if (libhexu_cachenonce (&array_nonce_cache[0], read_spi[i]))
                {
#if defined(__BIG_ENDIAN__) || defined(MIPSEB)
                  nonce = libhexu_decnonce (htole32 (read_spi[i]));
#else
                  nonce = libhexu_decnonce (read_spi[i]);
#endif
                  c_found = 0;
                  //n_cache = true;
                  //for (m = 0; m <= HEXMINERU_ARRAY_SIZE_REAL; m++)      
                  c_found +=
                    hexmineru_predecode_nonce (hexmineru, thr, nonce,
                                               c_job_id);
                  if (c_found == 0 && c_job_id != l_job_id)
                    c_found +=
                      hexmineru_predecode_nonce (hexmineru, thr, nonce,
                                                 l_job_id);

                  found += c_found;
                }
              else
                {
                  mutex_lock (&info->lock);
                  info->dupe[0]++;
                  mutex_unlock (&info->lock);
                }
            }

          if (found > 0)
            {
              mutex_lock (&info->lock);
              info->nonces += found;
              mutex_unlock (&info->lock);
            }
          else
            {
              //Due to implementation there is no way for now to count them. 
              //The number is inaccurate and too big!

              // if (n_cache) inc_hw_errors (thr);
            }

        }
      else
        {
          applog (LOG_ERR, "WTF??");
          libhexu_reset (hexmineru);
          libhexu_nanofury_spi_reset (hexmineru);
          mutex_lock (&info->lock);
          info->dev_reset_count++;
          mutex_unlock (&info->lock);

        }
      spipos = 80;
      //cgsem_post(&info->qsem);
      if (!job_switch)
        {
          cgsleep_ms (5);
        }
      else
        {
          cgsem_post (&info->qsem);
        }
    }
  free (array_nonce_cache);
  pthread_exit (NULL);
}

static struct cgpu_info *
hexmineru_detect_one (libusb_device * dev, struct usb_find_devices *found)
{

  struct hexmineru_info *info;
  struct cgpu_info *hexmineru;
  size_t spipos = 0;
  unsigned char buf[1024];
  unsigned char trash[1024];
  uint64_t freq;
  const uint8_t *osc6 = (unsigned char *) &freq;
  int i = 0;

  hexmineru = usb_alloc_cgpu (&hexmineru_drv, HEXU_MINER_THREADS);
  if (!usb_init (hexmineru, dev, found))
    {
      usb_uninit (hexmineru);
      return NULL;
    }
  hexmineru->device_data = calloc (sizeof (struct hexmineru_info), 1);

  if (unlikely (!(hexmineru->device_data)))
    {
      hexmineru->device_data = NULL;
      usb_uninit (hexmineru);
      return NULL;
    }

  info = hexmineru->device_data;
  info->hexworks = calloc (sizeof (struct work *), HEXMINERU_ARRAY_SIZE);
  if (unlikely (!(info->hexworks)))
    {
      free (hexmineru->device_data);
      hexmineru->device_data = NULL;
      usb_uninit (hexmineru);
      return NULL;
    }


  info->frequency = (uint8_t) HEXU_DEFAULT_FREQUENCY;
  if (opt_hexmineru_options != NULL
      && atoi (opt_hexmineru_options) > HEXU_MIN_FREQUENCY
      && atoi (opt_hexmineru_options) < HEXU_MAX_FREQUENCY)
    {
      info->frequency = (uint8_t) atoi (opt_hexmineru_options);
    }
  if (!add_cgpu (hexmineru))
    goto out;

  libhexu_reset (hexmineru);
  if (!libhexu_mcp2210_get_configs (hexmineru))
    goto out;
  if (!hex_nanofury_checkport (hexmineru))
    goto out;

  freq = htole64 ((1ULL << info->frequency) - 1ULL);

  libhexu_spi_emit_break (&spipos, (unsigned char *) buf);
  libhexu_spi_emit_data (&spipos, (unsigned char *) buf, 0x6000, osc6, 8);      // Program internal on-die slow oscillator frequency 
  libhexu_spi_send_conf (&spipos, (unsigned char *) buf);
  libhexu_spi_send_init (&spipos, (unsigned char *) buf);
  libhexu_nanofury_spi_reset (hexmineru);
  if (!libhexu_nanofury_spi_txrx
      (hexmineru, &spipos, (unsigned char *) buf, (unsigned char *) trash,
       true))
    goto out;
  while (i < HEXMINERU_ARRAY_SIZE)
    info->hexworks[i++] = calloc (1, sizeof (struct work));
  return hexmineru;


out:
  free (info->hexworks);
  free (hexmineru->device_data);
  hexmineru->device_data = NULL;
  hexmineru = usb_free_cgpu (hexmineru);
  usb_uninit (hexmineru);
  return NULL;
}

static void
hexmineru_detect (bool __maybe_unused hotplug)
{
  usb_detect (&hexmineru_drv, hexmineru_detect_one);
}

static void
do_hexmineru_close (struct thr_info *thr)
{
  struct cgpu_info *hexmineru = thr->cgpu;
  struct hexmineru_info *info = hexmineru->device_data;
  int i = 0;
  cgsleep_ms (200);

  pthread_join (info->write_thr, NULL);
  pthread_mutex_destroy (&info->lock);

  cgsem_destroy (&info->qsem);
  while (i < HEXMINERU_ARRAY_SIZE)
    {
//      if (info->hexworks[i] != NULL)
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
  //usb_uninit(hexmineru);
  //Hotplug fucks on full mem free :) 
  //free (hexmineru->device_data);
  //hexmineru->device_data = NULL;
  //thr->cgpu = usb_free_cgpu(hexmineru);

}

static void
hexmineru_shutdown (struct thr_info *thr)
{
  struct cgpu_info *hexmineru = thr->cgpu;
  struct hexmineru_info *info = hexmineru->device_data;

  if (!hexmineru->shutdown)
    hexmineru->shutdown = true;

  cgsem_post (&info->qsem);
  do_hexmineru_close (thr);
}

static bool
hexmineru_prepare (struct thr_info *thr)
{
  struct cgpu_info *hexmineru = thr->cgpu;
  struct hexmineru_info *info = hexmineru->device_data;

  info->thr = thr;
  mutex_init (&info->lock);
  cgsem_init (&info->qsem);

  if (pthread_create
      (&info->write_thr, NULL, hexmineru_read_write_tasks,
       (void *) hexmineru))
    quit (1, "Failed to create hexmineru read_write_thr");
  return true;
}

static int64_t
hexmineru_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexmineru = thr->cgpu;
  struct hexmineru_info *info = hexmineru->device_data;
  struct work *work = NULL;
  struct hexmineru_task ht;
  int64_t ms_timeout;
  int64_t hash_count = 0;
  /* 200 ms */
  if (thr->work_restart)
    goto res;
  ms_timeout = 200;
  mutex_lock (&info->lock);
  /* Rotate buffer */
  if (info->write_pos >= HEXMINERU_ARRAY_SIZE_REAL)
    info->write_pos = 0;

  while (!(info->cg_queue_cached_works > HEXMINERU_PUSH_THRESH ||
           info->write_pos >= HEXMINERU_ARRAY_SIZE_REAL))
    {
      mutex_unlock (&info->lock);
      work = get_work (thr, thr->id);
      mutex_lock (&info->lock);
      if (work == NULL)
        break;
      free_work (info->hexworks[info->write_pos]);
      hexmineru_create_task (&info->atrvecs[info->write_pos][0], &ht, work);
      info->hexworks[info->write_pos++] = work;

      info->cg_queue_cached_works++;
    }
  hash_count = 0xffffffffull * (uint64_t) info->nonces;
  info->nonces = 0;
  mutex_unlock (&info->lock);
  cgsem_mswait (&info->qsem, ms_timeout);
res:
  if (libhexu_usb_dead (hexmineru))
    {
      if (!hexmineru->shutdown)
        hexmineru->shutdown = true;
      return -1;
    }
  if (thr->work_restart)
    {
      work = get_work (thr, thr->id);
      mutex_lock (&info->lock);
      /* Eat Buffer */
      info->read_pos = 0;
      info->write_pos = 0;
      if (work != NULL)
        {

          free_work (info->hexworks[info->write_pos]);
          hexmineru_create_task (&info->atrvecs[info->write_pos][0], &ht,
                                 work);
          info->hexworks[info->write_pos++] = work;
          info->cg_queue_cached_works = 1;
        }
      else
        {
          info->cg_queue_cached_works = 0;
        }
      mutex_unlock (&info->lock);
    }
  return hash_count;
}

static void
get_hexmineru_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexmineru)
{
  struct hexmineru_info *info = hexmineru->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency, 0, 0);
}

static struct api_data *
hexmineru_api_stats (struct cgpu_info *cgpu)
{

  struct api_data *root = NULL;
  struct hexmineru_info *info = cgpu->device_data;
  uint64_t dh64, dr64;
  double dev_runtime;
  struct timeval now;
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
  root = api_add_int (root, "Reset Count", &(info->dev_reset_count), true);
  root =
    api_add_time (root, "Last Share Time", &(cgpu->last_share_pool_time),
                  true);
  root = api_add_uint8 (root, "Frequency", &(info->frequency), true);
  char mcw[24];
  sprintf (mcw, "Chip1 Dupes");
  root = api_add_int (root, mcw, &(info->dupe[0]), true);

  return root;
}

static bool
hexmineru_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexmineru = thr->cgpu;
  unsigned int wait;
  /* Pause each new thread at least 100ms between initialising
   * so the devices aren't making calls all at the same time. */
  wait = thr->id * HEXU_MAX_START_DELAY_MS;
//      applog(LOG_DEBUG, "%s%d: Delaying start by %dms",
  //              hexmineru->drv->name, hexmineru->device_id, wait / 1000);
  cgsleep_ms (wait);
  return true;
}

struct device_drv hexmineru_drv = {
  .drv_id = DRIVER_hexmineru,
  .dname = "hexmineru",
  .name = "HEXu",
  .drv_detect = hexmineru_detect,
  .thread_prepare = hexmineru_prepare,
  //.thread_init = hexmineru_thread_init,
  .hash_work = hash_queued_work,
  .scanwork = hexmineru_scanhash,
  .flush_work = hexmineru_flush_work,
  .get_api_stats = hexmineru_api_stats,
  .get_statline_before = get_hexmineru_statline_before,
  .thread_shutdown = hexmineru_shutdown,
};
