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

extern unsigned int work_block;
extern struct work *copy_work_noffset_fast_no_id (struct work *base_work,
                                                  int noffset);
static int option_offset = -1;
struct device_drv hexminerb_drv;
int opt_hexminerb_core_voltage = HEXB_DEFAULT_CORE_VOLTAGE;
#include "libhexb.c"
/*
    We use a replacement algorithm to only remove references to work done from the buffer when we need the extra space
    for new work. Thanks to Avalon code with some mods
 */



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

  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINERB_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (HEXB_WORKQUEUE_ADR);
  libhexb_setvoltage (info->core_voltage, &ht->refvoltage);
  ht->chipcount = htole16 (info->asic_count);
  ht->hashclock = htole16 ((uint16_t) info->frequency);
}
static void
do_write_hexb (struct thr_info *thr)
{

  struct cgpu_info *hexminerb = thr->cgpu;
  struct hexminerb_info *info = hexminerb->device_data;
  struct work *tmpwork = NULL;

  int send_jobs, ret;

  int jobs_to_send = info->jobs_to_send;


  send_jobs = 0;

  while (!libhexb_usb_dead (hexminerb) && (send_jobs < jobs_to_send))
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
              jobs_to_send = 4;
              info->work_block_local = work_block;
            }
          goto again;
        }

      if (info->write_pos >= HEXMINERB_ARRAY_SIZE_REAL || info->reset_work)
        info->write_pos = 0;

      info->work->subid = info->write_pos;
      tmpwork = copy_work_noffset_fast_no_id (info->work, info->roll++);

      hexminerb_create_task (info->reset_work, info->ht, tmpwork);

      free_work (info->hexworks[info->write_pos]);
      info->hexworks[info->write_pos] = tmpwork;

      if (info->work->drv_rolllimit)
        {
          info->work->drv_rolllimit--;
        }
      else
        {
          free_work (info->work);
          info->work = NULL;
        }

      ret = hexminerb_send_task (info->ht, hexminerb);

      info->write_pos++;
      send_jobs++;

      if (ret == HEXMINERB_TASK_SIZE && info->reset_work)
        {
          info->reset_work = false;
          gettimeofday (&info->last_wr, NULL);
        }
    }

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
hexminerb_scanhash (struct thr_info *thr)
{

  struct cgpu_info *hexminerb = thr->cgpu;
  struct hexminerb_info *info = hexminerb->device_data;

  uint32_t nonce;
  int notdupe, found;

  int ret_r = 0;

  int64_t hash_count = 0;

  int64_t tdif;
  int rminder = 0;
  struct timeval now;
  struct timeval diff;
  int free_sp = free_buff_space (info->write_pos, info->wr->lastnonceid);



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
      do_write_hexb (thr);
      goto done_wr;

    }

  gettimeofday (&now, NULL);
  tdif = timediff (&now, &info->last_wr);
  info->jobs_to_send = (int) (tdif / info->wsem_ustiming);
  rminder = (int) (tdif % info->wsem_ustiming);

  if (info->jobs_to_send > 0 || free_sp < 32)
    {
      gettimeofday (&info->last_wr, NULL);
      if (free_sp > 32)
        {
          goto done_wr;
        }


      now.tv_sec = 0;
      now.tv_usec = rminder;
      timersub (&info->last_wr, &now, &diff);
      memcpy (&info->last_wr, &diff, sizeof (struct timeval));
      if (free_sp < 32)
        {

          info->jobs_to_send++;
        }
      if (info->jobs_to_send > 8)
        {
          info->jobs_to_send = 6;
        }
      do_write_hexb (thr);

    }

done_wr:

  if (libhexb_usb_dead (hexminerb))
    {
      hexminerb->shutdown = true;
      return -1;
    }
  if (info->hash_write_pos + HEXB_USB_R_SIZE >= HEXB_HASH_BUF_SIZE)
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
        libhexb_eatHashData (info->wr, info->readbuf, &info->hash_read_pos,
                             &info->hash_write_pos);
      if (ret_r > HEXB_BUF_DATA)
        goto out;

      if (info->wr->datalength == 1)
        goto done;
      if (info->wr->lastnonceid > HEXMINERB_ARRAY_SIZE_REAL)
        info->wr->lastnonceid = 0;

      if (info->wr->prevnonceid > HEXMINERB_ARRAY_SIZE_REAL)
        info->wr->prevnonceid = 0;

      if (info->wr->lastchippos > 15)
        info->wr->lastchippos = 15;

      nonce = decnonce (htole32 (info->wr->lastnonce));


      notdupe =
        libhexb_cachenonce (&info->array_nonce_cache[info->wr->lastchippos],
                            nonce);

      if (notdupe)
        {
          found = hexminerb_predecode_nonce (hexminerb, thr, nonce,
                                             info->wr->lastnonceid);
          if (found == 0)
            found = hexminerb_predecode_nonce (hexminerb, thr, nonce,
                                               info->wr->prevnonceid);
          if (found > 0)
            {

              if (hash_count == 0)
                libhexb_getvoltage (htole16 (info->wr->lastvoltage),
                                    &info->pic_voltage_readings);
              hash_count += found;
              info->matching_work[info->wr->lastchippos]++;
            }
          else
            {
              // inc_hw_errors (thr);
            }
        }
      else
        {
          info->dupe[info->wr->lastchippos]++;
        }

    out:
      if (ret_r == HEXB_BUF_ERR)
        {
          info->usb_r_errors++;
        }
    done:
      if (info->hash_write_pos - info->hash_read_pos >= HEXB_MAX_WORK_SIZE)
        goto again;
    }

  ret_r =
    libhexb_readHashData (hexminerb, info->readbuf, &info->hash_write_pos,
                          HEXMINERB_BULK_READ_TIMEOUT, true);

  if (ret_r != LIBUSB_SUCCESS)
    {
      info->usb_bad_reads++;
    }
  else
    {
      info->usb_bad_reads = 0;
    }

  if (info->usb_bad_reads > 20)
    {
      libhexb_reset (hexminerb);
    }

  hash_count = (int64_t) (0xffffffffull * hash_count);


  if (libhexb_usb_dead (hexminerb))
    {
      hexminerb->shutdown = true;
      return -1;
    }


  return hash_count;

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

  info->wr = (struct workb_result *) malloc (sizeof (struct workb_result));
  info->array_nonce_cache = calloc (16, sizeof (struct chip_resultsb));
  info->readbuf = calloc (HEXB_HASH_BUF_SIZE, sizeof (unsigned char));

  info->hash_read_pos = 0;
  info->hash_write_pos = 0;
  info->shut_read = false;
  info->shut_write = false;
  info->shut_reset = false;
  info->wr->status = HEXB_STAT_IDLE;
  info->miner_count = HEXB_DEFAULT_MINER_NUM;
  info->asic_count = HEXB_DEFAULT_ASIC_NUM;
  info->frequency = HEXB_DEFAULT_FREQUENCY;
  info->pic_voltage_readings = HEXB_DEFAULT_CORE_VOLTAGE;
  info->core_voltage = opt_hexminerb_core_voltage;

  info->work_block_local = -1;
  info->reset_work = true;
  info->jobs_to_send = 4;
  info->roll = 0;
  info->ht = calloc (sizeof (struct hexminerb_task), 1);

  info->work = NULL;
  info->write_pos = 0;
  if (configured)
    {
      info->asic_count = asic_count;
      info->frequency = frequency;
    }

  gettimeofday (&info->last_wr, NULL);
  info->wr->lastnonceid = 0;
  info->wsem_ustiming = (int64_t) (0x100000000ll / (16 * 3000 * 1.4));
  hexminerb_init_task (info->ht, info);
  while (i < HEXMINERB_ARRAY_SIZE)
    {
      info->hexworks[i] = calloc (1, sizeof (struct work));
      info->hexworks[i]->pool = NULL;
      i++;
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

#ifdef DBG_HEXB
  pthread_join (info->dbg_thr, NULL);
#endif


  while (i < HEXMINERB_ARRAY_SIZE)
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

  do_hexminerb_close (thr);

  usb_nodev (hexminerb);
  //yes
  //free (hexminerb->device_data);
  //hexminerb->device_data = NULL;


}


#ifdef DBG_HEXB
static void *
hexminerb_get_stats (void *userdata)
{
  struct cgpu_info *hexminerb = (struct cgpu_info *) userdata;
  struct hexminerb_info *info = hexminerb->device_data;
  char threadname[24];
  snprintf (threadname, 24, "hexb_dbg/%d", hexminerb->device_id);
  RenameThread (threadname);

  while (!libhexb_usb_dead (hexminerb))
    {

      cgsleep_ms (30 * 1000);


    }
  pthread_exit (NULL);
}
#endif

static bool
hexminerb_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexminerb = thr->cgpu;
  struct hexminerb_info *info = hexminerb->device_data;
  info->thr = thr;

  // libhexb_reset (hexminerb);
  return true;
}


static void
get_hexminerb_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminerb)
{
  if (!hexminerb->device_data)
    return;
  struct hexminerb_info *info = hexminerb->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminerb_api_stats (struct cgpu_info *cgpu)
{

  struct api_data *root = NULL;
  struct hexminerb_info *info = cgpu->device_data;
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

struct device_drv hexminerb_drv = {
  .drv_id = DRIVER_hexminerb,
  .dname = "hexminerb",
  .name = "HEXb",
  .thread_init = hexminerb_thread_init,
  .drv_detect = hexminerb_detect,
  .hash_work = hash_driver_work,
  .scanwork = hexminerb_scanhash,
  .get_api_stats = hexminerb_api_stats,
  .get_statline_before = get_hexminerb_statline_before,
  .thread_shutdown = hexminerb_shutdown,
};
