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
#include "driver-hexminerm.h"

#include "util.h"
extern unsigned int work_block;
extern struct work *copy_work_noffset_fast_no_id (struct work *base_work,
                                                  int noffset);
static int option_offset = -1;
struct device_drv hexminerm_drv;
extern bool no_work;
int opt_hexminerm_chip_mask = 0xFF;

int opt_hexminerm_core_voltage = HEXM_DEFAULT_CORE_VOLTAGE;

#include "libhexm.c"

/*
    We use a replacement algorithm to only remove references to work done from the buffer when we need the extra space
    for new work. Thanks to Avalon code with some mods
 */



static int
hexminerm_send_task (struct hexminerm_task *ht, struct cgpu_info *hexminerm)
{
  int ret = 0;
  size_t nr_len = HEXMINERM_TASK_SIZE;
  struct hexminerm_info *info;
  info = hexminerm->device_data;

  libhexm_csum (&ht->startbyte, &ht->csum, &ht->csum);

  ret = libhexm_sendHashData (hexminerm, &ht->startbyte, nr_len);

  if (ret != nr_len)
    {
      libhexm_reset (hexminerm);
      info->usb_w_errors++;
      return -1;
    }

  return ret;
}

static inline void
hexminerm_create_task (bool reset_work, struct hexminerm_task *ht,
                       struct work *work)
{
  if (reset_work)
    {
      ht->status = htole16 ((uint16_t) HEXM_STAT_NEW_WORK_CLEAR_OLD);
    }
  else
    {
      ht->status = htole16 ((uint16_t) HEXM_STAT_NEW_WORK);
    }
  memcpy (ht->midstate, work->midstate, 32);
  memcpy (ht->merkle, work->data + 64, 12);
  ht->id = htole16 ((uint16_t) work->subid);
  //Try to save some CPU cycles not fancy primary/backup scenarios... 

   

}

static inline void
hexminerm_init_task_c (struct hexminerm_config_task *htc,
                       struct hexminerm_info *info)
{
  htc->startbyte = 0x53;
  htc->datalength =
    (uint8_t) ((sizeof (struct hexminerm_config_task) - (6+4)) / 2);
  htc->command = 0x57;
  htc->address = htole16 (0x30C0);
  htc->hashclock = htole16 ((uint16_t) info->frequency);
  libhexm_setvoltage (info->core_voltage, &htc->refvoltage);

  htc->chip_mask = (uint8_t) info->chip_mask;

  libhexm_csum (&htc->startbyte, &htc->csum, &htc->csum);
}

static inline void
hexminerm_init_task (struct hexminerm_task *ht, struct hexminerm_info *info)
{
  
  ht->startbyte = 0x53;
  ht->datalength = (uint8_t) ((HEXMINERM_TASK_SIZE - 6) / 2);
  ht->command = 0x57;
  ht->address = htole16 (0x3080);
  //ht->difficulty = htole32 (0xFFFF001D);
}

static bool
need_reset (struct cgpu_info *hexminerm)
{
  if (no_work) return false;
  
  struct hexminerm_info *info = hexminerm->device_data;

  time_t now = time (NULL);
  bool ret = false;
  int i = 0;
  int secs = 20;
  

    
  while (i < info->asic_count)
        {
        	
        	if(!info->chip_is_dead[i] && ( info->chip_con_resets[i] < 5 && info->matching_work[i] && info->engines[i]) &&
        	 (info->last_chip_valid_work[i] +
              (int) (secs * 32 / info->engines[i]) < now))
           {
        		
        		//applog(LOG_ERR, "HEXM %i Chip[%i] last valid work %i secs ago", hexminerm->device_id, i + 1, (int)(now-info->last_chip_valid_work[i]));
        		ret = true;
        		info->chip_con_resets[i]++;
						info->last_chip_valid_work[i] = now;
						if (info->chip_con_resets[i] == 5) info->chip_is_dead[i] = true;
	      		break;
        	}
        	info->chip_con_resets[i] = 0;
        	i++;
        }	

  return ret;
}


static struct cgpu_info *
hexminerm_detect_one (libusb_device * dev, struct usb_find_devices *found)
{
  int miner_count, asic_count, frequency;
  int this_option_offset = ++option_offset;
  struct hexminerm_info *info;
  struct cgpu_info *hexminerm;

  bool configured;
  int i = 0;

  hexminerm = usb_alloc_cgpu (&hexminerm_drv, HEXM_MINER_THREADS);
  if (!usb_init (hexminerm, dev, found))
    {
      usb_uninit (hexminerm);
      return NULL;
    }
  hexminerm->device_data = calloc (sizeof (struct hexminerm_info), 1);

  if (unlikely (!(hexminerm->device_data)))
    {
      hexminerm->device_data = NULL;
      usb_uninit (hexminerm);
      return NULL;
    }
  configured =
    libhexm_get_options (this_option_offset, &asic_count, &frequency);
  if (opt_hexminerm_core_voltage < HEXM_MIN_COREMV
      || opt_hexminerm_core_voltage > HEXM_MAX_COREMV)
    {

      applog
        (LOG_ERR,
         "Invalid hexminerm-voltage %d must be %dmV - %dmV",
         opt_hexminerm_core_voltage, HEXM_MIN_COREMV, HEXM_MAX_COREMV);
      free (hexminerm->device_data);
      hexminerm->device_data = NULL;
      usb_uninit (hexminerm);
      return NULL;
    }
  info = hexminerm->device_data;
  info->hexworks = calloc (sizeof (struct work *), HEXMINERM_ARRAY_SIZE);
  if (unlikely (!(info->hexworks)))
    {
      free (hexminerm->device_data);
      hexminerm->device_data = NULL;
      usb_uninit (hexminerm);
      return NULL;
    }

  info->wr = (struct workm_result *) malloc (sizeof (struct workm_result));
  info->array_nonce_cache = calloc (16, sizeof (struct chip_resultsm));
  info->readbuf = calloc (HEXM_HASH_BUF_SIZE, sizeof (unsigned char));
  
  info->write_pos = 0;
  info->hash_read_pos = 0;
  info->hash_write_pos = 0;
  
  info->shut_read = false;
  info->shut_write = false;
  info->shut_reset = false;
  info->work = NULL;
  
  info->miner_count = HEXM_DEFAULT_MINER_NUM;
  info->asic_count = HEXM_DEFAULT_ASIC_NUM;
  info->frequency = HEXM_DEFAULT_FREQUENCY;
  info->pic_voltage_readings = HEXM_DEFAULT_CORE_VOLTAGE;
  info->core_voltage = opt_hexminerm_core_voltage;
  info->chip_mask = opt_hexminerm_chip_mask;

  info->wr->buf_empty_space = 63;
  info->work_block_local = work_block;
  info->reset_work = true;
  info->roll = 0;
  if (configured)
    {
      info->asic_count = asic_count;
      info->frequency = frequency;
    }


  info->ht = calloc (sizeof (struct hexminerm_task), 1);
  hexminerm_init_task (info->ht, info);
  
  
  
  
  //hexminerm_init_task (ht, info);
  
 while (i < HEXMINERM_ARRAY_SIZE)
    {
      info->hexworks[i] = calloc (1, sizeof (struct work));
      info->hexworks[i]->pool = NULL;
      i++;
    }
  
  i = 0; 
  info->power_checked = time (NULL);
  
  while (i < HEXM_DEFAULT_ASIC_NUM)
 		 info->chip_is_dead[i++] = false;
  
  
  if (!add_cgpu (hexminerm))
    {
      free (info->hexworks);
      free (hexminerm->device_data);
      hexminerm->device_data = NULL;
      hexminerm = usb_free_cgpu (hexminerm);
      usb_uninit (hexminerm);
      return NULL;
    }

  
  return hexminerm;
}

static void
hexminerm_detect (bool __maybe_unused hotplug)
{
  usb_detect (&hexminerm_drv, hexminerm_detect_one);
}

static void
do_hexminerm_close (struct thr_info *thr)
{
  struct cgpu_info *hexminerm = thr->cgpu;
  struct hexminerm_info *info = hexminerm->device_data;
  int i = 0;


  //pthread_join (info->write_thr, NULL);
#ifdef DBG_HEXM
  pthread_join (info->dbg_thr, NULL);
pthread_mutex_destroy (&info->lock);
#endif

  while (i < HEXMINERM_ARRAY_SIZE)
    {
      free_work (info->hexworks[i]);
      i++;
    }
  free (info->hexworks);
  free (info->readbuf);
  free (info->array_nonce_cache);
  free (info->wr);
  free (info->ht);
  if(info->work)
  	free_work(info->work);
  //usb_uninit(hexminerm);
  //Hotplug fucks on full mem free :) 
  //free (hexminerm->device_data);
  //hexminerm->device_data = NULL;
  //thr->cgpu = usb_free_cgpu(hexminerm);

}

static void
hexminerm_shutdown (struct thr_info *thr)
{
  struct cgpu_info *hexminerm = thr->cgpu;
  struct hexminerm_info *info = hexminerm->device_data;

  do_hexminerm_close (thr);

  usb_nodev (hexminerm);
}

#ifdef DBG_HEXM
static void *
hexminerm_get_stats (void *userdata)
{
  struct cgpu_info *hexminerm = (struct cgpu_info *) userdata;
  struct hexminerm_info *info = hexminerm->device_data;
  char threadname[24];
  snprintf (threadname, 24, "hexm_dbg/%d", hexminerm->device_id);
  RenameThread (threadname);
  while (!libhexm_usb_dead (hexminerm))
    {

      cgsleep_ms (30 * 1000);

      applog (LOG_ERR,
              "HEXM %i was_64 %i, was_above_60 %i was_zero %i, was_below_5 %i",
              hexminerm->device_id, info->buf_empty_was_64,
              info->buf_empty_was_above_60, info->buf_empty_was_zero,
              info->buf_empty_was_below_5);

      applog (LOG_ERR,
              "HEXM %i roled %i, getworks %i", hexminerm->device_id,
              info->roled, info->totworks);


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



static bool
hexminerm_thread_init (struct thr_info *thr)
{
  struct cgpu_info *hexminerm = thr->cgpu;
  struct hexminerm_info *info = hexminerm->device_data;

  info->thr = thr;


#ifdef DBG_HEXM
  mutex_init (&info->lock);
  if (pthread_create
      (&info->dbg_thr, NULL, hexminerm_get_stats, (void *) hexminerm))
    quit (1, "Failed to create hexminerm dbg_thr");
#endif

	struct hexminerm_config_task *htc;

  htc = calloc (sizeof (struct hexminerm_config_task), 1);

  hexminerm_init_task_c (htc, info);

  int ret =
    libhexm_sendHashData (hexminerm, &htc->startbyte,
                          sizeof (struct hexminerm_config_task));

  if (ret != sizeof (struct hexminerm_config_task))
    applog (LOG_ERR, "HEXM %i Send config failed", hexminerm->device_id);


  free(htc);

  return true;
}
static void do_write_hexm(struct thr_info *thr)
{

  struct cgpu_info *hexminerm = thr->cgpu;
  struct hexminerm_info *info = hexminerm->device_data;
  //struct timeval tm;
	struct work *tmpwork = NULL;
  bool power;
  int jobs_to_send = 8;

  int send_jobs, ret;

if (time (NULL) - info->power_checked > 30)
        {

          info->power_checked = time (NULL);
          power = need_reset (hexminerm);
          
          if (power)
            {
            	info->b_reset_count++;
              libhexm_set_word (hexminerm, 0x3080 + HEXMINERM_TASK_SIZE - 8,
                                0x0004);
              info->reset_work = true;
              cgsleep_ms (200);
            }
        }
      send_jobs = 0;
/*
  if (info->work) {
    if(stale_work (info->work, false))
     info->reset_work = true;
    	
  }
  */  
      while (!libhexm_usb_dead (hexminerm) && ((info->work_block_local != work_block)
             || (info->wr->buf_empty_space > 45 && send_jobs < jobs_to_send)
             || info->reset_work))
        {
        again:
          if (!info->work)
            {
              info->roll = 0;
              info->work = get_work (thr, thr->id);
              info->work->ping = 1;
              if (info->work_block_local != work_block)
                {
                  info->reset_work = true;
                  info->work_block_local = work_block;
                }
#ifdef DBG_HEXM
              info->totworks++;
#endif
            }

          if (stale_work (info->work, false))
            {
              free_work (info->work);
              info->work = NULL;
              goto again;
            }

          if (info->write_pos >= HEXMINERM_ARRAY_SIZE_REAL || info->reset_work)
            info->write_pos = 0;

          info->work->subid = info->write_pos;
          tmpwork = copy_work_noffset_fast_no_id (info->work, info->roll++);
      
          hexminerm_create_task (info->reset_work, info->ht,
                                 tmpwork);
          
          free_work (info->hexworks[info->write_pos]);
          info->hexworks[info->write_pos] = tmpwork;
          

       
          if (info->work->drv_rolllimit)
            {
              info->work->drv_rolllimit--;
#ifdef DBG_HEXM
              info->roled++;
#endif
            }
          else
            {
              free_work (info->work);
              info->work = NULL;
            }

#ifdef DBG_HEXM
          if (info->reset_work)
            applog (LOG_ERR, "HEXM %i  Reset info->work Task!",
                    hexminerm->device_id);
#endif


          ret = hexminerm_send_task (info->ht, hexminerm);
          info->write_pos++;
          send_jobs++;
          if (ret == HEXMINERM_TASK_SIZE && info->reset_work)
            {
              info->reset_work = false;
              info->wr->buf_empty_space = 63;
              send_jobs-=5;
            }
        }
}

static int64_t
hexminerm_scanhash (struct thr_info *thr)
{
  struct cgpu_info *hexminerm = thr->cgpu;
  struct hexminerm_info *info = hexminerm->device_data;

  uint32_t nonce;
  double found;
  double hash_count = 0;
  int i = 0;
  int ret_r = 0;
  int64_t rethash_count = 0;

  if (libhexm_usb_dead (hexminerm)) {
   	
   	hexminerm->shutdown = true;
    return -1;
  }
  
  do_write_hexm(thr);
  
 if (libhexm_usb_dead (hexminerm)) {
   	
   	hexminerm->shutdown = true;
    return -1;
    
  }
  if (info->hash_write_pos + HEXM_USB_R_SIZE >= HEXM_HASH_BUF_SIZE)
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
        libhexm_eatHashData (info->wr, info->readbuf, &info->hash_read_pos,
                             &info->hash_write_pos);
      if (ret_r > HEXM_BUF_DATA)
        goto out;

      

#ifdef DBG_HEXM
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

      if (info->wr->lastnonceid > HEXMINERM_ARRAY_SIZE_REAL)
        info->wr->lastnonceid = 0;

      if (info->wr->lastchippos >= HEXM_DEFAULT_ASIC_NUM)
        info->wr->lastchippos = 7;

      if (libhexm_cachenonce
          (&info->array_nonce_cache[info->wr->lastchippos],
           info->wr->lastnonce))
        {
          nonce = htole32 (info->wr->lastnonce);

          found = hexminerm_predecode_nonce (hexminerm, thr, nonce,
                                             info->wr->lastnonceid);

          if (found > 0)
            {
             
              info->engines[(uint8_t) info->wr->lastchippos] =
                info->wr->good_engines;
              info->last_chip_valid_work[(uint8_t) info->wr->lastchippos] =
                time (NULL);
              if (hash_count == 0)
                libhexm_getvoltage (htole16 (info->wr->lastvoltage),
                                    &info->pic_voltage_readings);

              hash_count += found;
              info->matching_work[info->wr->lastchippos]++;
            }
          else
            {
              inc_hw_errors(thr);
            }
        }
      else
        {
          info->dupe[info->wr->lastchippos]++;
        }
    out:
      if (ret_r == HEXM_BUF_ERR)
        {
          info->usb_r_errors++;
        }
    done:
      if (info->hash_write_pos - info->hash_read_pos >= HEXM_MAX_WORK_SIZE)
        goto again;
    }

  ret_r =
    libhexm_readHashData (hexminerm, info->readbuf, &info->hash_write_pos,
                          HEXMINERM_BULK_READ_TIMEOUT, true);
                          
    if (ret_r != LIBUSB_SUCCESS)
    {
      info->usb_bad_reads++;
    }
  else
    {
      info->usb_bad_reads = 0;
    }

  if (info->usb_bad_reads > 20)
    libhexm_reset (hexminerm);
    
  rethash_count = (0xffffffffull * (int64_t) hash_count);
  

  if (libhexm_usb_dead (hexminerm)) {
   	hexminerm->shutdown = true;
    return -1;
    
  }

  return rethash_count;
}

static void
get_hexminerm_statline_before (char *buf, size_t bufsiz,
                               struct cgpu_info *hexminerm)
{
  if (!hexminerm->device_data)
    return;
  struct hexminerm_info *info = hexminerm->device_data;
  tailsprintf (buf, bufsiz, "%3d %4d/%4dmV", info->frequency,
               info->core_voltage, info->pic_voltage_readings);
}

static struct api_data *
hexminerm_api_stats (struct cgpu_info *cgpu)
{

  struct api_data *root = NULL;
  struct hexminerm_info *info = cgpu->device_data;
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

struct device_drv hexminerm_drv = {
  .drv_id = DRIVER_hexminerm,
  .dname = "hexminerm",
  .name = "HEXM",
  .drv_detect = hexminerm_detect,
  .thread_init = hexminerm_thread_init,
  .hash_work = hash_driver_work,
  .scanwork = hexminerm_scanhash,
 // .flush_work = hexminerm_flush_work,
  .get_api_stats = hexminerm_api_stats,
  .get_statline_before = get_hexminerm_statline_before,
  .thread_shutdown = hexminerm_shutdown,
};
