
//Once More - Thank you Zefir :)

static bool
libhexm_cachenonce (struct chip_resultsm *nonce_cache, uint32_t nonce)
{
  int i = 0;
  while (i < HEXM_NONCE_CASH_SIZE && nonce_cache->nonces[i] != nonce)
    i++;
  if (i < HEXM_NONCE_CASH_SIZE)
    return false;
  //Rotate
  if (nonce_cache->nonce_cache_write_pos == HEXM_NONCE_CASH_SIZE)
    nonce_cache->nonce_cache_write_pos = 0;
  nonce_cache->nonces[nonce_cache->nonce_cache_write_pos++] = nonce;
  return true;
}

char *
libhexm_set_config_voltage (char *arg)
{
  int val1, ret;
  ret = sscanf (arg, "%d", &val1);
  if (ret < 1)
    return "No values passed to hexminerm-voltage";
  if (val1 < HEXM_MIN_COREMV || val1 > HEXM_MAX_COREMV)
    return "Invalid value passed to hexminerm-voltage";
  opt_hexminerm_core_voltage = val1;
  return NULL;
}

char *
libhexm_set_config_chip_mask (char *arg)
{
  int val1, ret;
  ret = sscanf (arg, "%d", &val1);
  if (ret < 1)
    return "No values passed to hexminerm-chip-mask";
  opt_hexminerm_chip_mask = val1;
  return NULL;
}


static void
libhexm_csum (unsigned char *startptr, unsigned char *endptr,
              unsigned char *resptr)
{
  unsigned char *b = startptr;
  uint8_t sum = 0;
  while (b < endptr)
    sum += *b++;
  memcpy (resptr, &sum, 1);
}

static bool
libhexm_get_options (int this_option_offset, int *asic_count, int *frequency)
{
  char buf[BUFSIZ + 1];
  char *ptr, *comma, *colon, *colon2, *colon3, *colon4;
  bool timeout_default;
  size_t max;
  int i, tmp;
  if (opt_hexminerm_options == NULL)
    buf[0] = '\0';
  else
    {
      ptr = opt_hexminerm_options;
      for (i = 0; i < this_option_offset; i++)
        {
          comma = strchr (ptr, ',');
          if (comma == NULL)
            break;
          ptr = comma + 1;
        }
      comma = strchr (ptr, ',');
      if (comma == NULL)
        max = strlen (ptr);
      else
        max = comma - ptr;
      if (max > BUFSIZ)
        max = BUFSIZ;
      strncpy (buf, ptr, max);
      buf[max] = '\0';
    }
  if (!(*buf))
    return false;
  colon = strchr (buf, ':');
  if (colon)
    *(colon++) = '\0';
  tmp = atoi (buf);
  if (tmp > 0 && tmp <= HEXM_DEFAULT_ASIC_NUM)
    *asic_count = tmp;
  else
    {
      quit (1,
            "Invalid hexminerm-options for " "asic_count (%s) must be 1 ~ %d",
            buf, HEXM_DEFAULT_ASIC_NUM);
    }
  if (colon && *colon)
    {
      tmp = atoi (colon);
      if (tmp < HEXM_MIN_FREQUENCY || tmp > HEXM_MAX_FREQUENCY)
        {
          quit
            (1,
             "Invalid hexminerm-options for frequency (%s) must be %d <= frequency <= %d",
             colon, HEXM_MIN_FREQUENCY, HEXM_MAX_FREQUENCY);
        }
      *frequency = tmp;
    }
  return true;
}

static bool
libhexm_usb_dead (struct cgpu_info *hexminerm)
{
  struct cg_usb_device *usbdev;
  struct hexminerm_info *info = hexminerm->device_data;
  if (!info)
    return true;
  usbdev = hexminerm->usbdev;
  bool ret = (usbdev == NULL
              || usbdev->handle == NULL
              || hexminerm->shutdown
              || info->shut_read || info->shut_write || info->shut_reset
              || hexminerm->usbinfo.nodev || hexminerm->deven != DEV_ENABLED);
  //if (ret)
    //hexminerm->shutdown = true;

  return ret;
}


static int
libhexm_sendHashData (struct cgpu_info *hexminerm, unsigned char *sendbuf,
                      size_t buf_len)
{
  struct hexminerm_info *info = hexminerm->device_data;
  struct cg_usb_device *usbdev;
  int wrote = 0, written = 0;
  int err = LIBUSB_SUCCESS;

  usbdev = hexminerm->usbdev;
  if (libhexm_usb_dead (hexminerm))
    goto out;
  while (written < buf_len && err == LIBUSB_SUCCESS)
    {
      err = libusb_bulk_transfer
        (usbdev->handle,
         0x02,
         sendbuf + written,
         MIN (HEXM_USB_WR_SIZE, buf_len - written), &wrote,
         HEXM_USB_WR_TIME_OUT);
      if (err == LIBUSB_SUCCESS)
        written += wrote;
    }
out:
  if (err == LIBUSB_ERROR_NO_DEVICE || err == LIBUSB_ERROR_NOT_FOUND)
    info->shut_write = true;
    
#ifdef DBG_HEXM
if(err != LIBUSB_SUCCESS)
	applog(LOG_ERR, "HEXM %i libhexm_sendHashData %s",hexminerm->device_id, libusb_error_name(err));
#endif

  return written;
}

static void
libhexm_reset (struct cgpu_info *hexminerm)
{

  struct hexminerm_info *info = hexminerm->device_data;
  struct cg_usb_device *usbdev;
  int err = LIBUSB_SUCCESS;

  usbdev = hexminerm->usbdev;
  if (libhexm_usb_dead (hexminerm))
    goto out;
  err = libusb_reset_device (usbdev->handle);
out:
  if (err == LIBUSB_ERROR_NO_DEVICE || err == LIBUSB_ERROR_NOT_FOUND)
    info->shut_reset = true;
#ifdef DBG_HEXM
if(err != LIBUSB_SUCCESS)
	applog(LOG_ERR, "HEXM %i libhexm_reset %s",hexminerm->device_id, libusb_error_name(err));
#endif

  info->usb_reset_count++;
}

static int libhexm_readHashData
  (struct cgpu_info *hexminerm,
   unsigned char *hash, int *hash_write_pos, int timeout, bool read_once)
{
  struct hexminerm_info *info = hexminerm->device_data;
  struct cg_usb_device *usbdev;
  int read = 0, total = 0;
  int err = LIBUSB_SUCCESS;

  usbdev = hexminerm->usbdev;
  if (libhexm_usb_dead (hexminerm))
    goto out;
  while (*hash_write_pos + HEXM_USB_R_SIZE < HEXM_HASH_BUF_SIZE
         && err == LIBUSB_SUCCESS)
    {
      err =
        libusb_bulk_transfer (usbdev->handle, 0x82, hash + *hash_write_pos,
                              HEXM_USB_R_SIZE, &read, timeout);
      if (err == LIBUSB_SUCCESS)
        {
          *hash_write_pos += read;
          total += read;
        }
      if (read_once)
        break;
    }
out:
  if (err == LIBUSB_ERROR_NO_DEVICE || err == LIBUSB_ERROR_NOT_FOUND)
    {
      info->shut_read = true;
    }
#ifdef DBG_HEXM
if(err != LIBUSB_SUCCESS)
	applog(LOG_ERR, "HEXM %i libhexm_readHashData %s",hexminerm->device_id, libusb_error_name(err));
#endif

  return err;
}
static double
hexminerm_predecode_nonce (struct cgpu_info *hexminerm, struct thr_info *thr,
                           uint32_t nonce, uint8_t work_id)
{
  struct hexminerm_info *info = hexminerm->device_data;

  if (info->hexworks[work_id]->pool == NULL)
    {
      return 0;
    }

  if (test_nonce (info->hexworks[work_id], nonce))
    {
      submit_tested_work_fast_clone (thr, info->hexworks[work_id], true);
      return 1;
    }

		return 0;
}


static void
libhexm_getvoltage (uint16_t wr_bukvoltage, int *info_pic_voltage_readings)
{
  float voltagehuman;
  voltagehuman =
    (float) ((float) wr_bukvoltage * (float) 3300 / (float) ((1 << 12) - 1));
  *info_pic_voltage_readings = (int) voltagehuman;
}

static void
libhexm_setvoltage (int info_voltage, uint16_t * refvoltage)
{
  uint16_t voltageadc;
  voltageadc =
    (uint16_t) ((float) info_voltage / (float) 1000 / (float) 3.3 *
                ((1 << 12) - 1));
  *refvoltage = htole16 (voltageadc);
}

static int
libhexm_eatHashData (struct workm_result *wr, unsigned char *hash,
                     int *hash_read_pos, int *hash_write_pos)
{
  uint8_t psum;
  int wrpos;
  unsigned char *csum_pos;
  bool ok;
eat:
  while (*hash_read_pos < *hash_write_pos && hash[*hash_read_pos] != 0x53)
    {
#ifdef DBG_HEXM
      //  applog (LOG_ERR, "%x", hash[*hash_read_pos]);
#endif

      *hash_read_pos += 1;
    }
  if (*hash_write_pos - *hash_read_pos < 8)
    return HEXM_BUF_SKIP;
  memcpy ((char *) &wr->startbyte, &hash[*hash_read_pos],
          HEXM_BASE_WORK_SIZE - 1);
  wr->address = htole16 (wr->address);
  /* Address is outside be strict to avoid mem corruption - not fancy but it works */

  ok = (wr->command == 0x52) &&
    ((wr->address == HEXM_WORKANSWER_ADR && wr->datalength == 0x06)
     || (wr->address == 0x3008 && wr->datalength == 1));
  if (!ok)
    {
#ifdef DBG_HEXM
      //applog (LOG_ERR, "%x", hash[*hash_read_pos]);
#endif
      *hash_read_pos += 1;
      goto eat;
    }
  if (*hash_write_pos - *hash_read_pos <
      HEXM_BASE_WORK_SIZE + wr->datalength * 2)
    return HEXM_BUF_SKIP;
  csum_pos =
    hash + *hash_read_pos + HEXM_BASE_WORK_SIZE + wr->datalength * 2 - 1;
  //Crap?
  if (csum_pos - hash < HEXM_HASH_BUF_SIZE)
    {
//That was writing somewhere and corrupting memory because of faulty usb reads....
      libhexm_csum (hash + *hash_read_pos, csum_pos, &psum);
      if (psum != *csum_pos)
        {
#ifdef DBG_HEXM
          //applog (LOG_ERR, "%x", hash[*hash_read_pos]);
#endif
          *hash_read_pos += 1;
          return HEXM_BUF_ERR;
        }
    }
  else
    {
#ifdef DBG_HEXM
      //applog (LOG_ERR, "%x", hash[*hash_read_pos]);
#endif
      *hash_read_pos += 1;
      return HEXM_BUF_ERR;
    }
  wrpos = (wr->address - HEXM_WORKANSWER_ADR) + HEXM_BASE_WORK_SIZE - 1;
  memcpy
    ((char *) &wr->startbyte + wrpos,
     &hash[*hash_read_pos + HEXM_BASE_WORK_SIZE - 1], wr->datalength * 2);
  *hash_read_pos += HEXM_BASE_WORK_SIZE + wr->datalength * 2;

  return HEXM_BUF_DATA;
}


static void
libhexm_set_word (struct cgpu_info *hexminerm, uint16_t address,
                  uint16_t word)
{
  unsigned char status[10];
  uint16_t wr_adr = htole16 (address);
  uint16_t ledata = htole16 (word);
  status[0] = 0x53;
  status[1] = 0x01;
  status[2] = 0x57;
  memcpy (status + 3, &wr_adr, 2);
  memcpy (status + 5, &ledata, 2);
  libhexm_csum (status, status + 7, status + 7);
  libhexm_sendHashData (hexminerm, status, 8);
}
