/*$T indentinput.c GC 1.140 10/16/13 10:20:34 */
/*
Special thanks to Luke Dashjr - Nanofory code was adopted from bfgminer - mcp2210.c
*/

#define FIRST_BASE 61
#define SECOND_BASE 4
static const int8_t bitfury_counters[16] = { 64, 64,
  SECOND_BASE, SECOND_BASE + 4, SECOND_BASE + 2, SECOND_BASE + 2 + 16,
  SECOND_BASE, SECOND_BASE + 1,
  (FIRST_BASE) % 65, (FIRST_BASE + 1) % 65, (FIRST_BASE + 3) % 65,
  (FIRST_BASE + 3 + 16) % 65, (FIRST_BASE + 4) % 65,
  (FIRST_BASE + 4 + 4) % 65, (FIRST_BASE + 3 + 3) % 65,
  (FIRST_BASE + 3 + 1 + 3) % 65
};
const uint32_t SHA_U[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf
};

#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define BT_OFFSETS_U 7

static const uint32_t bf_offsetsu[] =
  { -0x800000, 0, 0xffc00000, 0xff800000, 0x02800000, 0x02C00000,
  0x00400000
};

static bool
libhexu_usb_dead (struct cgpu_info *hexmineru)
{
  struct cg_usb_device *usbdev;
  usbdev = hexmineru->usbdev;
  return (usbdev == NULL
          || usbdev->handle == NULL
          || hexmineru->shutdown
          || hexmineru->usbinfo.nodev || hexmineru->deven != DEV_ENABLED);
}

static void
libhexu_reset (struct cgpu_info *hexmineru)
{
  struct hexmineru_info *info = hexmineru->device_data;
  struct cg_usb_device *usbdev;
  int err = LIBUSB_SUCCESS;
  int pstate;
  usb_lock_w (hexmineru, pstate);
  usbdev = hexmineru->usbdev;
  if (libhexu_usb_dead (hexmineru))
    goto out;
  err = libusb_reset_device (usbdev->handle);
out:
  usb_unlock_w (hexmineru, pstate);

  applog (LOG_DEBUG, "libhexu_reset %d", err);
}

static int
libhexu_sendHashData (struct cgpu_info *hexmineru, unsigned char *sendbuf,
                      size_t buf_len, int timeout)
{

  struct hexmineru_info *info = hexmineru->device_data;
  struct cg_usb_device *usbdev;
  int wrote = 0, written = 0;
  int err = LIBUSB_SUCCESS;

  int pstate;
  usb_lock_w (hexmineru, pstate);
  usbdev = hexmineru->usbdev;
  if (libhexu_usb_dead (hexmineru))
    goto out;
  while (written < buf_len && err == LIBUSB_SUCCESS)
    {
      err = libusb_interrupt_transfer
        (usbdev->handle,
         0x01,
         sendbuf + written,
         MIN (HEXU_USB_WR_SIZE, buf_len - written), &wrote, timeout);
      if (err == LIBUSB_SUCCESS)
        written += wrote;
    }
out:
  usb_unlock_w (hexmineru, pstate);
  if (err == LIBUSB_ERROR_NO_DEVICE || err == LIBUSB_ERROR_NOT_FOUND)
    {
      hexmineru->shutdown = true;
      cgsem_post (&info->qsem);
    }

  return written;

}

static int
  libhexu_readHashData
  (struct cgpu_info *hexmineru,
   unsigned char *hash, int *hash_write_pos, int timeout, bool read_once)
{
  struct hexmineru_info *info = hexmineru->device_data;
  struct cg_usb_device *usbdev;
  int read = 0, total = 0;
  int err = LIBUSB_SUCCESS;
  int pstate;
  usb_lock_r (hexmineru, pstate);
  usbdev = hexmineru->usbdev;
  if (libhexu_usb_dead (hexmineru))
    goto out;
  while (*hash_write_pos + HEXU_USB_R_SIZE < HEXU_HASH_BUF_SIZE
         && err == LIBUSB_SUCCESS)
    {
      err =
        libusb_interrupt_transfer (usbdev->handle, 0x81,
                                   hash + *hash_write_pos, HEXU_USB_R_SIZE,
                                   &read, timeout);
      if (err == LIBUSB_SUCCESS)
        {
          *hash_write_pos += read;
          total += read;
        }
      if (read_once)
        break;
    }
out:
  usb_unlock_r (hexmineru, pstate);

  return total;
}

static void
libhexu_libbitfury_ms3_compute (unsigned *p)
{
  unsigned a, b, c, d, e, f, g, h, ne, na, i;
//Buggy on init but who cares :)
#if defined(__BIG_ENDIAN__) || defined(MIPSEB)
  for (i = 0; i < 8; i++)
    p[i] = htole32 (p[i]);
#endif
  a = p[0];
  b = p[1];
  c = p[2];
  d = p[3];
  e = p[4];
  f = p[5];
  g = p[6];
  h = p[7];

  for (i = 0; i < 3; i++)
    {
#if defined(__BIG_ENDIAN__) || defined(MIPSEB)
      p[i + 16] = htole32 (p[i + 16]);
#endif
      ne = p[i + 16] + SHA_U[i] + h + Ch (e, f, g) + S1 (e) + d;
      na =
        p[i + 16] + SHA_U[i] + h + Ch (e, f, g) + S1 (e) + S0 (a) + Maj (a, b,
                                                                         c);
      d = c;
      c = b;
      b = a;
      a = na;
      h = g;
      g = f;
      f = e;
      e = ne;
    }
  p[15] = a;
  p[14] = b;
  p[13] = c;
  p[12] = d;
  p[11] = e;
  p[10] = f;
  p[9] = g;
  p[8] = h;


#if defined(__BIG_ENDIAN__) || defined(MIPSEB)
  for (i = 0; i < 19; i++)
    p[i] = htole32 (p[i]);
#endif
}

static void
libhexu_work_to_bitfury_payload (struct hexmineru_task *p, struct work *w)
{
  //memset(p, 0, HEXMINERU_TASK_SIZE);
  memcpy (&p->midstate[0], w->midstate, 32);
  memcpy (&p->m7, w->data + 64, 12);
}
static void
libhexu_bitfury_payload_to_atrvec (uint32_t * atrvec,
                                   struct hexmineru_task *p)
{
/* Programming next value */

  memcpy (atrvec, p, 76);
  libhexu_libbitfury_ms3_compute (atrvec);
}

static bool
libhexu_cachenonce (struct chip_resultsu *nonce_cache, uint32_t nonce)
{
  int i = 0;
  while (i < HEXU_NONCE_CASH_SIZE && nonce_cache->nonces[i] != nonce)
    i++;
  if (i < HEXU_NONCE_CASH_SIZE)
    return false;
  //Rotate
  if (nonce_cache->nonce_cache_write_pos == HEXU_NONCE_CASH_SIZE)
    nonce_cache->nonce_cache_write_pos = 0;
  nonce_cache->nonces[nonce_cache->nonce_cache_write_pos++] = nonce;
  return true;
}

static uint32_t
libhexu_decnonce (uint32_t in)
{
  uint32_t out;
  /* First part load */
  out = (in & 0xFF) << 24;
  in >>= 8;
  /* Byte reversal */
  in = (((in & 0xaaaaaaaa) >> 1) | ((in & 0x55555555) << 1));
  in = (((in & 0xcccccccc) >> 2) | ((in & 0x33333333) << 2));
  in = (((in & 0xf0f0f0f0) >> 4) | ((in & 0x0f0f0f0f) << 4));
  out |= (in >> 2) & 0x3FFFFF;
  /* Extraction */
  if (in & 1)
    out |= (1 << 23);
  if (in & 2)
    out |= (1 << 22);
  out -= 0x800004;
  return out;
}

static int
libhexu_bitfury_checkresults (struct thr_info *thr, struct work *work,
                              uint32_t nonce)
{
  int i;
  for (i = 0; i < BT_OFFSETS_U; i++)
    {
      if (test_nonce (work, nonce + bf_offsetsu[i]))
        {
          submit_tested_work_no_clone (thr, work, true);
          return 1;
        }
    }
  free_work (work);
  return 0;
}

static int
hexmineru_predecode_nonce (struct cgpu_info *hexmineru, struct thr_info *thr,
                           uint32_t nonce, int work_id)
{
  struct hexmineru_info *info = hexmineru->device_data;
  struct work *work_sub;

  mutex_lock (&info->lock);

  work_sub = copy_work (info->hexworks[work_id]);
  mutex_unlock (&info->lock);
  return libhexu_bitfury_checkresults (thr, work_sub, nonce);


}
