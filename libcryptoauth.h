/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2015 Cryptotronix, LLC.
 *
 * This file is part of libcryptoauth.
 *
 * libcryptoauth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libcryptoauth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libcryptoauth.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef LIBCRYPTOAUTH_H_
#define LIBCRYPTOAUTH_H_

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <gcrypt.h>
#include <unistd.h>

#define LCA_SHA256_DLEN 32

enum LCA_LOG_LEVEL
  {
    SEVERE = 0,
    WARNING,
    INFO,
    DEBUG
  };

void
lca_init (void);

void
lca_init_and_debug (enum LCA_LOG_LEVEL lvl);

/* Utility Functions */

struct lca_octet_buffer
{
    unsigned char *ptr; /* Pointer to buffer */
    unsigned int len;   /* Length of data */
};

/**
 * Converts an octet buffer into a printable hex string.
 *
 * @param buf The octet buffer
 *
 * @return A malloc'd character string
 */
const char*
lca_octet_buffer2hex_string (struct lca_octet_buffer buf);

/**
 * Wipes the buffer with zeroes.
 *
 * @param buf The buffer to be wiped.
 * @param len The length of the buffer
 */
void
lca_wipe(unsigned char *buf, unsigned int len);

/**
 * Mallocs a buffer of length len and then wipes the buffer with zeroes.
 *
 * @param len The length of the buffer to allocate
 *
 * @return The allocated buffer.  NULL on error.
 */
uint8_t*
lca_malloc_wipe(unsigned int len);

/* Wipes then frees the buffer */
void
lca_free_wipe(unsigned char* buf, unsigned int len);

/**
 * Compares two octet buffers
 *
 * @param lhs The left octet buffer
 * @param rhs The right octet buffer
 *
 * @return True if the contents are the same
 */
bool
lca_memcmp_octet_buffer (struct lca_octet_buffer lhs,
                          struct lca_octet_buffer rhs)
  __attribute__ ((pure));

/**
 * Created a malloc'd octet buffer.
 *
 * @param len The length of the desired buffer.
 *
 * @return A malloc'd and wiped octet buffer.
 */
struct lca_octet_buffer
lca_make_buffer(unsigned int len);

/**
 * Frees and clears an octet_buffer
 *
 * @param buf The malloc'ed octet buffer
 */
void
lca_free_octet_buffer(struct lca_octet_buffer buf);

uint8_t
lca_reverse_bits_in_byte(uint8_t b) __attribute__ ((const));

/**
 * Converts an ASCII encoded Hex character string into binary.
 *
 * @param hex The null terminated ASCII Hex string
 * @param max_len The expected max len of the string
 *
 * @return The malloc'd binary encoding.  Buf.ptr will be NULL on error
 */
struct lca_octet_buffer
lca_ascii_hex_2_bin (const char* hex, unsigned int max_len);

/**
 * Returns true if the string is all hex
 *
 * @param hex The hex string to test
 * @param max_len the expected len of the string
 *
 * @return True if the string is all hex
 */
bool
lca_is_all_hex (const char* hex, unsigned int max_len);

/**
 * Copies the src octet buffer into the dst at the given offset.  This
 * will assert to make sure the buffer's don't overflow.
 *
 * @param dst The destination buffer.
 * @param offset The offset in the destination buffer.
 * @param src The source buffer.
 *
 * @return The updated offset (offset + dst.len)
 */

unsigned int
lca_copy_buffer (struct lca_octet_buffer dst,
                  unsigned int offset,
                  const struct lca_octet_buffer src);

/**
 * Copies p of length len into the octet buffer.
 *
 * @param buf The destination buffer
 * @param offset The offset in the destination buffer.
 * @param p the pointer to the data
 * @param len The lengh of the data
 *
 * @return The updated offset (offset + len)
 */
unsigned int
lca_copy_to_buffer (struct lca_octet_buffer buf,
                     unsigned int offset,
                     const uint8_t *p,
                     unsigned int len);

/**
 * XOR two buffers.  The buffers must not be zero and must be the same size.
 *
 * @param lhs The left buffer.
 * @param rhs The right buffer.
 *
 * @return A malloc'd buffer that is the XOR of the two.
 */
struct lca_octet_buffer
lca_xor_buffers (const struct lca_octet_buffer lhs,
                  const struct lca_octet_buffer rhs);

/**
 * Convert a char into a "byte".
 *
 * @param c The char to convert
 *
 * @return An unsigned int representing the char. Will return UINT_MAX
 * on error.
 */
unsigned int
lca_c2b (char c) __attribute__ ((const));

/* CRC Functions */

/**
 * Calculates a CRC16 and compares it to the specified CRC. Returns
 * true if the CRC matches.
 *
 * @param data The data on which a CRC is calculated.
 * @param data_len The length of the data.
 * @param crc A two byte CRC to which a new CRC will be compared.
 *
 * @return true if the CRC matches the calculated, otherwise false.
 */
bool
lca_is_crc_16_valid (const uint8_t *data, unsigned int data_len,
                     const uint8_t *crc) __attribute__ ((pure));

/**
 * Calculates a two byte CRC over the specified data.
 *
 * @param p The pointer to the data on which a CRC will be calculated
 * @param length The length of the data.
 *
 * @return The CRC16 over the data.
 */
uint16_t
lca_calculate_crc16 (const uint8_t *p, unsigned int length)
  __attribute__ ((pure));


/* Command Adaptation */



struct Command_ATSHA204
{
    uint8_t command;
    uint8_t count;
    uint8_t opcode;
    uint8_t param1;
    uint8_t param2[2];
    uint8_t *data;
    unsigned int data_len;
    uint8_t checksum[2];
    struct timespec exec_time;
};

enum LCA_STATUS_RESPONSE
  {
    RSP_SUCCESS = 0,            /**< The command succeeded. */
    RSP_CHECKMAC_MISCOMPARE = 0x01, /**< The CHECKMAC Command failed */
    RSP_PARSE_ERROR = 0x03,     /**< Command was received but length,
                                   opcode or parameters are illegal
                                   regardless of device state */
    ECC_FAULT = 0x05,
    RSP_EXECUTION_ERROR = 0x0F, /**< Command was received but can't
                                   be executed in the current state */
    RSP_AWAKE = 0x11,           /**< The device is awake */
    RSP_COMM_ERROR = 0xFF,       /**< Command was not received properly
                                  */
    RSP_NAK = 0xAA,     /**< Response was NAKed and a retry should occur */
  };


enum LCA_STATUS_RESPONSE
lca_process_command (int fd,
                      struct Command_ATSHA204 *c,
                      uint8_t* rec_buf,
                      unsigned int recv_len);

enum LCA_STATUS_RESPONSE
lca_send_and_receive (int fd,
                       const uint8_t *send_buf,
                       unsigned int send_buf_len,
                       uint8_t *recv_buf,
                       unsigned int recv_buf_len,
                       struct timespec *wait_time);

unsigned int
lca_serialize_command (struct Command_ATSHA204 *c,
                        uint8_t **serialized);

enum LCA_STATUS_RESPONSE
lca_read_and_validate (int fd,
                        uint8_t *buf,
                        unsigned int len);

struct lca_octet_buffer
lca_send_and_get_rsp (int fd,
                      const uint8_t *send_buf,
                      const unsigned int send_buf_len,
                      struct timespec wait_time,
                      const int MAX_RECV_LEN);

/* Hashing functions */
/**
 * Perform a SHA256 Digest on a file stream
 *
 * @param fp The file pointer to hash
 *
 * @return A malloc'd buffer of 32 bytes containing the digest.
 * buf.ptr will be null on error
 */
struct lca_octet_buffer
lca_sha256 (FILE *fp);

/**
 * SHA256s a file and returns the gcrypt digest
 *
 * @param fp The file to hash
 * @param digest the digest to return
 *
 * @return 0 on success.
 */
int
lca_hash_file (FILE *fp, gcry_sexp_t *digest);

/**
 * Perform a SHA 256 on a fixed data block
 *
 * @param data The data to hash
 *
 * @return The digest
 */
struct lca_octet_buffer
lca_sha256_buffer (struct lca_octet_buffer data);

/**
 * Performs an offline verification of a MAC using the default settings.
 *
 * @param challenge The 32 Byte challenge
 * @param challenge_rsp The 32 Byte challenge response
 * @param key The 32 byte key
 * @param key_slot The key slot used
 *
 * @return True if matched, otherwise false
 */
bool
lca_verify_hash_defaults (struct lca_octet_buffer challenge,
                           struct lca_octet_buffer challenge_rsp,
                           struct lca_octet_buffer key,
                           unsigned int key_slot);

/**
 * Performs an offline verification of HMAC using the default settings.
 *
 * @param challenge The 32 Byte challenge
 * @param challenge_rsp The 32 Byte challenge response
 * @param key The 32 byte key
 * @param key_slot The key slot used
 *
 * @return True if matched, otherwise false
 */
bool
lca_verify_hmac_defaults (struct lca_octet_buffer challenge,
                          struct lca_octet_buffer challenge_rsp,
                          struct lca_octet_buffer key, unsigned int key_slot);


/**
 * Performs a software based HMAC 256 using default values for the
 * ATSHA204.
 *
 * @param challenge The 32 byte challenge to HMAC.
 * @param key The HMAC 256 key.
 * @param key_slot the key_slot to use (0-15).
 *
 * @return A buffer containing the digest
 */
struct lca_octet_buffer
lca_soft_hmac256_defaults(struct lca_octet_buffer challenge,
                          struct lca_octet_buffer key,
                          uint8_t key_slot);

/* I2C Functions */

/**
 * Open the I2C bus
 *
 * @param bus The desired I2C bus.
 *
 * @return An open file descriptor or the program will exit.
 */
int
lca_setup (const char* bus);

void
lca_acquire_bus (int fd, int addr);

bool
lca_wakeup (int fd);

int
lca_sleep_device (int fd);

ssize_t
lca_write(int fd, const unsigned char *buf, unsigned int len);

ssize_t
lca_read(int fd, unsigned char *buf, unsigned int len);

/**
 * Idle the device. It will only respond to a wakeup after
 * this. However, internal volatile memory is preserved. Returns true
 * if successful.
 *
 * @param fd The open file descriptor
 */
bool
lca_idle(int fd);

/**
 * Sets up the device for communication.
 *
 * @param bus The I2C bus.
 * @param addr The address of the device
 *
 * @return An open file descriptor or -1 on error
 */
int
lca_atmel_setup(const char *bus, unsigned int addr);

/**
 * Sleeps the device and closes the file descriptor.
 *
 * @param fd The open file descriptor
 *
 */
void
lca_atmel_teardown(int fd);

ssize_t
lca_read_sleep(int fd,
                unsigned char *buf,
                unsigned int len,
                struct timespec wait_time);

/* ECDSA Functions */

bool
lca_ecdsa_p256_verify (struct lca_octet_buffer pub_key,
                        struct lca_octet_buffer signature,
                        struct lca_octet_buffer sha256_digest);

/**
 * Adds the uncompressed point format tag (0x04) to the Public Key
 *
 * @param q The 64 byte P-256 public key
 *
 * @return A new malloc'd buffer with 65 bytes, starting with
 * 0x04. The original buffer will be free'd
 */
struct lca_octet_buffer
lca_add_uncompressed_point_tag (struct lca_octet_buffer q);

/**
 * Prints out the sexp to the logging facility.
 *
 * @param to_print The sexp to print.
 */
void
lca_print_sexp (gcry_sexp_t to_print);

/**
 * Creates an ECDSA P256 Key pair in software.
 *
 * @param key Pointer to key storage
 *
 * @return libgcrypt result code
 */
int
lca_gen_soft_keypair (gcry_sexp_t *key);

int
lca_soft_sign (gcry_sexp_t *key_pair, struct lca_octet_buffer hash,
               gcry_sexp_t  *sig_out);

/**
 * Load an ECDSA private key from a file.
 *
 * @param keyfile The file to load.
 * @param key The gcrypt key struct to fill in
 *
 * @return 0 on success
 */
int
lca_load_signing_key (const char *keyfile, gcry_sexp_t *key);

int
lca_ssig2buffer (const gcry_sexp_t *sig, struct lca_octet_buffer *r_out,
                 struct lca_octet_buffer *s_out);

struct lca_octet_buffer
lca_sig2buf (const gcry_sexp_t *sig);

/* ATECCX08 Commands */

/**
 * Generates a private or public key in the specified slot. If private
* is true, it will generate a new private key. If false, it will
 * return the *public* key from the *existing* private key in that slot.
 *
 * @param fd The open file descriptor.
 * @param key_id The key ID on which to operate.
 * @param private True if a new private key is desired, otherwise false.
 *
 * @return In either case, this will return the *public* key of the
 * specified key slot. The caller should check if the pointer is null,
 * which signifies an error.
 */
struct lca_octet_buffer
lca_gen_ecc_key (int fd,
                      uint8_t key_id,
                      bool private);

/**
 * Performs an ECC signature over the data loaded in tempkey
 * register. You must run the load nonce command first to populate
 * this register.
 *
 * @param fd The open file descriptor.
 * @param key_id The key ID for the key you want to use.
 *
 * @return The signature as one buffer: R + S.
 */
struct lca_octet_buffer
lca_ecc_sign (int fd,
                   uint8_t key_id);

/**
 * Verifies an ECDSA Signature. Requires that the data, which was
 * signed, was first loaded with the nonce command.
 *
 * @param fd The open file descriptor.
 * @param pub_key The Public Key matching the private key that signed
 * the data.
 * @param signature The resultant signature.
 *
 * @return True if the signature is valid otherwise false
 */
bool
lca_ecc_verify (int fd,
                     struct lca_octet_buffer pub_key,
                     struct lca_octet_buffer signature);

/**
 * Compute the master secret from ECDH between the passed in public
 * key and the key stored in slot @slot.
 *
 * @param fd The open fd for the device.
 * @param slot The slot which should contain an ECDSA Private Key.
 * @param x The x component of the corresponding key to do the exchange.
 * @param y Like param x, but the y component.
 *
 * @return The buffer containing the master secret which will be 32
 * bytes or the buffer will indicate 0 bytes on failure.
 */
struct lca_octet_buffer
lca_ecdh (int fd, uint8_t slot,
          struct lca_octet_buffer x, struct lca_octet_buffer y);

/* ATSHA204 Commands */

enum DATA_ZONE
  {
    CONFIG_ZONE = 0,
    OTP_ZONE = 1,
    DATA_ZONE = 2
  };

/* Random Commands */

struct Command_ATSHA204
lca_build_random_cmd (bool update_seed);

/**
 * Get 32 bytes of random data from the device
 *
 * @param fd The open file descriptor
 * @param update_seed True updates the seed.  Do this sparingly.
 *
 * @return A malloc'ed buffer with random data.
 */
struct lca_octet_buffer
lca_get_random (int fd, bool update_seed);


/**
 * Builds the command structure for a read4 command.
 *
 * @param zone The zone from which to read.
 * @param addr The desired read address.
 *
 * @return The populated command structure.
 */
struct Command_ATSHA204
lca_build_read4_cmd (enum DATA_ZONE zone, uint8_t addr);

/**
 * Builds the command structure for the write 4 command.
 *
 * @param zone The zone to which to write.
 * @param addr The address to which to write.
 * @param buf The 4 byte buffer, which will be written.
 *
 * @return The populated command struct.
 */
struct Command_ATSHA204
lca_build_write4_cmd (enum DATA_ZONE zone, uint8_t addr, uint32_t buf);

/**
 * Builds the command structure for the write 32 command.
 *
 * @param zone The zone to which to write.
 * @param addr The address to which to write.
 * @param buf The data to write.
 * @param mac An optional mac.
 *
 * @return The populated structure.
 */
struct Command_ATSHA204
lca_build_write32_cmd (const enum DATA_ZONE zone,
                        const uint8_t addr,
                        const struct lca_octet_buffer buf,
                        const struct lca_octet_buffer *mac);

/**
 * Write 32 bytes to the device.
 *
 * @param fd The open file descriptor.
 * @param addr The address to write to.
 * @param buf The buffer to write, passed by value.  Buf.ptr should be
 * a valid pointer to the data and buf.len must be 32.
 * @param mac An optional mac for encrypted writes.
 *
 * @return True if successful.
 */
bool
lca_write32_cmd (const int fd,
                  const enum DATA_ZONE zone,
                  const uint8_t addr,
                  const struct lca_octet_buffer buf,
                  const struct lca_octet_buffer *mac);

/**
 *
 *
 * @param fd The open file descriptor
 *
 * @return True if the configuration zone is locked
 */
bool
lca_is_config_locked (int fd);

/**
 *
 *
 * @param fd The open file descriptor
 *
 * @return True if the data zone is locked
 */
bool
lca_is_data_locked (int fd);

/**
 * Returns the entire configuration zone.
 *
 * @param fd The open file descriptor
 *
 * @return A malloc'ed buffer containing the entire configuration
 * zone.
 */
struct lca_octet_buffer
get_config_zone (int fd);

/**
 * Returns the entire OTP zone.
 *
 * @param fd The open file descriptor.
 *
 * @return A malloc'ed buffer containing the entire OTP zone.
 */
struct lca_octet_buffer
get_otp_zone (int fd);

/**
 * Builds the command structure for a read 32 command.
 *
 * @param zone The zone from which to read.
 * @param addr The address from which to read.
 *
 * @return The populated command structure.
 */
struct Command_ATSHA204
lca_build_read32_cmd (enum DATA_ZONE zone, uint8_t addr);

enum DEVICE_STATE
  {
    STATE_FACTORY = 0,            /**< Config zone, data and OTP zones
                                     are unlocked */
    STATE_INITIALIZED,            /**< Config zone locked, data and OTP
                                     zones are unlockded */
    STATE_PERSONALIZED            /**< Config, data, and OTP zones are locked */
  };

/**
 * Returns the logical state of the device based on the config, data,
 * and OTP zones
 *
 * @param fd The open file descriptor
 *
 * @return The devie state
 */
enum DEVICE_STATE
lca_get_device_state (int fd);

/**
 * Returns a status if the specified zone is locked or not.
 *
 * @param fd The open file descriptor.
 * @param zone The zone to test.
 *
 * @return True if locked.
 */
bool
lca_is_locked (int fd, enum DATA_ZONE zone);

/**
 * Returns true if the configuration zone is locked.
 *
 * @param fd The open file descriptor.
 *
 * @return true or false.
 */
bool
lca_is_config_locked (int fd);

/**
 * Returns true if the data section is locked.
 *
 * @param fd The open file descriptor.
 *
 * @return True if locked.
 */
bool
lca_is_data_locked (int fd);

/* Command Utilities */
/**
 * Print the command structure to the debug log source.
 *
 * @param c The command to be sent.
 */
void
lca_print_command (struct Command_ATSHA204 *c);

void
LCA_LOG(enum LCA_LOG_LEVEL lvl, const char *format, ...);

void
lca_set_log_level(enum LCA_LOG_LEVEL lvl);

bool
lca_is_debug (void);


void
lca_print_hex_string (const char *str, const uint8_t *hex, unsigned int len);

/**
 * Returns the status, as an enumeration, from the response buffer
 *
 * @param rsp The full response buffer
 *
 * @return The converted enumeration
 */
enum LCA_STATUS_RESPONSE
lca_get_status_response(const uint8_t *rsp);

/* Configuration Zone Functions */
int
lca_config2bin(const char *docname, struct lca_octet_buffer *out);

int
lca_burn_config_zone (int fd, struct lca_octet_buffer cz);

int
lca_lock_config_zone (int fd, const struct lca_octet_buffer template);


/* OTP zone functions */
struct lca_octet_buffer
lca_build_otp_zone (void);

int
lca_burn_otp_zone (int fd, struct lca_octet_buffer otp_zone);

int
personalize (int fd, const char *config_file);

/* hkdf functions */

int
lca_hkdf_256_extract( const uint8_t *salt, int salt_len,
                      const uint8_t *ikm, int ikm_len,
                      uint8_t prk[LCA_SHA256_DLEN]);


int
lca_hkdf_256_expand(const uint8_t prk[ ], int prk_len,
                    const unsigned char *info, int info_len,
                    uint8_t okm[ ], int okm_len);

/*
 *  hkdf
 *
 *  Description:
 *      This function will generate keying material using HKDF-256.
 *
 *  Parameters:
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm[ ]: [in]
 *          Input keying material.
 *      ikm_len: [in]
 *          The length of the input keying material.
 *      info[ ]: [in]
 *          The optional context and application specific information.
 *          If info == NULL or a zero-length string, it is ignored.
 *      info_len: [in]
 *          The length of the optional context and application specific
 *          information.  (Ignored if info == NULL.)
 *      okm[ ]: [out]
 *          Where the HKDF is to be stored.
 *      okm_len: [in]
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * USHABlockSize(whichSha)
 *
 *  Notes:
 *      Calls hkdf_extract() and hkdf_expand().
 *
 *  Returns:
 *      sha 0 on success otherwise non-zero
 *
 */
int
lca_hkdf(const unsigned char *salt, int salt_len,
         const unsigned char *ikm, int ikm_len,
         const unsigned char *info, int info_len,
         uint8_t okm[ ], int okm_len);

#endif // LIBCRYPTOAUTH_H_
