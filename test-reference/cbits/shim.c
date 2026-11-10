/* The reference implementation's steps (libopaque, scripts/reference.sh)
 * with the random values each step draws given by the caller.
 *
 * libopaque and liboprf take their random values from two functions of
 * libsodium: `randombytes` and `crypto_core_ristretto255_scalar_random`.
 * This package's own steps can be run with their random values given
 * (`Crypto.OPAQUE.Internal`'s functions that end in `With`). To compare
 * the two byte for byte, both must use the same values. So
 * scripts/reference.sh compiles the two libraries with those two names
 * replaced by the two functions defined here. Normally they call
 * libsodium's own. During one call of a step below they hand out the
 * caller's bytes instead, in order: the script.
 *
 * Only what the two libraries draw themselves goes through here. What
 * libsodium draws inside its own functions does not (its Argon2id draws 64
 * bytes that never reach its output), so the script does not depend on
 * libsodium's version.
 *
 * A step fails when its script does not fit: -100 when the step asked for
 * more bytes than the script has, -101 when bytes are left over. Either
 * means that libopaque does not draw what the test thinks it draws, so the
 * comparison would be of different inputs. A script of no bytes
 * (`bytes == NULL`) leaves the step libsodium's own random values, for the
 * tests that run the two against each other with real randomness.
 *
 * A scripted scalar is given as it is: the test scripts canonical, nonzero
 * scalars, which is what libsodium's function gives.
 *
 * Not thread safe: the script is global. The tests call it from one thread.
 */
#include <stdint.h>
#include <string.h>

#include <sodium.h>

#include <opaque.h>

static const uint8_t *script = NULL;
static size_t script_len = 0;
static size_t script_at = 0;
static int script_armed = 0;
static int script_short = 0;

/* The next bytes of the script, or zeros past its end, which fails the
 * step. */
static void scripted(void *const buf, const size_t size) {
  if (script_len - script_at < size) {
    script_short = 1;
    memset(buf, 0, size);
    return;
  }
  memcpy(buf, script + script_at, size);
  script_at += size;
}

/* What libopaque calls where its source says `randombytes`. */
void opaque_reference_randombytes(unsigned char *const buf, const unsigned long long size) {
  if (script_armed) {
    scripted(buf, (size_t)size);
  } else {
    randombytes(buf, size);
  }
}

/* What liboprf calls where its source says
 * `crypto_core_ristretto255_scalar_random`. */
void opaque_reference_scalar_random(unsigned char *r) {
  if (script_armed) {
    scripted(r, crypto_core_ristretto255_SCALARBYTES);
  } else {
    crypto_core_ristretto255_scalar_random(r);
  }
}

/* Start libsodium. Once, before any step. */
int ref_install(void) { return sodium_init() < 0 ? -1 : 0; }

static void arm(const uint8_t *bytes, size_t len) {
  if (bytes == NULL) {
    return;
  }
  script = bytes;
  script_len = len;
  script_at = 0;
  script_short = 0;
  script_armed = 1;
}

/* The step's result: its own failure first, then a script that did not fit. */
static int disarm(int result) {
  if (!script_armed) {
    return result;
  }
  script_armed = 0;
  int left = script_at != script_len;
  script = NULL;
  if (result != 0) {
    return result;
  }
  if (script_short) {
    return -100;
  }
  return left ? -101 : 0;
}

static Opaque_Ids ids_of(const uint8_t *client, uint16_t client_len, const uint8_t *server, uint16_t server_len) {
  /* libopaque takes an identity of no bytes as none: the party's public key. */
  Opaque_Ids ids = {client_len, (uint8_t *)client, server_len, (uint8_t *)server};
  return ids;
}

/* The lengths of libopaque's buffers, for a password of this length. */
size_t ref_registration_secret_len(uint16_t password_len) { return OPAQUE_REGISTER_USER_SEC_LEN + (size_t)password_len; }
size_t ref_login_secret_len(uint16_t password_len) { return OPAQUE_USER_SESSION_SECRET_LEN + (size_t)password_len; }
size_t ref_server_secret_len(void) { return OPAQUE_REGISTER_SECRET_LEN; }
size_t ref_registration_response_len(void) { return OPAQUE_REGISTER_PUBLIC_LEN; }
size_t ref_registration_record_len(void) { return OPAQUE_REGISTRATION_RECORD_LEN; }
size_t ref_user_record_len(void) { return OPAQUE_USER_RECORD_LEN; }
size_t ref_ke1_len(void) { return OPAQUE_USER_SESSION_PUBLIC_LEN; }
size_t ref_ke2_len(void) { return OPAQUE_SERVER_SESSION_LEN; }

/* The client's registration request. Draws the blind. */
int ref_registration_request(const uint8_t *bytes, size_t len,
                             const uint8_t *password, uint16_t password_len,
                             uint8_t *secret, uint8_t *request) {
  arm(bytes, len);
  return disarm(opaque_CreateRegistrationRequest(password, password_len, secret, request));
}

/* The server's registration response, with its private key given. Draws
 * the client's OPRF key. */
int ref_registration_response(const uint8_t *bytes, size_t len,
                              const uint8_t *request, const uint8_t *server_private_key,
                              uint8_t *server_secret, uint8_t *response) {
  arm(bytes, len);
  return disarm(opaque_CreateRegistrationResponse(request, server_private_key, server_secret, response));
}

/* The client's registration record and export key. Draws the envelope's
 * nonce. */
int ref_finalize_registration(const uint8_t *bytes, size_t len,
                              const uint8_t *secret, const uint8_t *response,
                              const uint8_t *client, uint16_t client_len,
                              const uint8_t *server, uint16_t server_len,
                              uint8_t *record, uint8_t *export_key) {
  Opaque_Ids ids = ids_of(client, client_len, server, server_len);
  arm(bytes, len);
  return disarm(opaque_FinalizeRequest(secret, response, &ids, record, export_key));
}

/* What the server stores: its secrets of the registration before the
 * client's record. Draws nothing. */
void ref_store_record(const uint8_t *server_secret, const uint8_t *record, uint8_t *user_record) {
  opaque_StoreUserRecord(server_secret, record, user_record);
}

/* The client's first login message. Draws the blind, the seed of its key
 * share and its nonce, in that order. */
int ref_client_start(const uint8_t *bytes, size_t len,
                     const uint8_t *password, uint16_t password_len,
                     uint8_t *secret, uint8_t *ke1) {
  arm(bytes, len);
  return disarm(opaque_CreateCredentialRequest(password, password_len, secret, ke1));
}

/* The server's login message, its session key and the MAC it expects from
 * the client. Draws the masking nonce, its nonce and the seed of its key
 * share, in that order. */
int ref_server_respond(const uint8_t *bytes, size_t len,
                       const uint8_t *ke1, const uint8_t *user_record,
                       const uint8_t *client, uint16_t client_len,
                       const uint8_t *server, uint16_t server_len,
                       const uint8_t *context, uint16_t context_len,
                       uint8_t *ke2, uint8_t *session_key, uint8_t *expected_mac) {
  Opaque_Ids ids = ids_of(client, client_len, server, server_len);
  arm(bytes, len);
  return disarm(opaque_CreateCredentialResponse(ke1, user_record, &ids, context, context_len, ke2, session_key, expected_mac));
}

/* The client's last step: its session key, its MAC for the server (KE3)
 * and its export key. Draws nothing. */
int ref_client_finish(const uint8_t *ke2, const uint8_t *secret,
                      const uint8_t *client, uint16_t client_len,
                      const uint8_t *server, uint16_t server_len,
                      const uint8_t *context, uint16_t context_len,
                      uint8_t *session_key, uint8_t *mac, uint8_t *export_key) {
  Opaque_Ids ids = ids_of(client, client_len, server, server_len);
  return opaque_RecoverCredentials(ke2, secret, context, context_len, &ids, session_key, mac, export_key);
}

/* Whether the client's MAC is the one the server expects: 0 when it is. */
int ref_server_finish(const uint8_t *expected_mac, const uint8_t *mac) {
  return opaque_UserAuth(expected_mac, mac);
}
