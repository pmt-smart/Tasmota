/*
  espnow_ota.h - ESP-NOW OTA: the frames a device in its safeboot image and the neighbour that sends it an image exchange

  Copyright (C) 2026  Casa Inteligente

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ESPNOW_OTA_H_
#define _ESPNOW_OTA_H_

/*********************************************************************************************\
 * What the receiver (xdrv_98_5, in the safeboot image) and the sender (xdrv_98_7, in the app) both say, so that neither has
 * a copy of it to keep in step. Every frame is
 *   protocol(1) kind(1) sender's number in the network(1) body tag(8)
 * the tag the first 8 bytes of an HMAC-SHA256 of everything before it, under a key derived by HKDF-SHA256 from the network
 * key of the ESP-NOW mesh (salt "espnow-ota", info "tag"). The bodies:
 *   beacon  receiver to all, every 2 s   state(1) image(4) block(2) blocks(2)
 *   offer   sender to receiver           size(4) blocks(2) block_kb(1) sha256(32) signature(64), then, unsigned, the
 *                                        sender's name for a display: length(1) name(up to ESPNOW_OTA_NAME_MAX)
 *   piece   sender to receiver           image(4) block(2) offset(4) length(4) data
 *   ack     receiver to sender           image(4) block(2) offset(4) state(1): the block and the byte it wants next
 * The image is the first 4 bytes of its SHA-256, and the signature (Ed25519) covers the 39 bytes of the offer before it.
\*********************************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include <t_bearssl.h>

#define ESPNOW_OTA_PROTOCOL            0x4F       // the first byte: above the types of the other ESP-NOW protocols on the radio
#define ESPNOW_OTA_TAG_LEN             8
#define ESPNOW_OTA_MAX_FRAME           250
#define ESPNOW_OTA_HEADER              3          // protocol, kind, sender
#define ESPNOW_OTA_BEACON_BODY         9
#define ESPNOW_OTA_ACK_BODY            11
#define ESPNOW_OTA_PIECE_HEADER        14         // image, block, offset, length
#define ESPNOW_OTA_PIECE_DATA          (ESPNOW_OTA_MAX_FRAME - ESPNOW_OTA_HEADER - ESPNOW_OTA_PIECE_HEADER - ESPNOW_OTA_TAG_LEN)
#define ESPNOW_OTA_OFFER_LEN           103
#define ESPNOW_OTA_SIGNED_LEN          39
#define ESPNOW_OTA_NAME_MAX            20         // the sender's name after an offer
#define ESPNOW_OTA_BLOCK_MAX_KB        64

enum EspNowOtaKind : uint8_t { kOtaBeacon = 0, kOtaOffer = 1, kOtaPiece = 2, kOtaAck = 3 };
enum EspNowOtaState : uint8_t { kOtaIdle = 0, kOtaReceiving = 1, kOtaChecking = 2, kOtaDone = 3, kOtaFailed = 4 };

static inline uint32_t EspNowOtaGet32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint16_t EspNowOtaGet16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static inline void EspNowOtaPut32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static inline void EspNowOtaPut16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }

// The key of the frames' tags, from the network key of the mesh
static inline void EspNowOtaTagKey(const uint8_t group_key[32], br_hmac_key_context *out) {
  uint8_t key[32];
  br_hkdf_context hc;
  br_hkdf_init(&hc, &br_sha256_vtable, "espnow-ota", 10);
  br_hkdf_inject(&hc, group_key, 32);
  br_hkdf_flip(&hc);
  br_hkdf_produce(&hc, "tag", 3, key, sizeof(key));
  br_hmac_key_init(out, &br_sha256_vtable, key, sizeof(key));
  volatile uint8_t *wipe = key;
  for (size_t i = 0; i < sizeof(key); i++) { wipe[i] = 0; }
}

// The tag of a frame's first `len` bytes
static inline void EspNowOtaTagOf(const br_hmac_key_context *key, const uint8_t *frame, size_t len, uint8_t out[ESPNOW_OTA_TAG_LEN]) {
  br_hmac_context hc;
  br_hmac_init(&hc, key, ESPNOW_OTA_TAG_LEN);
  br_hmac_update(&hc, frame, len);
  br_hmac_out(&hc, out);
}

// Whether a frame heard is one of these, with its tag right: what it says is `len` - ESPNOW_OTA_TAG_LEN bytes
static inline bool EspNowOtaTagged(const br_hmac_key_context *key, const uint8_t *frame, size_t len) {
  if ((len < ESPNOW_OTA_HEADER + ESPNOW_OTA_TAG_LEN) || (len > ESPNOW_OTA_MAX_FRAME) || (ESPNOW_OTA_PROTOCOL != frame[0])) { return false; }
  uint8_t tag[ESPNOW_OTA_TAG_LEN];
  EspNowOtaTagOf(key, frame, len - ESPNOW_OTA_TAG_LEN, tag);
  uint8_t diff = 0;
  for (size_t i = 0; i < ESPNOW_OTA_TAG_LEN; i++) { diff |= tag[i] ^ frame[len - ESPNOW_OTA_TAG_LEN + i]; }
  return (0 == diff);
}

#endif  // _ESPNOW_OTA_H_
