/*
  xdrv_98_5_espnow_ota_receiver.ino - ESP-NOW OTA receiver for the safeboot image

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

#ifdef ESP32
#ifdef USE_ESPNOW_OTA_RECEIVER
/*********************************************************************************************\
 * A device in its safeboot image takes a new firmware from a neighbour over ESP-NOW, for the device that has no route
 * to an HTTP server: the neighbour fetches the image and hands it over, one hop.
 *
 * The image goes as blocks of 64 KB (the last one shorter), each compressed on its own as a raw deflate stream, so that
 * the device decompresses a block with the inflater in the chip's ROM and writes it to the app partition as soon as it is
 * whole. The block written last is kept in NVS: a device that loses power in the middle starts again from the block after
 * it, and a neighbour that stops sending can be replaced by another one. Before the device boots the new image, it reads it
 * back from flash and checks its SHA-256 against the manifest, whose Ed25519 signature it checked before it took a block.
 *
 * Every frame carries a tag, the first 8 bytes of an HMAC-SHA256 under a key derived from the network key the ESP-NOW mesh
 * of the device keeps in NVS: only a device of the same network can drive the transfer. The image itself is trusted only
 * for its signature, under one of the public keys the build carries (ESPNOW_OTA_PUBLIC_KEYS, 32 bytes each, as one
 * string); a build without them refuses every offer.
 *
 * The frames are espnow_ota.h's, which the sender (xdrv_98_7) speaks too.
 *
 * The same image comes over HTTP too, for a device that reaches the server of its releases: the application leaves the
 * release's address in NVS (the key "url", http://host:port/folder, the folder the release tool packs), and this image
 * fetches the folder's manifest.json, takes its offer as one from a neighbour (the signature checked before a block is
 * taken), and fetches each block from blocks.bin, a part at a time with a Range, into the same blocks a neighbour's pieces
 * make. The station is not parked while the WiFi comes up for it; a release that cannot be fetched ESPNOW_OTA_HTTP_TRIES times
 * in a row, or a WiFi that does not come up in ESPNOW_OTA_GRACE_S, leaves the image to the mesh, as above.
 *
 * A station looking for a network out of reach scans every channel at each try, and the radio is off the mesh's channel
 * most of the time. The station is parked, its retries and Tasmota's off and the radio on the channel of the mesh's record,
 * when the image is to come over ESP-NOW and the station is not on that channel: the application asked for it before it
 * restarted into this image (the NVS key "armed"), or a transfer is under way. A device whose WiFi has not connected
 * ESPNOW_OTA_GRACE_S after its start parks it too, so that a neighbour can reach it. It stays parked until it restarts.
 * Tasmota's WiFi Manager has the radio while it runs (its access point is on a channel of its own): nothing is parked and
 * the channel is left alone.
 *
 * This image that restarts ESPNOW_OTA_BOOT_TRIES times in a row, each before ESPNOW_OTA_BOOT_OK_S, gives the device back to its
 * app when the app partition holds a whole image (the boot loader checks it): Tasmota counts no boot loop in a safeboot image, and
 * a fault here must not leave the device to a serial cable. The count lives in RTC memory, which a power cut clears.
 *
 * The buttons of a device of a network do nothing while it runs this image: they are taken before the default handling,
 * which would switch its relays.
\*********************************************************************************************/

#define XDRV_104                       104

#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <nvs.h>
#include "miniz.h"                           // tinfl, in the ROM
#include "include/ed25519.h"
#include "include/espnow_ota.h"

#define ESPNOW_OTA_RX_DEPTH            8
#define ESPNOW_OTA_BEACON_S            2
#define ESPNOW_OTA_GRACE_S             30         // a device whose WiFi has not connected by then parks it, for the mesh
#define ESPNOW_OTA_HTTP_CHUNK          8192       // the bytes of blocks.bin fetched at once over HTTP
#define ESPNOW_OTA_HTTP_TRIES          10         // fetches that fail in a row, after which the image is left to the mesh
#define ESPNOW_OTA_HTTP_AGAIN_MS       3000       // and the time between them
#define ESPNOW_OTA_BOOT_TRIES          3          // starts of this image in a row that end early, after which the app is booted
#define ESPNOW_OTA_BOOT_OK_S           30         // a start that lasts this long is not one of them
#define ESPNOW_OTA_BOOT_MAGIC          0x4F7A5BB0
#define ESPNOW_OTA_NVS                 "espnowota"
#define ESPNOW_OTA_MESH_NVS            "espnowmesh"  // the record of the ESP-NOW mesh: the device's number, the channel and the network key
#define ESPNOW_OTA_MESH_ID             5          // offsets in that record
#define ESPNOW_OTA_MESH_CHANNEL        6
#define ESPNOW_OTA_MESH_HAS_GROUP      13
#define ESPNOW_OTA_MESH_GROUP_KEY      48


typedef struct {
  uint8_t mac[6];
  uint8_t len;
  uint8_t data[ESPNOW_OTA_MAX_FRAME];
} EspNowOtaRx_t;

struct {
  QueueHandle_t rx = nullptr;
  const esp_partition_t *part = nullptr;
  br_hmac_key_context tag;
  uint8_t manifest[ESPNOW_OTA_OFFER_LEN];    // the offer taken, signature included
  uint8_t sender[6];                         // the neighbour sending, the only unicast peer
  uint8_t *in = nullptr;                     // the compressed block being received
  uint32_t length = 0;                       // its length
  uint32_t got = 0;                          // and the bytes of it received
  uint16_t block = 0;                        // the block being received
  uint8_t node = 0;
  uint8_t channel = 0;
  uint8_t state = kOtaIdle;
  bool radio = false;
  bool has_key = false;
  bool has_manifest = false;
  bool armed = false;                        // the application asked for the image over ESP-NOW
  bool parked = false;                       // the station, on the mesh's channel
  uint8_t sender_node = 0;                   // the sender's number in the network
  char sender_name[ESPNOW_OTA_NAME_MAX + 1] = "";
  uint32_t last_piece_ms = 0;                // when the last piece was taken
  uint32_t since_ms = 0;                     // when the sender offered, and the block it found: what the time left is reckoned from
  uint16_t since_block = 0;
  char url[ESPNOW_OTA_URL_MAX] = "";         // the release to fetch over HTTP, from the application; empty for the mesh only
  uint8_t http_fails = 0;                    // fetches that failed in a row
  uint32_t http_next_ms = 0;                 // when the next one goes, after one that failed
  uint32_t http_blocks = 0;                  // the release's blocks, from its manifest: 0 until it is read
  uint32_t http_length[ESPNOW_OTA_MAX_BLOCKS];
} EspNowOta;

/*********************************************************************************************/

static uint32_t EspNowOtaSize(void) { return EspNowOtaGet32(EspNowOta.manifest); }
static uint16_t EspNowOtaBlocks(void) { return EspNowOtaGet16(EspNowOta.manifest + 4); }
static uint32_t EspNowOtaBlockSize(void) { return EspNowOta.manifest[6] * 1024; }
static const uint8_t *EspNowOtaSha(void) { return EspNowOta.manifest + 7; }

static bool EspNowOtaSigned(const uint8_t *offer) {
  return EspNowOtaRecordSigned(offer, offer + ESPNOW_OTA_SIGNED_LEN);
}

/*********************************************************************************************/

// The device's number, the channel and the network key, from the record of the ESP-NOW mesh
static bool EspNowOtaReadNetwork(void) {
  nvs_handle_t handle;
  if (ESP_OK != nvs_open(ESPNOW_OTA_MESH_NVS, NVS_READONLY, &handle)) { return false; }
  uint8_t record[ESPNOW_OTA_MESH_GROUP_KEY + 32];
  size_t size = 0;
  bool ok = (ESP_OK == nvs_get_blob(handle, "settings", nullptr, &size)) && (size >= sizeof(record));
  if (ok) {
    uint8_t *copy = (uint8_t *)malloc(size);
    ok = copy && (ESP_OK == nvs_get_blob(handle, "settings", copy, &size));
    if (ok) { memcpy(record, copy, sizeof(record)); }
    if (copy) {
      memset(copy, 0, size);
      free(copy);
    }
  }
  nvs_close(handle);
  if (!ok || !record[ESPNOW_OTA_MESH_HAS_GROUP]) { return false; }
  EspNowOta.node = record[ESPNOW_OTA_MESH_ID];
  EspNowOta.channel = record[ESPNOW_OTA_MESH_CHANNEL];
  EspNowOtaTagKey(record + ESPNOW_OTA_MESH_GROUP_KEY, &EspNowOta.tag);
  memset(record, 0, sizeof(record));
  return true;
}

// The offer taken and the block written last survive a restart
static void EspNowOtaSaveProgress(void) {
  nvs_handle_t handle;
  if (ESP_OK != nvs_open(ESPNOW_OTA_NVS, NVS_READWRITE, &handle)) { return; }
  nvs_set_blob(handle, "manifest", EspNowOta.manifest, sizeof(EspNowOta.manifest));
  nvs_set_u16(handle, "block", EspNowOta.block);
  nvs_commit(handle);
  nvs_close(handle);
}

static void EspNowOtaLoadProgress(void) {
  nvs_handle_t handle;
  if (ESP_OK != nvs_open(ESPNOW_OTA_NVS, NVS_READONLY, &handle)) { return; }
  size_t size = sizeof(EspNowOta.manifest);
  uint16_t block = 0;
  if ((ESP_OK == nvs_get_blob(handle, "manifest", EspNowOta.manifest, &size)) && (size == sizeof(EspNowOta.manifest)) &&
      (ESP_OK == nvs_get_u16(handle, "block", &block)) && EspNowOtaSigned(EspNowOta.manifest)) {
    EspNowOta.has_manifest = true;
    EspNowOta.block = block;
    EspNowOta.state = kOtaReceiving;
  }
  uint8_t armed = 0;
  EspNowOta.armed = (ESP_OK == nvs_get_u8(handle, "armed", &armed)) && armed;
  size_t url_len = sizeof(EspNowOta.url);
  if ((ESP_OK != nvs_get_str(handle, "url", EspNowOta.url, &url_len)) || strncmp_P(EspNowOta.url, PSTR("http://"), 7)) { EspNowOta.url[0] = '\0'; }
  nvs_close(handle);
}

/*********************************************************************************************/

// Tasmota's retries are held while the station is parked (WifiCheckIp)
bool EspNowOtaWifiQuiet(void) {
  return EspNowOta.parked;
}

static bool EspNowOtaShouldPark(void) {
  if (Wifi.config_type) { return false; }    // the WiFi Manager's access point
  bool connected = (WL_CONNECTED == WiFi.status());
  if (EspNowOta.url[0]) {                    // the image over HTTP while the WiFi is up: the mesh when it does not come up
    return !connected && (TasmotaGlobal.uptime >= ESPNOW_OTA_GRACE_S);
  }
  if (EspNowOta.armed || EspNowOta.has_manifest) {
    return !connected || (EspNowOta.channel && (WiFi.channel() != EspNowOta.channel));
  }
  return !connected && (TasmotaGlobal.uptime >= ESPNOW_OTA_GRACE_S);
}

static void EspNowOtaPark(void) {
  WiFi.setAutoReconnect(false);
  WiFi.disconnect();                         // a connection under way is ended; the radio stays on
  EspNowOta.parked = true;
  AddLog(LOG_LEVEL_INFO, PSTR("EOT: WiFi parked on channel %u, for the mesh"), EspNowOta.channel);
}

static void EspNowOtaKeepChannel(void) {
  if (!EspNowOta.parked || !EspNowOta.channel || Wifi.config_type) { return; }
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&channel, &second);
  if (channel != EspNowOta.channel) { esp_wifi_set_channel(EspNowOta.channel, WIFI_SECOND_CHAN_NONE); }
}

/*********************************************************************************************/

static void EspNowOtaSend(const uint8_t *mac, uint8_t *frame, size_t len) {
  EspNowOtaTagOf(&EspNowOta.tag, frame, len, frame + len);
  esp_now_send(mac, frame, len + ESPNOW_OTA_TAG_LEN);
}

static void EspNowOtaSetSender(const uint8_t *mac) {
  if (0 == memcmp(EspNowOta.sender, mac, 6)) { return; }
  static const uint8_t none[6] = { 0 };
  if (memcmp(EspNowOta.sender, none, 6)) { esp_now_del_peer(EspNowOta.sender); }
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, mac, 6);
  peer.ifidx = WIFI_IF_STA;
  esp_now_add_peer(&peer);
  memcpy(EspNowOta.sender, mac, 6);
}

static void EspNowOtaAck(const uint8_t *mac) {
  uint8_t frame[ESPNOW_OTA_HEADER + ESPNOW_OTA_ACK_BODY + ESPNOW_OTA_TAG_LEN] = { ESPNOW_OTA_PROTOCOL, kOtaAck, EspNowOta.node };
  memcpy(frame + 3, EspNowOtaSha(), 4);
  EspNowOtaPut16(frame + 7, EspNowOta.block);
  EspNowOtaPut32(frame + 9, EspNowOta.got);
  frame[13] = EspNowOta.state;
  EspNowOtaSend(mac, frame, ESPNOW_OTA_HEADER + ESPNOW_OTA_ACK_BODY);
}

static void EspNowOtaBeacon(void) {
  static const uint8_t all[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  uint8_t frame[ESPNOW_OTA_HEADER + ESPNOW_OTA_BEACON_BODY + ESPNOW_OTA_TAG_LEN] = { ESPNOW_OTA_PROTOCOL, kOtaBeacon, EspNowOta.node, EspNowOta.state };
  if (EspNowOta.has_manifest) {
    memcpy(frame + 4, EspNowOtaSha(), 4);
    EspNowOtaPut16(frame + 8, EspNowOta.block);
    EspNowOtaPut16(frame + 10, EspNowOtaBlocks());
  }
  EspNowOtaSend(all, frame, ESPNOW_OTA_HEADER + ESPNOW_OTA_BEACON_BODY);
}

/*********************************************************************************************/

static void EspNowOtaFail(const char *why) {
  AddLog(LOG_LEVEL_ERROR, PSTR("EOT: %s"), why);
  free(EspNowOta.in);
  EspNowOta.in = nullptr;
  EspNowOta.got = 0;
  EspNowOta.state = kOtaFailed;
}

// The block is whole: inflated into RAM and written to the app partition
static bool EspNowOtaWriteBlock(void) {
  uint32_t at = EspNowOta.block * EspNowOtaBlockSize();
  uint32_t want = EspNowOtaSize() - at;
  if (want > EspNowOtaBlockSize()) { want = EspNowOtaBlockSize(); }
  uint8_t *out = (uint8_t *)malloc(want);
  tinfl_decompressor *inflater = (tinfl_decompressor *)malloc(sizeof(tinfl_decompressor));
  bool ok = out && inflater;
  if (ok) {
    tinfl_init(inflater);
    size_t in_len = EspNowOta.length;
    size_t out_len = want;
    tinfl_status status = tinfl_decompress(inflater, EspNowOta.in, &in_len, out, out, &out_len, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    ok = (TINFL_STATUS_DONE == status) && (out_len == want);
  }
  free(inflater);
  if (ok) {
    uint32_t erase = (want + SPI_FLASH_SEC_SIZE - 1) & ~(SPI_FLASH_SEC_SIZE - 1);
    ok = (ESP_OK == esp_partition_erase_range(EspNowOta.part, at, erase)) && (ESP_OK == esp_partition_write(EspNowOta.part, at, out, want));
  }
  free(out);
  return ok;
}

// Every block is written: the image is read back and checked before the device is set to boot it
static void EspNowOtaCheck(void) {
  EspNowOta.state = kOtaChecking;
  uint8_t *buffer = (uint8_t *)malloc(SPI_FLASH_SEC_SIZE);
  if (!buffer) { return EspNowOtaFail("no memory"); }
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  uint32_t size = EspNowOtaSize();
  bool ok = true;
  for (uint32_t at = 0; ok && (at < size); at += SPI_FLASH_SEC_SIZE) {
    uint32_t n = size - at;
    if (n > SPI_FLASH_SEC_SIZE) { n = SPI_FLASH_SEC_SIZE; }
    ok = (ESP_OK == esp_partition_read(EspNowOta.part, at, buffer, n));
    br_sha256_update(&ctx, buffer, n);
    if (0 == (at & 0xFFFF)) { yield(); }
  }
  free(buffer);
  uint8_t digest[32];
  br_sha256_out(&ctx, digest);
  if (!ok || memcmp(digest, EspNowOtaSha(), 32)) {
    EspNowOta.block = 0;                     // the image is received again from the start
    EspNowOtaSaveProgress();
    return EspNowOtaFail("image does not match its SHA-256");
  }
  if (ESP_OK != esp_ota_set_boot_partition(EspNowOta.part)) { return EspNowOtaFail("image refused by the boot loader"); }
  EspNowOta.state = kOtaDone;
  nvs_handle_t handle;
  if (ESP_OK == nvs_open(ESPNOW_OTA_NVS, NVS_READWRITE, &handle)) {
    nvs_erase_all(handle);
    nvs_commit(handle);
    nvs_close(handle);
  }
  AddLog(LOG_LEVEL_INFO, PSTR("EOT: Image of %u bytes written and checked, restarting"), size);
  TasmotaGlobal.restart_flag = 3;
}

// An offer taken, signed, from a neighbour or from the server: false when it is refused. The same image again keeps the blocks
// already written, and the block under way starts over
static bool EspNowOtaTake(const uint8_t *offer) {
  bool same = EspNowOta.has_manifest && (0 == memcmp(offer + 7, EspNowOtaSha(), 32));
  if (!same) {
    if (!EspNowOtaSigned(offer)) {
      AddLog(LOG_LEVEL_INFO, PSTR("EOT: Offer refused, its signature does not check"));
      return false;
    }
    uint32_t size = EspNowOtaGet32(offer);
    uint32_t block_size = offer[6] * 1024;
    if ((0 == block_size) || (offer[6] > ESPNOW_OTA_BLOCK_MAX_KB) || (size > EspNowOta.part->size) ||
        (EspNowOtaGet16(offer + 4) != (size + block_size - 1) / block_size)) {
      AddLog(LOG_LEVEL_INFO, PSTR("EOT: Offer refused, the image does not fit"));
      return false;
    }
    memcpy(EspNowOta.manifest, offer, sizeof(EspNowOta.manifest));
    EspNowOta.has_manifest = true;
    EspNowOta.block = 0;
    EspNowOtaSaveProgress();
    AddLog(LOG_LEVEL_INFO, PSTR("EOT: Taking an image of %u bytes in %u blocks"), size, EspNowOtaBlocks());
  }
  if (EspNowOta.state != kOtaDone) { EspNowOta.state = kOtaReceiving; }
  free(EspNowOta.in);
  EspNowOta.in = nullptr;
  EspNowOta.got = 0;
  EspNowOta.since_ms = millis();
  EspNowOta.since_block = EspNowOta.block;
  EspNowOta.last_piece_ms = EspNowOta.since_ms;
  return true;
}

static void EspNowOtaOffer(const uint8_t *mac, uint8_t node, const uint8_t *body, size_t len) {
  if (len < ESPNOW_OTA_OFFER_LEN) { return; }
  size_t name_len = (len > ESPNOW_OTA_OFFER_LEN) ? body[ESPNOW_OTA_OFFER_LEN] : 0;
  if ((name_len > ESPNOW_OTA_NAME_MAX) || (len != ESPNOW_OTA_OFFER_LEN + ((len > ESPNOW_OTA_OFFER_LEN) ? 1 + name_len : 0))) { return; }
  if (!EspNowOtaTake(body)) { return; }
  EspNowOta.sender_node = node;
  memcpy(EspNowOta.sender_name, body + ESPNOW_OTA_OFFER_LEN + 1, name_len);
  EspNowOta.sender_name[name_len] = '\0';
  EspNowOtaSetSender(mac);
  EspNowOtaAck(mac);
}

// The block is whole: written, and the next one wanted, or, after the last, the image checked
static void EspNowOtaBlockWhole(void) {
  bool ok = EspNowOtaWriteBlock();
  free(EspNowOta.in);
  EspNowOta.in = nullptr;
  EspNowOta.got = 0;
  if (!ok) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EOT: Block %u could not be written"), EspNowOta.block);
    return;
  }
  EspNowOta.block++;
  EspNowOtaSaveProgress();
  if (EspNowOta.block == EspNowOtaBlocks()) { EspNowOtaCheck(); }
}

static void EspNowOtaPiece(const uint8_t *mac, const uint8_t *body, size_t len) {
  if ((len <= ESPNOW_OTA_PIECE_HEADER) || !EspNowOta.has_manifest || memcmp(body, EspNowOtaSha(), 4)) { return; }
  EspNowOtaSetSender(mac);
  if (EspNowOta.state != kOtaReceiving) { return EspNowOtaAck(mac); }
  uint16_t block = EspNowOtaGet16(body + 4);
  uint32_t offset = EspNowOtaGet32(body + 6);
  uint32_t length = EspNowOtaGet32(body + 10);
  const uint8_t *data = body + ESPNOW_OTA_PIECE_HEADER;
  size_t n = len - ESPNOW_OTA_PIECE_HEADER;
  if ((block != EspNowOta.block) || (offset != EspNowOta.got) || (offset + n > length) ||
      (length > EspNowOtaBlockSize() + EspNowOtaBlockSize() / 8)) {
    return EspNowOtaAck(mac);                // says where it is, and the sender goes on from there
  }
  if (nullptr == EspNowOta.in) {
    EspNowOta.in = (uint8_t *)malloc(length);
    if (nullptr == EspNowOta.in) { return EspNowOtaFail("no memory"); }
    EspNowOta.length = length;
  } else if (length != EspNowOta.length) {
    return EspNowOtaAck(mac);
  }
  memcpy(EspNowOta.in + offset, data, n);
  EspNowOta.got += n;
  EspNowOta.last_piece_ms = millis();
  if (EspNowOta.got == EspNowOta.length) { EspNowOtaBlockWhole(); }
  EspNowOtaAck(mac);
}

/*********************************************************************************************/

// The release's manifest.json, over HTTP: its offer taken as a neighbour's is, and the length of each block kept. False when it
// could not be fetched or read; a release whose offer is refused is not fetched again
static bool EspNowOtaHttpManifest(void) {
  char url[ESPNOW_OTA_URL_MAX + 16];
  snprintf_P(url, sizeof(url), PSTR("%s/manifest.json"), EspNowOta.url);
  HTTPClient http;                           // the core's client, which this image's own OTA takes: the light one comes with TLS
  if (!http.begin(url)) { return false; }
  http.setConnectTimeout(ESPNOW_OTA_HTTP_MS);
  http.setTimeout(ESPNOW_OTA_HTTP_MS);
  int size = (200 == http.GET()) ? http.getSize() : 0;
  char *text = ((size > 0) && (size < ESPNOW_OTA_MANIFEST_MAX)) ? (char *)malloc(size + 1) : nullptr;
  bool ok = text && EspNowOtaHttpRead(http.getStreamPtr(), (uint8_t *)text, size);
  http.end();
  uint8_t offer[ESPNOW_OTA_OFFER_LEN];
  uint32_t blocks = 0;
  if (ok) {
    text[size] = '\0';
    ok = EspNowOtaManifestRead(text, offer, EspNowOta.http_length, ESPNOW_OTA_MAX_BLOCKS, &blocks);
  }
  free(text);
  if (!ok) { return false; }
  uint32_t block_size = offer[6] * 1024;
  for (uint32_t i = 0; i < blocks; i++) {
    if (EspNowOta.http_length[i] > block_size + block_size / 8) { ok = false; }
  }
  if (!ok || !EspNowOtaTake(offer)) {
    AddLog(LOG_LEVEL_INFO, PSTR("EOT: The release at %s is refused, the mesh may bring another"), EspNowOta.url);
    EspNowOta.url[0] = '\0';
    return true;
  }
  EspNowOta.http_blocks = blocks;
  EspNowOta.sender_node = 0;
  strlcpy(EspNowOta.sender_name, "the server", sizeof(EspNowOta.sender_name));
  AddLog(LOG_LEVEL_INFO, PSTR("EOT: Fetching the release at %s, from block %u"), EspNowOta.url, EspNowOta.block + 1);
  return true;
}

// The next part of the block under way, over HTTP, into the block as a neighbour's pieces go. False when it could not be fetched
static bool EspNowOtaHttpPart(void) {
  uint16_t block = EspNowOta.block;
  if (block >= EspNowOta.http_blocks) { return true; }
  uint32_t length = EspNowOta.http_length[block];
  uint32_t from = 0;
  for (uint32_t i = 0; i < block; i++) { from += EspNowOta.http_length[i]; }
  if ((nullptr != EspNowOta.in) && (length != EspNowOta.length)) {
    free(EspNowOta.in);
    EspNowOta.in = nullptr;
  }
  if (nullptr == EspNowOta.in) {
    EspNowOta.in = (uint8_t *)malloc(length);
    if (nullptr == EspNowOta.in) {
      EspNowOtaFail("no memory");
      return true;
    }
    EspNowOta.length = length;
    EspNowOta.got = 0;
  }
  uint32_t at = from + EspNowOta.got;
  uint32_t n = length - EspNowOta.got;
  if (n > ESPNOW_OTA_HTTP_CHUNK) { n = ESPNOW_OTA_HTTP_CHUNK; }
  char url[ESPNOW_OTA_URL_MAX + 12];
  snprintf_P(url, sizeof(url), PSTR("%s/blocks.bin"), EspNowOta.url);
  char range[40];
  snprintf_P(range, sizeof(range), PSTR("bytes=%u-%u"), at, at + n - 1);
  HTTPClient http;
  bool ok = http.begin(url);
  if (ok) {
    http.setConnectTimeout(ESPNOW_OTA_HTTP_MS);
    http.setTimeout(ESPNOW_OTA_HTTP_MS);
    http.addHeader(F("Range"), range);
    int code = http.GET();
    ok = ((206 == code) || ((200 == code) && (0 == at))) && EspNowOtaHttpRead(http.getStreamPtr(), EspNowOta.in + EspNowOta.got, n);
    http.end();
  }
  if (!ok) { return false; }
  EspNowOta.got += n;
  EspNowOta.last_piece_ms = millis();
  if (EspNowOta.got == EspNowOta.length) { EspNowOtaBlockWhole(); }
  return true;
}

// The image over HTTP, a request at a time, while the WiFi is up and the station is not parked: the manifest, then the blocks
static void EspNowOtaHttpStep(void) {
  if (!EspNowOta.url[0] || EspNowOta.parked || !EspNowOta.part || (WL_CONNECTED != WiFi.status())) { return; }
  if ((kOtaChecking == EspNowOta.state) || (kOtaDone == EspNowOta.state)) { return; }
  if (kOtaFailed == EspNowOta.state) {
    AddLog(LOG_LEVEL_INFO, PSTR("EOT: The release at %s failed, the mesh may bring it"), EspNowOta.url);
    EspNowOta.url[0] = '\0';
    return;
  }
  if ((int32_t)(millis() - EspNowOta.http_next_ms) < 0) { return; }
  if (EspNowOta.http_blocks ? EspNowOtaHttpPart() : EspNowOtaHttpManifest()) {
    EspNowOta.http_fails = 0;
    return;
  }
  EspNowOta.http_next_ms = millis() + ESPNOW_OTA_HTTP_AGAIN_MS;
  if (++EspNowOta.http_fails >= ESPNOW_OTA_HTTP_TRIES) {
    AddLog(LOG_LEVEL_INFO, PSTR("EOT: The release at %s could not be fetched, the mesh may bring it"), EspNowOta.url);
    EspNowOta.url[0] = '\0';
  }
}

static void EspNowOtaHandle(const EspNowOtaRx_t &rx);
static void EspNowOtaHandle(const EspNowOtaRx_t &rx) {
  if (!EspNowOtaTagged(&EspNowOta.tag, rx.data, rx.len)) { return; }
  size_t len = rx.len - ESPNOW_OTA_TAG_LEN;
  const uint8_t *body = rx.data + ESPNOW_OTA_HEADER;
  len -= ESPNOW_OTA_HEADER;
  switch (rx.data[1]) {
    case kOtaOffer: EspNowOtaOffer(rx.mac, rx.data[2], body, len); break;
    case kOtaPiece: EspNowOtaPiece(rx.mac, body, len); break;
  }
}

/*********************************************************************************************/

// On the WiFi task: the frame is only copied
static void EspNowOtaRecvCb(const esp_now_recv_info_t *info, const uint8_t *data, int len);
static void EspNowOtaRecvCb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if ((len < 1) || (len > ESPNOW_OTA_MAX_FRAME) || (data[0] != ESPNOW_OTA_PROTOCOL) || !EspNowOta.rx) { return; }
  EspNowOtaRx_t rx;
  memcpy(rx.mac, info->src_addr, 6);
  rx.len = len;
  memcpy(rx.data, data, len);
  xQueueSend(EspNowOta.rx, &rx, 0);
}

static void EspNowOtaRadioStart(void) {
  if (EspNowOta.radio || !EspNowOta.has_key || !(WiFi.getMode() & WIFI_MODE_STA)) { return; }
  if (EspNowOta.channel && !Wifi.config_type) { esp_wifi_set_channel(EspNowOta.channel, WIFI_SECOND_CHAN_NONE); }
  if (ESP_OK != esp_now_init()) { return; }
  if (nullptr == EspNowOta.rx) { EspNowOta.rx = xQueueCreate(ESPNOW_OTA_RX_DEPTH, sizeof(EspNowOtaRx_t)); }
  esp_now_register_recv_cb(EspNowOtaRecvCb);
  esp_now_peer_info_t peer = {};
  memset(peer.peer_addr, 0xFF, 6);
  peer.ifidx = WIFI_IF_STA;
  esp_now_add_peer(&peer);
  EspNowOta.radio = true;
  AddLog(LOG_LEVEL_INFO, PSTR("EOT: Listening as node %u on channel %u"), EspNowOta.node, EspNowOta.channel);
}

static void EspNowOtaInit(void) {
  EspNowOta.part = esp_ota_get_next_update_partition(nullptr);
  if (nullptr == EspNowOta.part) { return; }
  EspNowOta.has_key = EspNowOtaReadNetwork();
  EspNowOtaLoadProgress();                   // an image under way, from a neighbour or from the server
}

static void EspNowOtaLoop(void) {
  EspNowOtaHttpStep();
  if (!EspNowOta.radio) { return; }
  EspNowOtaRx_t rx;
  while (xQueueReceive(EspNowOta.rx, &rx, 0)) { EspNowOtaHandle(rx); }
}

// The starts of this image that did not last, kept across a restart and lost with the power
RTC_NOINIT_ATTR static uint32_t EspNowOtaBootMagic;
RTC_NOINIT_ATTR static uint32_t EspNowOtaBoots;

static void EspNowOtaBootGuard(void) {
  if (ESPNOW_OTA_BOOT_MAGIC != EspNowOtaBootMagic) {
    EspNowOtaBootMagic = ESPNOW_OTA_BOOT_MAGIC;
    EspNowOtaBoots = 0;
  }
  EspNowOtaBoots++;
  if (EspNowOtaBoots < ESPNOW_OTA_BOOT_TRIES) { return; }
  EspNowOtaBoots = 0;
  const esp_partition_t *app = esp_ota_get_next_update_partition(nullptr);
  if (app && (ESP_OK == esp_ota_set_boot_partition(app))) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EOT: This image restarted %u times in a row, the app is booted"), ESPNOW_OTA_BOOT_TRIES);
    EspRestart();
  }
}

static void EspNowOtaEverySecond(void) {
  if (ESPNOW_OTA_BOOT_OK_S == TasmotaGlobal.uptime) { EspNowOtaBoots = 0; }
  if (EspNowOta.has_key && !EspNowOta.parked && (WiFi.getMode() & WIFI_MODE_STA) && EspNowOtaShouldPark()) { EspNowOtaPark(); }
  EspNowOtaKeepChannel();
  EspNowOtaRadioStart();
  if (EspNowOta.radio && (0 == (TasmotaGlobal.uptime % ESPNOW_OTA_BEACON_S))) { EspNowOtaBeacon(); }
}

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv104(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_LOOP:
      EspNowOtaLoop();
      break;
    case FUNC_EVERY_SECOND:
      EspNowOtaEverySecond();
      break;
    case FUNC_PRE_INIT:
      EspNowOtaBootGuard();
      break;
    case FUNC_INIT:
      EspNowOtaInit();
      break;
    case FUNC_BUTTON_PRESSED:
    case FUNC_BUTTON_MULTI_PRESSED:
      result = EspNowOta.has_key;            // a device of a network takes no action from its buttons here: its relays stay as they are
      break;
    case FUNC_ACTIVE:
      result = true;
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_OTA_RECEIVER
#endif  // ESP32
