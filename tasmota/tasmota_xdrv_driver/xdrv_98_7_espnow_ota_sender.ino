/*
  xdrv_98_7_espnow_ota_sender.ino - ESP-NOW OTA in the app: the neighbours in their safeboot image, and an image sent to one

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
#ifdef USE_ESPNOW_MESH
#ifdef USE_ESPNOW_OTA
/*********************************************************************************************\
 * The app's side of ESP-NOW OTA (espnow_ota.h), for a device of the ESP-NOW mesh: it hears the beacons of the neighbours that
 * run their safeboot image's receiver (xdrv_98_5) and says so to the rule engine; it sends one of them an image, which it
 * fetches over HTTP a few KB at a time; and it puts its own device into its safeboot image, to take an image that way.
 *
 * The image is a folder, as a release tool packs it: manifest.json, whose "offer" is the 103-byte signed offer in hex and
 * whose "blocks" are the length of each compressed block in blocks.bin, the other file, where they follow each other; the
 * manifest is compact JSON of 2 KB at most, which is what the JSON parser reads. The sender takes the
 * receiver's word for where it is at every ack, and sends the piece it asks for: one piece at a time, sent again when no ack
 * comes, the blocks fetched with a Range of ESPNOW_OTA_CHUNK bytes. The frames go on the mesh's radio, under its lock and with
 * its peers, and the sender takes the OTA frames the radio hears before the mesh does.
 *
 *   EspNowOtaArm                          restarts this device into its safeboot image, to take an image over ESP-NOW: the NVS key
 *                                         "armed" tells the receiver to keep the radio on the mesh's channel at once
 *   EspNowOtaNodes                        the neighbours heard in their safeboot image
 *   EspNowOtaSend <node> <url> [<name>]   sends neighbour <node>, heard in its safeboot image, the image at <url>; <name> is what
 *                                         its display says the image is from, this device's name when not given
 *   EspNowOtaSend                         what the send is doing
 *   EspNowOtaStop                         stops it
 *   EspNowOtaSafeboot <url>               writes the safeboot image at <url> (a .bin) into this device's safeboot partition: the image
 *                                         must be signed by one of the build's keys, in <url>.sig.json ("record" and "signature" in hex,
 *                                         a record of 0 blocks); it is fetched once to check it before anything is erased, then written,
 *                                         read back and checked by the boot loader. The app keeps running whatever happens; a write that
 *                                         went wrong says so, and the command is run again
 *
 * Reported to the rule engine:
 *   {"EspNowOta":{"Node":7,"State":1,"Image":"3a91f0c2","Block":2,"Blocks":31,"Rssi":-61}}  a neighbour in its safeboot image,
 *                                                                                           when what it says changes
 *   {"EspNowOta":{"Node":7,"Gone":1}}                      not heard for ESPNOW_OTA_GONE_S
 *   {"EspNowOtaSend":{"Node":7,"Result":"Done"}}           the end of a send: Done, Failed (the receiver says so), NoAnswer,
 *                                                          Fetch (the image could not be fetched, 5 times in a row) or Stopped
 *
 * The app that starts clears what the safeboot image kept of an image under way: a device that runs its app takes none.
\*********************************************************************************************/

#define XDRV_106                       106

#include "include/espnow_ota.h"
#include <esp_partition.h>
#include <esp_image_format.h>

#define ESPNOW_OTA_HEARD_MAX           8          // the neighbours in their safeboot image kept at once
#define ESPNOW_OTA_GONE_S              30
#define ESPNOW_OTA_SEND_BLOCKS         48         // the most blocks of an image: 3 MB in 64 KB
#define ESPNOW_OTA_CHUNK               2048       // the bytes of blocks.bin fetched at once
#define ESPNOW_OTA_ANSWER_MS           250        // a piece, or an offer, sent again when no ack came in this long
#define ESPNOW_OTA_TRIES               24         // and given up after as many, which outlasts a block's erase and write
#define ESPNOW_OTA_RX_QUEUE            8
#define ESPNOW_OTA_URL_MAX             120
#define ESPNOW_OTA_MANIFEST_MAX        2048       // the JSON parser keeps a token's place in 11 bits: 2 KB at most
#define ESPNOW_OTA_HTTP_MS             2000       // an HTTP request with nothing for this long fails: inside the loop's 5 s watchdog
#define ESPNOW_OTA_FETCH_TRIES         5          // the blocks not fetched this many times in a row end the send
#define ESPNOW_OTA_SAFEBOOT_CHUNK      4096
#define ESPNOW_OTA_SAFEBOOT_ERASE      0x10000    // the safeboot partition erased a 64 KB block at a time

enum EspNowOtaSendState : uint8_t { kOtaSendIdle = 0, kOtaSendOffer, kOtaSendPieces };

typedef struct {
  uint8_t mac[6];
  int8_t rssi;
  uint8_t len;
  uint8_t data[ESPNOW_OTA_MAX_FRAME];
} EspNowOtaHeardFrame_t;

typedef struct {
  uint8_t mac[6];
  uint8_t image[4];
  uint32_t heard_ms;
  uint16_t block;
  uint16_t blocks;
  uint8_t node;
  uint8_t state;
  int8_t rssi;
  bool used;
} EspNowOtaNeighbour_t;

struct {
  QueueHandle_t rx = nullptr;
  br_hmac_key_context tag;
  uint8_t group_version = 0;
  bool has_key = false;
  EspNowOtaNeighbour_t heard[ESPNOW_OTA_HEARD_MAX];
  // the send
  uint8_t send = kOtaSendIdle;
  uint8_t node = 0;
  uint8_t mac[6];
  char url[ESPNOW_OTA_URL_MAX];
  char name[ESPNOW_OTA_NAME_MAX + 1];
  uint8_t offer[ESPNOW_OTA_OFFER_LEN];
  uint16_t blocks = 0;
  uint32_t block_offset[ESPNOW_OTA_SEND_BLOCKS];
  uint32_t block_length[ESPNOW_OTA_SEND_BLOCKS];
  uint16_t at_block = 0;                     // where the receiver is, by its last ack
  uint32_t at_got = 0;
  uint8_t at_state = kOtaIdle;
  uint8_t *chunk = nullptr;                  // a part of blocks.bin
  uint32_t chunk_from = 0;
  uint32_t chunk_len = 0;
  uint32_t sent_ms = 0;
  uint8_t tries = 0;
  uint32_t pieces = 0;                       // sent, and sent again
  uint32_t again = 0;
  uint32_t fetches = 0;
  uint8_t fetch_fails = 0;                   // in a row
} EspNowOtaSender;

/*********************************************************************************************/

// The radio's callback, on the WiFi task, before the mesh: true when the frame is one of these, which is only copied
bool EspNowOtaHears(const uint8_t *mac, int8_t rssi, const uint8_t *data, int len) {
  if ((len < 1) || (ESPNOW_OTA_PROTOCOL != data[0])) { return false; }
  if (EspNowOtaSender.rx && (len <= ESPNOW_OTA_MAX_FRAME)) {
    EspNowOtaHeardFrame_t f;
    memcpy(f.mac, mac, 6);
    f.rssi = rssi;
    f.len = len;
    memcpy(f.data, data, len);
    xQueueSend(EspNowOtaSender.rx, &f, 0);
  }
  return true;
}

// The frame, tagged, to one address, on the mesh's radio
static bool EspNowOtaSenderTx(const uint8_t *mac, uint8_t *frame, size_t len) {
  if (!EspNowOtaSender.has_key || !EspNowMeshDriver.radio || EspNowMeshDriver.radio_lost) { return false; }
  EspNowOtaTagOf(&EspNowOtaSender.tag, frame, len, frame + len);
  if (!EspNowMeshRadioTake(100)) { return false; }
  bool ok = EspNowMeshDriver.radio && !EspNowMeshDriver.radio_lost && EspNowMeshAddPeer(mac, millis()) &&
            (ESP_OK == esp_now_send(mac, frame, len + ESPNOW_OTA_TAG_LEN));
  EspNowMeshRadioGive();
  return ok;
}

static void EspNowOtaSenderKey(void) {
  if (!EspNowMeshSettings.has_group) {
    EspNowOtaSender.has_key = false;
    return;
  }
  if (EspNowOtaSender.has_key && (EspNowOtaSender.group_version == EspNowMeshSettings.group_version)) { return; }
  EspNowOtaTagKey(EspNowMeshSettings.group_key, &EspNowOtaSender.tag);
  EspNowOtaSender.group_version = EspNowMeshSettings.group_version;
  EspNowOtaSender.has_key = true;
}

/*********************************************************************************************/

static void EspNowOtaSenderEnd(const char *result) {
  AddLog(LOG_LEVEL_INFO, PSTR("EOS: Send to node %u ended: %s, %u pieces, %u again"), EspNowOtaSender.node, result, EspNowOtaSender.pieces, EspNowOtaSender.again);
  Response_P(PSTR("{\"EspNowOtaSend\":{\"Node\":%u,\"Result\":\"%s\"}}"), EspNowOtaSender.node, result);
  XdrvRulesProcess(0);
  free(EspNowOtaSender.chunk);
  EspNowOtaSender.chunk = nullptr;
  EspNowOtaSender.chunk_len = 0;
  EspNowOtaSender.send = kOtaSendIdle;
}

// An HTTP request that gives up in ESPNOW_OTA_HTTP_MS, within the loop's watchdog: connecting does not yield
static void EspNowOtaHttpTimeouts(HTTPClientLight &http) {
  http.setConnectTimeout(ESPNOW_OTA_HTTP_MS);
  http.setTimeout(ESPNOW_OTA_HTTP_MS);
}

// The next len bytes of a response, the loop's watchdog fed while they come (Stream::readBytes waits without yielding);
// false when none came for ESPNOW_OTA_HTTP_MS, or the connection closed first
static bool EspNowOtaHttpRead(HTTPClientLight &http, uint8_t *buf, uint32_t len) {
  auto &stream = http.getStream();
  uint32_t got = 0;
  uint32_t heard = millis();
  while (got < len) {
    int n = stream.available();
    if (n > 0) {
      if ((uint32_t)n > len - got) { n = len - got; }
      n = stream.read(buf + got, n);
    }
    if (n > 0) {
      got += n;
      heard = millis();
    } else if (!stream.connected() || ((millis() - heard) > ESPNOW_OTA_HTTP_MS)) {
      return false;
    } else {
      delay(1);
    }
  }
  return true;
}

// The bytes [from, from + len) of blocks.bin
static bool EspNowOtaSenderFetch(uint32_t from, uint32_t len) {
  if (nullptr == EspNowOtaSender.chunk) {
    EspNowOtaSender.chunk = (uint8_t *)malloc(ESPNOW_OTA_CHUNK);
    if (nullptr == EspNowOtaSender.chunk) { return false; }
  }
  char url[ESPNOW_OTA_URL_MAX + 12];
  snprintf_P(url, sizeof(url), PSTR("%s/blocks.bin"), EspNowOtaSender.url);
  char range[40];
  snprintf_P(range, sizeof(range), PSTR("bytes=%u-%u"), from, from + len - 1);
  HTTPClientLight http;
  bool ok = http.begin(url);
  if (ok) {
    EspNowOtaHttpTimeouts(http);
    http.addHeader(F("Range"), range);
    int code = http.GET();
    ok = ((206 == code) || ((200 == code) && (0 == from))) && EspNowOtaHttpRead(http, EspNowOtaSender.chunk, len);
    http.end();
  }
  if (ok) {
    EspNowOtaSender.chunk_from = from;
    EspNowOtaSender.chunk_len = len;
    EspNowOtaSender.fetches++;
  } else {
    EspNowOtaSender.chunk_len = 0;
  }
  return ok;
}

static void EspNowOtaSenderOffer(void) {
  uint8_t frame[ESPNOW_OTA_HEADER + ESPNOW_OTA_OFFER_LEN + 1 + ESPNOW_OTA_NAME_MAX + ESPNOW_OTA_TAG_LEN] = { ESPNOW_OTA_PROTOCOL, kOtaOffer, EspNowMeshSettings.id };
  memcpy(frame + ESPNOW_OTA_HEADER, EspNowOtaSender.offer, ESPNOW_OTA_OFFER_LEN);
  size_t len = ESPNOW_OTA_HEADER + ESPNOW_OTA_OFFER_LEN;
  size_t name = strlen(EspNowOtaSender.name);
  if (name) {
    frame[len++] = name;
    memcpy(frame + len, EspNowOtaSender.name, name);
    len += name;
  }
  EspNowOtaSenderTx(EspNowOtaSender.mac, frame, len);
  EspNowOtaSender.sent_ms = millis();
}

// The piece the receiver asked for last
static void EspNowOtaSenderPiece(void) {
  uint16_t block = EspNowOtaSender.at_block;
  if (block >= EspNowOtaSender.blocks) { return; }
  uint32_t length = EspNowOtaSender.block_length[block];
  uint32_t got = EspNowOtaSender.at_got;
  if (got >= length) { return; }
  uint32_t from = EspNowOtaSender.block_offset[block] + got;
  uint32_t n = length - got;
  if (n > ESPNOW_OTA_PIECE_DATA) { n = ESPNOW_OTA_PIECE_DATA; }
  if ((from < EspNowOtaSender.chunk_from) || (from + n > EspNowOtaSender.chunk_from + EspNowOtaSender.chunk_len)) {
    uint32_t len = length - got;             // to the end of the block at most: a chunk is of one block
    if (len > ESPNOW_OTA_CHUNK) { len = ESPNOW_OTA_CHUNK; }
    if (!EspNowOtaSenderFetch(from, len)) {
      if (++EspNowOtaSender.fetch_fails >= ESPNOW_OTA_FETCH_TRIES) { return EspNowOtaSenderEnd(PSTR("Fetch")); }
      AddLog(LOG_LEVEL_DEBUG, PSTR("EOS: Bytes %u of the blocks not fetched, tried again"), from);
      EspNowOtaSender.sent_ms = millis();    // fetched again when the time for an ack has gone
      return;
    }
    EspNowOtaSender.fetch_fails = 0;
  }
  uint8_t frame[ESPNOW_OTA_MAX_FRAME] = { ESPNOW_OTA_PROTOCOL, kOtaPiece, EspNowMeshSettings.id };
  memcpy(frame + 3, EspNowOtaSender.offer + 7, 4);  // the image: the first bytes of its SHA-256
  EspNowOtaPut16(frame + 7, block);
  EspNowOtaPut32(frame + 9, got);
  EspNowOtaPut32(frame + 13, length);
  memcpy(frame + ESPNOW_OTA_HEADER + ESPNOW_OTA_PIECE_HEADER, EspNowOtaSender.chunk + (from - EspNowOtaSender.chunk_from), n);
  EspNowOtaSenderTx(EspNowOtaSender.mac, frame, ESPNOW_OTA_HEADER + ESPNOW_OTA_PIECE_HEADER + n);
  EspNowOtaSender.sent_ms = millis();
  EspNowOtaSender.pieces++;
}

static void EspNowOtaSenderAck(const uint8_t *mac, const uint8_t *body) {
  if ((kOtaSendIdle == EspNowOtaSender.send) || memcmp(mac, EspNowOtaSender.mac, 6) || memcmp(body, EspNowOtaSender.offer + 7, 4)) { return; }
  EspNowOtaSender.at_block = EspNowOtaGet16(body + 4);
  EspNowOtaSender.at_got = EspNowOtaGet32(body + 6);
  EspNowOtaSender.at_state = body[10];
  EspNowOtaSender.tries = 0;
  if (kOtaDone == EspNowOtaSender.at_state) { return EspNowOtaSenderEnd(PSTR("Done")); }
  if (kOtaFailed == EspNowOtaSender.at_state) { return EspNowOtaSenderEnd(PSTR("Failed")); }
  if (kOtaChecking == EspNowOtaSender.at_state) { return; }  // reading the image back: the next ack says how it went
  EspNowOtaSender.send = kOtaSendPieces;
  EspNowOtaSenderPiece();
}

static void EspNowOtaSenderBeacon(const EspNowOtaHeardFrame_t &f, const uint8_t *body);
static void EspNowOtaSenderBeacon(const EspNowOtaHeardFrame_t &f, const uint8_t *body) {
  uint8_t node = f.data[2];
  int32_t slot = -1;
  for (int32_t i = 0; i < ESPNOW_OTA_HEARD_MAX; i++) {
    if (EspNowOtaSender.heard[i].used && (EspNowOtaSender.heard[i].node == node)) { slot = i; break; }
    if (!EspNowOtaSender.heard[i].used && (slot < 0)) { slot = i; }
  }
  if (slot < 0) { return; }
  EspNowOtaNeighbour_t &n = EspNowOtaSender.heard[slot];
  bool changed = !n.used || (n.state != body[0]) || memcmp(n.image, body + 1, 4) || (n.block != EspNowOtaGet16(body + 5));
  n.used = true;
  n.node = node;
  memcpy(n.mac, f.mac, 6);
  n.state = body[0];
  memcpy(n.image, body + 1, 4);
  n.block = EspNowOtaGet16(body + 5);
  n.blocks = EspNowOtaGet16(body + 7);
  n.rssi = f.rssi;
  n.heard_ms = millis();
  if (changed) {
    char image[9];
    ToHex_P(n.image, 4, image, sizeof(image));
    Response_P(PSTR("{\"EspNowOta\":{\"Node\":%u,\"State\":%u,\"Image\":\"%s\",\"Block\":%u,\"Blocks\":%u,\"Rssi\":%d}}"), n.node, n.state, image, n.block, n.blocks, n.rssi);
    XdrvRulesProcess(0);
  }
}

static void EspNowOtaSenderLoop(void) {
  if (nullptr == EspNowOtaSender.rx) { return; }
  EspNowOtaHeardFrame_t f;
  while (pdTRUE == xQueueReceive(EspNowOtaSender.rx, &f, 0)) {
    if (!EspNowOtaSender.has_key || !EspNowOtaTagged(&EspNowOtaSender.tag, f.data, f.len)) { continue; }
    size_t len = f.len - ESPNOW_OTA_TAG_LEN - ESPNOW_OTA_HEADER;
    const uint8_t *body = f.data + ESPNOW_OTA_HEADER;
    if ((kOtaBeacon == f.data[1]) && (ESPNOW_OTA_BEACON_BODY == len)) {
      EspNowOtaSenderBeacon(f, body);
    } else if ((kOtaAck == f.data[1]) && (ESPNOW_OTA_ACK_BODY == len)) {
      EspNowOtaSenderAck(f.mac, body);
    }
  }
  if ((kOtaSendIdle == EspNowOtaSender.send) || ((millis() - EspNowOtaSender.sent_ms) < ESPNOW_OTA_ANSWER_MS)) { return; }
  // no ack: the same again, and given up after ESPNOW_OTA_TRIES
  if (++EspNowOtaSender.tries > ESPNOW_OTA_TRIES) { return EspNowOtaSenderEnd(PSTR("NoAnswer")); }
  EspNowOtaSender.again++;
  if (kOtaSendOffer == EspNowOtaSender.send) {
    EspNowOtaSenderOffer();
  } else {
    EspNowOtaSenderPiece();
  }
}

static void EspNowOtaSenderEverySecond(void) {
  EspNowOtaSenderKey();
  uint32_t now = millis();
  for (uint32_t i = 0; i < ESPNOW_OTA_HEARD_MAX; i++) {
    EspNowOtaNeighbour_t &n = EspNowOtaSender.heard[i];
    if (n.used && ((now - n.heard_ms) > ESPNOW_OTA_GONE_S * 1000)) {
      n.used = false;
      Response_P(PSTR("{\"EspNowOta\":{\"Node\":%u,\"Gone\":1}}"), n.node);
      XdrvRulesProcess(0);
    }
  }
}

/*********************************************************************************************/

// The manifest at the url: the offer and the blocks
static bool EspNowOtaSenderManifest(void) {
  char url[ESPNOW_OTA_URL_MAX + 16];
  snprintf_P(url, sizeof(url), PSTR("%s/manifest.json"), EspNowOtaSender.url);
  HTTPClientLight http;
  if (!http.begin(url)) { return false; }
  EspNowOtaHttpTimeouts(http);
  bool ok = (200 == http.GET()) && (http.getSize() > 0) && (http.getSize() < ESPNOW_OTA_MANIFEST_MAX);
  String text;
  if (ok) { text = http.getString(); }
  http.end();
  if (!ok) { return false; }
  JsonParser parser((char *)text.c_str());
  JsonParserObject root = parser.getRootObject();
  const char *offer = root.getStr(PSTR("offer"), "");
  JsonParserArray blocks = root[PSTR("blocks")].getArray();
  if ((2 * ESPNOW_OTA_OFFER_LEN != strlen(offer)) || (HexToBytes(offer, EspNowOtaSender.offer, ESPNOW_OTA_OFFER_LEN) != ESPNOW_OTA_OFFER_LEN)) { return false; }
  uint32_t count = blocks.size();
  if (!count || (count > ESPNOW_OTA_SEND_BLOCKS) || (count != EspNowOtaGet16(EspNowOtaSender.offer + 4))) { return false; }
  uint32_t offset = 0;
  for (uint32_t i = 0; i < count; i++) {
    EspNowOtaSender.block_offset[i] = offset;
    EspNowOtaSender.block_length[i] = blocks[i].getUInt(0);
    if (!EspNowOtaSender.block_length[i]) { return false; }
    offset += EspNowOtaSender.block_length[i];
  }
  EspNowOtaSender.blocks = count;
  return true;
}

static void CmndEspNowOtaArm(void) {
  if (!EspSingleOtaPartition() || EspRunningFactoryPartition()) {
    ResponseCmndChar_P(PSTR("no safeboot image to restart into"));
    return;
  }
  nvs_handle_t handle;
  if ((ESP_OK != nvs_open("espnowota", NVS_READWRITE, &handle))) {
    ResponseCmndChar_P(PSTR("flash write failed"));
    return;
  }
  bool ok = (ESP_OK == nvs_set_u8(handle, "armed", 1)) && (ESP_OK == nvs_commit(handle));
  nvs_close(handle);
  if (!ok) {
    ResponseCmndChar_P(PSTR("flash write failed"));
    return;
  }
  AddLog(LOG_LEVEL_INFO, PSTR("EOS: Restarting into the safeboot image, to take an image over ESP-NOW"));
  EspPrepRestartToSafeBoot();
  TasmotaGlobal.restart_flag = 2;
  ResponseCmndDone();
}

static void CmndEspNowOtaNodes(void) {
  Response_P(PSTR("{\"%s\":["), XdrvMailbox.command);
  bool first = true;
  uint32_t now = millis();
  for (uint32_t i = 0; i < ESPNOW_OTA_HEARD_MAX; i++) {
    const EspNowOtaNeighbour_t &n = EspNowOtaSender.heard[i];
    if (!n.used) { continue; }
    char mac[18];
    char image[9];
    ToHex_P(n.mac, 6, mac, sizeof(mac), ':');
    ToHex_P(n.image, 4, image, sizeof(image));
    ResponseAppend_P(PSTR("%s{\"Node\":%u,\"Mac\":\"%s\",\"State\":%u,\"Image\":\"%s\",\"Block\":%u,\"Blocks\":%u,\"Rssi\":%d,\"Age\":%u}"),
      first ? "" : ",", n.node, mac, n.state, image, n.block, n.blocks, n.rssi, (now - n.heard_ms) / 1000);
    first = false;
  }
  ResponseAppend_P(PSTR("]}"));
}

static void CmndEspNowOtaSend(void) {
  if (0 == XdrvMailbox.data_len) {
    uint32_t percent = 0;
    if (EspNowOtaSender.blocks) {
      uint32_t length = (EspNowOtaSender.at_block < EspNowOtaSender.blocks) ? EspNowOtaSender.block_length[EspNowOtaSender.at_block] : 1;
      percent = (EspNowOtaSender.at_block * 100 + EspNowOtaSender.at_got * 100 / length) / EspNowOtaSender.blocks;
      if (percent > 100) { percent = 100; }
    }
    Response_P(PSTR("{\"%s\":{\"State\":%u,\"Node\":%u,\"Block\":%u,\"Blocks\":%u,\"Percent\":%u,\"Pieces\":%u,\"Again\":%u,\"Fetches\":%u}}"),
      XdrvMailbox.command, EspNowOtaSender.send, EspNowOtaSender.node, EspNowOtaSender.at_block, EspNowOtaSender.blocks, percent,
      EspNowOtaSender.pieces, EspNowOtaSender.again, EspNowOtaSender.fetches);
    return;
  }
  if (kOtaSendIdle != EspNowOtaSender.send) {
    ResponseCmndChar_P(PSTR("a send is under way"));
    return;
  }
  char *rest = nullptr;
  uint32_t node = strtoul(XdrvMailbox.data, &rest, 10);
  while (rest && (' ' == *rest)) { rest++; }
  const char *url = rest;
  const char *name = rest ? strchr(rest, ' ') : nullptr;
  size_t url_len = name ? (size_t)(name - url) : (url ? strlen(url) : 0);
  if (!node || (node > 254) || !url_len || (url_len >= ESPNOW_OTA_URL_MAX) || strncmp_P(url, PSTR("http://"), 7)) {
    ResponseCmndChar_P(PSTR("EspNowOtaSend <node> <http://...> [<name>]"));
    return;
  }
  const EspNowOtaNeighbour_t *target = nullptr;
  for (uint32_t i = 0; i < ESPNOW_OTA_HEARD_MAX; i++) {
    if (EspNowOtaSender.heard[i].used && (EspNowOtaSender.heard[i].node == node)) { target = &EspNowOtaSender.heard[i]; }
  }
  if (!target) {
    ResponseCmndChar_P(PSTR("node not heard in its safeboot image"));
    return;
  }
  if (!EspNowOtaSender.has_key) {
    ResponseCmndChar_P(PSTR("no network key"));
    return;
  }
  memcpy(EspNowOtaSender.url, url, url_len);
  EspNowOtaSender.url[url_len] = '\0';
  if (name) {
    while (' ' == *name) { name++; }
    strlcpy(EspNowOtaSender.name, name, sizeof(EspNowOtaSender.name));
  } else {
    strlcpy(EspNowOtaSender.name, SettingsText(SET_DEVICENAME), sizeof(EspNowOtaSender.name));
  }
  if (!EspNowOtaSenderManifest()) {
    ResponseCmndChar_P(PSTR("the manifest could not be fetched or read"));
    return;
  }
  EspNowOtaSender.node = node;
  memcpy(EspNowOtaSender.mac, target->mac, 6);
  EspNowOtaSender.at_block = 0;
  EspNowOtaSender.at_got = 0;
  EspNowOtaSender.at_state = kOtaIdle;
  EspNowOtaSender.chunk_len = 0;
  EspNowOtaSender.tries = 0;
  EspNowOtaSender.pieces = 0;
  EspNowOtaSender.again = 0;
  EspNowOtaSender.fetches = 0;
  EspNowOtaSender.fetch_fails = 0;
  EspNowOtaSender.send = kOtaSendOffer;
  EspNowOtaSenderOffer();
  AddLog(LOG_LEVEL_INFO, PSTR("EOS: Sending node %u the image at %s, %u blocks"), node, EspNowOtaSender.url, EspNowOtaSender.blocks);
  ResponseCmndChar_P(PSTR("Started"));
}

static void CmndEspNowOtaStop(void) {
  if (kOtaSendIdle != EspNowOtaSender.send) { EspNowOtaSenderEnd(PSTR("Stopped")); }
  ResponseCmndDone();
}

// One pass over the image at the url: its SHA-256 and, with a partition, the image written to it as it comes. The bytes it had
static uint32_t EspNowOtaSafebootPass(const char *url, const esp_partition_t *part, uint8_t digest[32]) {
  HTTPClientLight http;
  if (!http.begin(url)) { return 0; }
  EspNowOtaHttpTimeouts(http);
  int size = (200 == http.GET()) ? http.getSize() : -1;
  uint8_t *buf = (size > 0) ? (uint8_t *)malloc(ESPNOW_OTA_SAFEBOOT_CHUNK) : nullptr;
  if (nullptr == buf) {
    http.end();
    return 0;
  }
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  uint32_t got = 0;
  bool ok = true;
  while (ok && (got < (uint32_t)size)) {
    uint32_t want = size - got;
    if (want > ESPNOW_OTA_SAFEBOOT_CHUNK) { want = ESPNOW_OTA_SAFEBOOT_CHUNK; }
    if (!EspNowOtaHttpRead(http, buf, want)) {
      ok = false;
      break;
    }
    br_sha256_update(&ctx, buf, want);
    if (part) { ok = (ESP_OK == esp_partition_write(part, got, buf, want)); }
    got += want;
    delay(1);                                // the loop's turn, for the WiFi and the watchdog
  }
  free(buf);
  http.end();
  br_sha256_out(&ctx, digest);
  return ok ? got : 0;
}

// The partition's first bytes, read back: their SHA-256
static void EspNowOtaSafebootReadBack(const esp_partition_t *part, uint32_t size, uint8_t digest[32]) {
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  uint8_t *buf = (uint8_t *)malloc(ESPNOW_OTA_SAFEBOOT_CHUNK);
  for (uint32_t at = 0; buf && (at < size); at += ESPNOW_OTA_SAFEBOOT_CHUNK) {
    uint32_t n = size - at;
    if (n > ESPNOW_OTA_SAFEBOOT_CHUNK) { n = ESPNOW_OTA_SAFEBOOT_CHUNK; }
    if (ESP_OK != esp_partition_read(part, at, buf, n)) { break; }
    br_sha256_update(&ctx, buf, n);
    yield();
  }
  free(buf);
  br_sha256_out(&ctx, digest);
}

static void CmndEspNowOtaSafeboot(void) {
  if (!XdrvMailbox.data_len || (XdrvMailbox.data_len >= ESPNOW_OTA_URL_MAX) || strncmp_P(XdrvMailbox.data, PSTR("http://"), 7)) {
    ResponseCmndChar_P(PSTR("EspNowOtaSafeboot <http://...bin>"));
    return;
  }
  const esp_partition_t *factory = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, nullptr);
  if (!factory || EspRunningFactoryPartition()) {
    ResponseCmndChar_P(PSTR("no safeboot partition to write"));
    return;
  }
  char url[ESPNOW_OTA_URL_MAX];
  strlcpy(url, XdrvMailbox.data, sizeof(url));
  // the signed record, beside the image
  char sig_url[ESPNOW_OTA_URL_MAX + 12];
  snprintf_P(sig_url, sizeof(sig_url), PSTR("%s.sig.json"), url);
  uint8_t record[ESPNOW_OTA_SIGNED_LEN];
  uint8_t signature[64];
  bool ok = false;
  {
    HTTPClientLight http;
    if (http.begin(sig_url)) {
      EspNowOtaHttpTimeouts(http);
      if ((200 == http.GET()) && (http.getSize() > 0) && (http.getSize() < ESPNOW_OTA_MANIFEST_MAX)) {
        String text = http.getString();
        JsonParser parser((char *)text.c_str());
        JsonParserObject root = parser.getRootObject();
        const char *r = root.getStr(PSTR("record"), "");
        const char *g = root.getStr(PSTR("signature"), "");
        ok = (2 * ESPNOW_OTA_SIGNED_LEN == strlen(r)) && (128 == strlen(g)) &&
             (HexToBytes(r, record, sizeof(record)) == ESPNOW_OTA_SIGNED_LEN) && (HexToBytes(g, signature, sizeof(signature)) == 64);
      }
      http.end();
    }
  }
  if (!ok) {
    ResponseCmndChar_P(PSTR("the signature could not be fetched or read"));
    return;
  }
  if (!EspNowOtaRecordSigned(record, signature)) {
    ResponseCmndChar_P(PSTR("the image is not signed by a key of this build"));
    return;
  }
  uint32_t size = EspNowOtaGet32(record);
  const uint8_t *sha = record + 7;
  if (EspNowOtaGet16(record + 4) || record[6] || !size || (size > factory->size)) {
    ResponseCmndChar_P(PSTR("the image does not fit the safeboot partition"));
    return;
  }
  // what the server has is the image signed, before anything is erased
  uint8_t digest[32];
  if ((EspNowOtaSafebootPass(url, nullptr, digest) != size) || memcmp(digest, sha, 32)) {
    ResponseCmndChar_P(PSTR("the image could not be fetched whole, or is not the one signed"));
    return;
  }
  AddLog(LOG_LEVEL_INFO, PSTR("EOS: Writing a safeboot image of %u bytes"), size);
  uint32_t erase = (size + SPI_FLASH_SEC_SIZE - 1) & ~(SPI_FLASH_SEC_SIZE - 1);
  for (uint32_t at = 0; ok && (at < erase); at += ESPNOW_OTA_SAFEBOOT_ERASE) {
    uint32_t n = erase - at;
    if (n > ESPNOW_OTA_SAFEBOOT_ERASE) { n = ESPNOW_OTA_SAFEBOOT_ERASE; }
    ok = (ESP_OK == esp_partition_erase_range(factory, at, n));
    yield();                                 // a block at a time: the whole partition at once outlasts the loop's watchdog
  }
  ok = ok && (EspNowOtaSafebootPass(url, factory, digest) == size) && !memcmp(digest, sha, 32);
  if (ok) {
    EspNowOtaSafebootReadBack(factory, size, digest);
    ok = !memcmp(digest, sha, 32);
  }
  if (ok) {
    esp_partition_pos_t pos = { .offset = factory->address, .size = factory->size };
    esp_image_metadata_t meta;
    ok = (ESP_OK == esp_image_verify(ESP_IMAGE_VERIFY, &pos, &meta));
  }
  if (!ok) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EOS: The safeboot partition holds a broken image: run EspNowOtaSafeboot again before any update"));
    ResponseCmndChar_P(PSTR("written wrong: run it again before any update"));
    return;
  }
  char hex[17];
  ToHex_P(sha, 8, hex, sizeof(hex));
  AddLog(LOG_LEVEL_INFO, PSTR("EOS: Safeboot image of %u bytes written and checked, SHA-256 %s..."), size, hex);
  Response_P(PSTR("{\"%s\":{\"Written\":%u,\"Sha256\":\"%s\"}}"), XdrvMailbox.command, size, hex);
}

// What the safeboot image kept of an image under way: a device that runs its app takes none
static void EspNowOtaSenderInit(void) {
  if (nullptr == EspNowOtaSender.rx) { EspNowOtaSender.rx = xQueueCreate(ESPNOW_OTA_RX_QUEUE, sizeof(EspNowOtaHeardFrame_t)); }
  nvs_handle_t handle;
  if (ESP_OK == nvs_open("espnowota", NVS_READWRITE, &handle)) {
    size_t size = 0;
    uint8_t armed = 0;
    bool kept = (ESP_OK == nvs_get_blob(handle, "manifest", nullptr, &size)) || (ESP_OK == nvs_get_u8(handle, "armed", &armed));
    if (kept) {
      nvs_erase_all(handle);
      nvs_commit(handle);
      AddLog(LOG_LEVEL_INFO, PSTR("EOS: What the safeboot image kept of an image is cleared"));
    }
    nvs_close(handle);
  }
}

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

const char kEspNowOtaCommands[] PROGMEM = "EspNowOta|"
  "Arm|Nodes|Send|Stop|Safeboot";
void (* const kEspNowOtaCommand[])(void) PROGMEM = {
  &CmndEspNowOtaArm, &CmndEspNowOtaNodes, &CmndEspNowOtaSend, &CmndEspNowOtaStop, &CmndEspNowOtaSafeboot };

bool Xdrv106(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_INIT:
      EspNowOtaSenderInit();
      break;
    case FUNC_LOOP:
      EspNowOtaSenderLoop();
      break;
    case FUNC_EVERY_SECOND:
      EspNowOtaSenderEverySecond();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowOtaCommands, kEspNowOtaCommand);
      break;
    case FUNC_ACTIVE:
      result = true;
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_OTA
#endif  // USE_ESPNOW_MESH
#endif  // ESP32
