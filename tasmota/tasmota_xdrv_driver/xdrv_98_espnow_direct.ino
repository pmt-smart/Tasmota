/*
  xdrv_98_espnow_direct.ino - ESP-NOW peer-to-peer transport

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

#ifdef USE_ESPNOW_DIRECT
/*********************************************************************************************\
 * Point-to-point ESP-NOW transport between two paired devices.
 *
 * Carries command and event traffic directly between the peers, without
 * routing anything through the access point, so the link keeps working while
 * the WiFi infrastructure is unavailable.
 *
 * Frame layout, 17 bytes of fixed overhead (ESP-NOW allows 250 per frame):
 *
 *   type(1) | session_id(4) | counter(4) | payload(0..233) | tag(8)
 *
 * `session_id` is drawn once per start and `counter` increases per frame, so a
 * receiver can tell a replayed frame from a fresh one. This driver carries both
 * fields but does not yet act on them.
 *
 * `tag` currently holds a 64-bit FNV-1a hash over the frame keyed with a shared
 * secret. That is enough to reject traffic from devices that do not know the
 * secret, but FNV-1a is not a cryptographic MAC: it is a placeholder for an
 * HMAC-SHA256 truncated to 8 bytes, along with a real pairing flow to establish
 * the secret rather than compiling it in.
 *
 * Uses the ESP-NOW API directly instead of a wrapper library so that peer
 * bookkeeping stays owned here: esp_now_deinit() drops the driver peer table,
 * and a wrapper holding its own copy of that list would go out of sync with it
 * across a stop/start cycle.
 *
 * Commands:
 *   EspNowEnable 0|1  - stop/start the radio, reports state when called bare
 *   EspNowStatus      - report link state, session and peer
 *   EspNowPing        - send a signed ping, RTT is logged when the pong lands
 *   EspNowForge       - send a deliberately mis-signed ping to check rejection
\*********************************************************************************************/

#define XDRV_98                        98

#include <esp_now.h>
#include <esp_wifi.h>

#define ESPNOW_DIRECT_HEADER_SIZE      9                                                              // type + session_id + counter
#define ESPNOW_DIRECT_TAG_SIZE         8
#define ESPNOW_DIRECT_OVERHEAD         (ESPNOW_DIRECT_HEADER_SIZE + ESPNOW_DIRECT_TAG_SIZE)           // 17
#define ESPNOW_DIRECT_MAX_FRAME        250
#define ESPNOW_DIRECT_MAX_PAYLOAD      (ESPNOW_DIRECT_MAX_FRAME - ESPNOW_DIRECT_OVERHEAD)             // 233

// Frame types. Only PING and PONG are handled so far; the rest are listed to
// keep the wire protocol defined in one place.
#define ESPNOW_DIRECT_TYPE_PING        0x01
#define ESPNOW_DIRECT_TYPE_PONG        0x02
#define ESPNOW_DIRECT_TYPE_PAIR_REQ    0x10
#define ESPNOW_DIRECT_TYPE_PAIR_ACK    0x11
#define ESPNOW_DIRECT_TYPE_HELLO       0x12
#define ESPNOW_DIRECT_TYPE_CMD         0x20
#define ESPNOW_DIRECT_TYPE_EVENT       0x21

// Peer addresses of the two paired devices. The same binary runs on both, so
// the peer is whichever of the two does not match the local address. Compiled
// in for now; a pairing flow replaces this with stored settings.
static const uint8_t kEspNowDirectMacA[6] = {0xA0, 0xA3, 0xB3, 0x88, 0xB1, 0x98};
static const uint8_t kEspNowDirectMacB[6] = {0xD4, 0xE9, 0xF4, 0xF3, 0x0C, 0x8C};

static const uint8_t kEspNowDirectSecret[] = {0x43, 0x61, 0x73, 0x61, 0x49, 0x6E, 0x74, 0x65};

struct {
  bool enabled = false;                    // requested state, see CmndEspNowEnable
  bool active = false;                     // ESP-NOW is initialised and the peer is registered
  uint32_t session_id = 0;                 // drawn per start, travels in every frame we send
  uint32_t tx_counter = 0;                 // increases per frame sent within the session
  uint8_t peer_mac[6] = {0};
} EspNowDirect;

/*********************************************************************************************\
 * Framing
\*********************************************************************************************/

// FNV-1a over the shared secret followed by the data. Placeholder for a real
// keyed MAC, see the file header.
static uint64_t EspNowDirectTag(const uint8_t* data, size_t len) {
  uint64_t hash = 0xCBF29CE484222325ULL;   // FNV-1a 64-bit offset basis
  for (size_t i = 0; i < sizeof(kEspNowDirectSecret); i++) {
    hash ^= kEspNowDirectSecret[i];
    hash *= 0x100000001B3ULL;              // FNV-1a 64-bit prime
  }
  for (size_t i = 0; i < len; i++) {
    hash ^= data[i];
    hash *= 0x100000001B3ULL;
  }
  return hash;
}

static void EspNowDirectPut32(uint8_t* out, uint32_t value) {
  out[0] = (uint8_t)value;
  out[1] = (uint8_t)(value >> 8);
  out[2] = (uint8_t)(value >> 16);
  out[3] = (uint8_t)(value >> 24);
}

static uint32_t EspNowDirectGet32(const uint8_t* in) {
  return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void EspNowDirectPut64(uint8_t* out, uint64_t value) {
  for (uint32_t i = 0; i < 8; i++) { out[i] = (uint8_t)(value >> (8 * i)); }
}

static uint64_t EspNowDirectGet64(const uint8_t* in) {
  uint64_t value = 0;
  for (uint32_t i = 0; i < 8; i++) { value |= (uint64_t)in[i] << (8 * i); }
  return value;
}

// Builds a signed frame into `out`, which must hold ESPNOW_DIRECT_MAX_FRAME
// bytes. Returns the frame length, or 0 if the payload does not fit.
static size_t EspNowDirectBuildFrame(uint8_t* out, uint8_t type, const uint8_t* payload, size_t payload_len) {
  if (payload_len > ESPNOW_DIRECT_MAX_PAYLOAD) { return 0; }

  out[0] = type;
  EspNowDirectPut32(&out[1], EspNowDirect.session_id);
  EspNowDirectPut32(&out[5], EspNowDirect.tx_counter);
  if (payload_len) { memcpy(&out[ESPNOW_DIRECT_HEADER_SIZE], payload, payload_len); }

  size_t signed_len = ESPNOW_DIRECT_HEADER_SIZE + payload_len;
  EspNowDirectPut64(&out[signed_len], EspNowDirectTag(out, signed_len));

  EspNowDirect.tx_counter++;
  return signed_len + ESPNOW_DIRECT_TAG_SIZE;
}

// Checks the tag of a received frame. The caller must have established that
// `len` is at least ESPNOW_DIRECT_OVERHEAD, otherwise `len - tag size` wraps
// around on unsigned arithmetic and reads out of bounds.
static bool EspNowDirectVerifyFrame(const uint8_t* frame, size_t len) {
  size_t signed_len = len - ESPNOW_DIRECT_TAG_SIZE;
  return (EspNowDirectTag(frame, signed_len) == EspNowDirectGet64(&frame[signed_len]));
}

static bool EspNowDirectSend(uint8_t type, const uint8_t* payload, size_t payload_len) {
  if (!EspNowDirect.active) { return false; }

  uint8_t frame[ESPNOW_DIRECT_MAX_FRAME];
  size_t frame_len = EspNowDirectBuildFrame(frame, type, payload, payload_len);
  if (!frame_len) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Payload of %u bytes exceeds the %u byte limit"), (unsigned)payload_len, ESPNOW_DIRECT_MAX_PAYLOAD);
    return false;
  }
  return (ESP_OK == esp_now_send(EspNowDirect.peer_mac, frame, frame_len));
}

/*********************************************************************************************\
 * Callbacks
 *
 * Both run on the ESP-NOW task, not on the main loop, so they stay short and
 * touch nothing that the main loop owns. Handing received frames to the rest of
 * the firmware needs a queue drained from the main loop; until that exists this
 * driver only answers pings, which it can do from here.
\*********************************************************************************************/

// Both callbacks are declared before their definition so that the sketch
// preprocessor does not hoist a generated prototype above the ESP-NOW include.
void EspNowDirectSendCb(const esp_now_send_info_t* info, esp_now_send_status_t status);
void EspNowDirectSendCb(const esp_now_send_info_t* info, esp_now_send_status_t status) {
  if (ESP_NOW_SEND_SUCCESS == status) { return; }

  const uint8_t* mac = info->des_addr;
  AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Send to %02X:%02X:%02X:%02X:%02X:%02X was not acknowledged"),
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void EspNowDirectRecvCb(const esp_now_recv_info_t* info, const uint8_t* frame, int len);
void EspNowDirectRecvCb(const esp_now_recv_info_t* info, const uint8_t* frame, int len) {
  // Ignore anything that is not from the paired peer before looking at the frame.
  if (memcmp(info->src_addr, EspNowDirect.peer_mac, 6)) { return; }

  // Reject short frames before deriving any length from `len`.
  if (len < ESPNOW_DIRECT_OVERHEAD) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Frame of %d bytes is shorter than the %u byte header"), len, ESPNOW_DIRECT_OVERHEAD);
    return;
  }

  if (!EspNowDirectVerifyFrame(frame, len)) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Frame rejected, bad signature"));
    return;
  }

  const uint8_t* payload = &frame[ESPNOW_DIRECT_HEADER_SIZE];
  size_t payload_len = len - ESPNOW_DIRECT_OVERHEAD;

  switch (frame[0]) {
    case ESPNOW_DIRECT_TYPE_PING:
      // Echo the payload untouched so the sender measures the round trip
      // against its own clock, without needing the two clocks to agree.
      EspNowDirectSend(ESPNOW_DIRECT_TYPE_PONG, payload, payload_len);
      break;

    case ESPNOW_DIRECT_TYPE_PONG:
      if (payload_len >= 4) {
        AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pong received, RTT %u ms, RSSI %d"),
          TimeDifference(EspNowDirectGet32(payload), millis()), info->rx_ctrl->rssi);
      }
      break;
  }
}

/*********************************************************************************************\
 * Start and stop
\*********************************************************************************************/

static bool EspNowDirectAddPeer(void) {
  uint8_t primary = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&primary, &second);

  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, EspNowDirect.peer_mac, 6);
  peer.channel = primary;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;

  esp_err_t error = esp_now_add_peer(&peer);
  if (ESP_OK != error) {
    AddLog(LOG_LEVEL_ERROR, PSTR("ENW: Adding peer failed with error %d"), error);
    return false;
  }
  return true;
}

static bool EspNowDirectStart(void) {
  if (EspNowDirect.active) { return true; }

  uint8_t local_mac[6];
  WiFi.macAddress(local_mac);
  memcpy(EspNowDirect.peer_mac, memcmp(local_mac, kEspNowDirectMacA, 6) ? kEspNowDirectMacA : kEspNowDirectMacB, 6);

  // Deinitialise first so a restart always begins from a known state. Without
  // it, a peer table left over from an earlier start would disagree with the
  // peers this driver believes it registered.
  esp_now_deinit();

  esp_err_t error = esp_now_init();
  if (ESP_OK != error) {
    AddLog(LOG_LEVEL_ERROR, PSTR("ENW: Init failed with error %d"), error);
    return false;
  }

  esp_now_register_recv_cb(EspNowDirectRecvCb);
  esp_now_register_send_cb(EspNowDirectSendCb);

  if (!EspNowDirectAddPeer()) {
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    esp_now_deinit();
    return false;
  }

  EspNowDirect.session_id = esp_random();
  EspNowDirect.tx_counter = 0;
  EspNowDirect.active = true;

  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Started, peer %02X:%02X:%02X:%02X:%02X:%02X, session %08X"),
    EspNowDirect.peer_mac[0], EspNowDirect.peer_mac[1], EspNowDirect.peer_mac[2],
    EspNowDirect.peer_mac[3], EspNowDirect.peer_mac[4], EspNowDirect.peer_mac[5],
    EspNowDirect.session_id);
  return true;
}

static void EspNowDirectStop(void) {
  if (!EspNowDirect.active) { return; }

  esp_now_unregister_recv_cb();
  esp_now_unregister_send_cb();
  esp_now_del_peer(EspNowDirect.peer_mac);
  esp_now_deinit();

  EspNowDirect.active = false;
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Stopped"));
}

// Called every second rather than at init: ESP-NOW needs WiFi up, and the start
// is retried until it is.
static void EspNowDirectEverySecond(void) {
  if (!EspNowDirect.enabled) { return; }
  if (EspNowDirect.active) { return; }
  if (TasmotaGlobal.global_state.wifi_down) { return; }

  EspNowDirectStart();
}

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

// ESP-NOW shares the radio with the WiFi station interface, so it stays off
// until asked for. A build carrying this driver then behaves like a build
// without it until someone enables the transport.
void CmndEspNowEnable(void) {
  if ((XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 1)) {
    EspNowDirect.enabled = XdrvMailbox.payload;
    if (EspNowDirect.enabled) {
      EspNowDirectStart();       // retried every second while WiFi is still coming up
    } else {
      EspNowDirectStop();
    }
  }
  ResponseCmndStateText(EspNowDirect.active);
}

void CmndEspNowStatus(void) {
  Response_P(PSTR("{\"EspNowStatus\":{\"Active\":%d,\"Peer\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"Session\":\"%08X\",\"Sent\":%u,\"MaxPayload\":%u}}"),
    EspNowDirect.active,
    EspNowDirect.peer_mac[0], EspNowDirect.peer_mac[1], EspNowDirect.peer_mac[2],
    EspNowDirect.peer_mac[3], EspNowDirect.peer_mac[4], EspNowDirect.peer_mac[5],
    EspNowDirect.session_id, EspNowDirect.tx_counter, ESPNOW_DIRECT_MAX_PAYLOAD);
}

void CmndEspNowPing(void) {
  if (!EspNowDirect.active) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  uint8_t payload[4];
  EspNowDirectPut32(payload, millis());
  EspNowDirectSend(ESPNOW_DIRECT_TYPE_PING, payload, sizeof(payload));
  ResponseCmndChar_P(PSTR("sent"));
}

// Sends a ping whose tag is deliberately wrong, to confirm the receiver drops
// it. Checks the rejection path without needing a third device to impersonate.
void CmndEspNowForge(void) {
  if (!EspNowDirect.active) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  uint8_t frame[ESPNOW_DIRECT_OVERHEAD + 4];
  uint8_t payload[4];
  EspNowDirectPut32(payload, millis());
  EspNowDirectBuildFrame(frame, ESPNOW_DIRECT_TYPE_PING, payload, sizeof(payload));
  frame[sizeof(frame) - 1] ^= 0xFF;                    // corrupt the tag
  esp_now_send(EspNowDirect.peer_mac, frame, sizeof(frame));
  ResponseCmndChar_P(PSTR("forged sent"));
}

// Leading "|" marks a flat command list without a shared prefix.
const char kEspNowDirectCommands[] PROGMEM = "|" "EspNowEnable|EspNowStatus|EspNowPing|EspNowForge";
void (* const kEspNowDirectCommand[])(void) PROGMEM = { &CmndEspNowEnable, &CmndEspNowStatus, &CmndEspNowPing, &CmndEspNowForge };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv98(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_EVERY_SECOND:
      EspNowDirectEverySecond();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowDirectCommands, kEspNowDirectCommand);
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_DIRECT
