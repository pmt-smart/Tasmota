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
 * receiver can tell a replayed frame from a fresh one. A session is adopted
 * only from a HELLO, never inferred from an ordinary frame: since a receiver
 * remembers just the latest (session, counter), letting any frame introduce a
 * session would make a frame captured from an earlier session acceptable again
 * as soon as the receiver moved on, which is routine after every reboot.
 * Within the established session the counter must strictly increase.
 *
 * `tag` holds an HMAC-SHA256 over the rest of the frame, keyed with a shared
 * secret and truncated to its first 8 bytes. The peer address and the secret
 * are configured per device and kept in NVS, so nothing about a given pair is
 * compiled in. Establishing the secret still has to be done by hand; deriving
 * it from a pairing exchange is not implemented.
 *
 * Uses the ESP-NOW API directly instead of a wrapper library so that peer
 * bookkeeping stays owned here: esp_now_deinit() drops the driver peer table,
 * and a wrapper holding its own copy of that list would go out of sync with it
 * across a stop/start cycle.
 *
 * Settings live in their own NVS namespace rather than in the global settings
 * struct, so the driver stays self-contained and carries its own versioning.
 *
 * Commands:
 *   EspNowEnable 0|1  - stop/start the radio, reports state when called bare
 *   EspNowPeerMac     - peer address as AA:BB:CC:DD:EE:FF
 *   EspNowSecret      - shared secret, never echoed back; EspNowSecret2 is the
 *                       silent form that answers with asterisks either way
 *   EspNowChannel     - fixed channel, or 0 to follow the station
 *   EspNowSend        - send a command line to the peer, run there on arrival
 *   EspNowStatus      - report link state, session and peer
 *   EspNowPing        - send a signed ping, RTT is logged when the pong lands
 *   EspNowForge       - send a deliberately mis-signed ping to check rejection
 *   EspNowReplay      - resend the previous ping to check replay rejection
\*********************************************************************************************/

#define XDRV_98                        98

#include <esp_now.h>
#include <esp_wifi.h>
#include <mbedtls/md.h>

#define ESPNOW_DIRECT_HEADER_SIZE      9                                                              // type + session_id + counter
#define ESPNOW_DIRECT_TAG_SIZE         8
#define ESPNOW_DIRECT_OVERHEAD         (ESPNOW_DIRECT_HEADER_SIZE + ESPNOW_DIRECT_TAG_SIZE)           // 17
#define ESPNOW_DIRECT_MAX_FRAME        250
#define ESPNOW_DIRECT_MAX_PAYLOAD      (ESPNOW_DIRECT_MAX_FRAME - ESPNOW_DIRECT_OVERHEAD)             // 233

// Frame types. The pairing pair is listed to keep the wire protocol defined in
// one place; it is not handled yet.
#define ESPNOW_DIRECT_TYPE_PING        0x01
#define ESPNOW_DIRECT_TYPE_PONG        0x02
#define ESPNOW_DIRECT_TYPE_PAIR_REQ    0x10
#define ESPNOW_DIRECT_TYPE_PAIR_ACK    0x11
#define ESPNOW_DIRECT_TYPE_HELLO       0x12
#define ESPNOW_DIRECT_TYPE_CMD         0x20
#define ESPNOW_DIRECT_TYPE_EVENT       0x21

#define ESPNOW_DIRECT_SETTINGS_VERSION 1
#define ESPNOW_DIRECT_SECRET_SIZE      32
#define ESPNOW_DIRECT_NVS_NAMESPACE    "espnowdir"

struct {
  uint32_t version;
  uint8_t peer_mac[6];
  uint8_t channel;                         // 0 follows the station channel
  uint8_t secret_len;
  uint8_t secret[ESPNOW_DIRECT_SECRET_SIZE];
} EspNowDirectSettings;

struct {
  bool enabled = false;                    // requested state, see CmndEspNowEnable
  bool active = false;                     // ESP-NOW is initialised and the peer is registered
  uint32_t session_id = 0;                 // drawn per start, travels in every frame we send
  uint32_t tx_counter = 0;                 // increases per frame sent within the session
  uint8_t applied_channel = 0;             // channel the peer entry is currently on
  bool peer_known = false;                 // a HELLO from the peer has been accepted
  uint32_t peer_session = 0;               // session the peer announced in that HELLO
  uint32_t peer_counter = 0;               // highest counter accepted within that session
} EspNowDirect;

// Received command lines cross from the ESP-NOW task to the main loop through
// this queue. The receive callback runs on its own task, where running a
// command is not safe, so it only copies the line and lets the main loop
// execute it. A full queue drops the oldest arrival rather than blocking the
// radio task.
#define ESPNOW_DIRECT_RX_QUEUE_DEPTH   4

typedef struct {
  char text[ESPNOW_DIRECT_MAX_PAYLOAD + 1];
} EspNowDirectRxItem_t;

static QueueHandle_t EspNowDirectRxQueue = nullptr;

static bool EspNowDirectConfigured(void) {
  static const uint8_t no_mac[6] = {0};
  return (EspNowDirectSettings.secret_len > 0) && memcmp(EspNowDirectSettings.peer_mac, no_mac, 6);
}

/*********************************************************************************************\
 * Settings
\*********************************************************************************************/

static void EspNowDirectSettingsSave(void) {
  NvmSave(ESPNOW_DIRECT_NVS_NAMESPACE, "settings", &EspNowDirectSettings, sizeof(EspNowDirectSettings));
}

static void EspNowDirectSettingsLoad(void) {
  memset(&EspNowDirectSettings, 0, sizeof(EspNowDirectSettings));
  EspNowDirectSettings.version = ESPNOW_DIRECT_SETTINGS_VERSION;

  auto loaded = EspNowDirectSettings;
  if (NvmLoad(ESPNOW_DIRECT_NVS_NAMESPACE, "settings", &loaded, sizeof(loaded)) &&
      (ESPNOW_DIRECT_SETTINGS_VERSION == loaded.version) &&
      (loaded.secret_len <= ESPNOW_DIRECT_SECRET_SIZE)) {
    EspNowDirectSettings = loaded;
  }
}

/*********************************************************************************************\
 * Framing
\*********************************************************************************************/

// HMAC-SHA256 over the frame, keyed with the shared secret, truncated to the
// first 8 bytes. Truncation is the standard way to trade tag length for frame
// budget; 64 bits still leaves a forgery one chance in 2^64 per attempt.
static void EspNowDirectTag(const uint8_t* data, size_t len, uint8_t* tag) {
  uint8_t digest[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if ((nullptr == info) ||
      mbedtls_md_hmac(info, EspNowDirectSettings.secret, EspNowDirectSettings.secret_len, data, len, digest)) {
    memset(tag, 0, ESPNOW_DIRECT_TAG_SIZE);   // never leave a stale tag behind on failure
    return;
  }
  memcpy(tag, digest, ESPNOW_DIRECT_TAG_SIZE);
}

// Compares in constant time so that a wrong tag reveals nothing about how many
// leading bytes happened to match.
static bool EspNowDirectTagEqual(const uint8_t* a, const uint8_t* b) {
  uint8_t diff = 0;
  for (uint32_t i = 0; i < ESPNOW_DIRECT_TAG_SIZE; i++) { diff |= a[i] ^ b[i]; }
  return (0 == diff);
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

// Builds a signed frame into `out`, which must hold ESPNOW_DIRECT_MAX_FRAME
// bytes. Returns the frame length, or 0 if the payload does not fit.
static size_t EspNowDirectBuildFrame(uint8_t* out, uint8_t type, const uint8_t* payload, size_t payload_len) {
  if (payload_len > ESPNOW_DIRECT_MAX_PAYLOAD) { return 0; }

  out[0] = type;
  EspNowDirectPut32(&out[1], EspNowDirect.session_id);
  EspNowDirectPut32(&out[5], EspNowDirect.tx_counter);
  if (payload_len) { memcpy(&out[ESPNOW_DIRECT_HEADER_SIZE], payload, payload_len); }

  size_t signed_len = ESPNOW_DIRECT_HEADER_SIZE + payload_len;
  EspNowDirectTag(out, signed_len, &out[signed_len]);

  EspNowDirect.tx_counter++;
  return signed_len + ESPNOW_DIRECT_TAG_SIZE;
}

// Checks the tag of a received frame. The caller must have established that
// `len` is at least ESPNOW_DIRECT_OVERHEAD, otherwise `len - tag size` wraps
// around on unsigned arithmetic and reads out of bounds.
static bool EspNowDirectVerifyFrame(const uint8_t* frame, size_t len) {
  size_t signed_len = len - ESPNOW_DIRECT_TAG_SIZE;
  uint8_t expected[ESPNOW_DIRECT_TAG_SIZE];
  EspNowDirectTag(frame, signed_len, expected);
  return EspNowDirectTagEqual(expected, &frame[signed_len]);
}

static bool EspNowDirectSend(uint8_t type, const uint8_t* payload, size_t payload_len) {
  if (!EspNowDirect.active) { return false; }

  uint8_t frame[ESPNOW_DIRECT_MAX_FRAME];
  size_t frame_len = EspNowDirectBuildFrame(frame, type, payload, payload_len);
  if (!frame_len) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Payload of %u bytes exceeds the %u byte limit"), (unsigned)payload_len, ESPNOW_DIRECT_MAX_PAYLOAD);
    return false;
  }
  return (ESP_OK == esp_now_send(EspNowDirectSettings.peer_mac, frame, frame_len));
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
  if (memcmp(info->src_addr, EspNowDirectSettings.peer_mac, 6)) { return; }

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
  uint8_t type = frame[0];
  uint32_t session = EspNowDirectGet32(&frame[1]);
  uint32_t counter = EspNowDirectGet32(&frame[5]);

  // A session is only ever adopted from a HELLO. Letting any frame introduce a
  // session would reopen the replay hole this is here to close: only the latest
  // (session, counter) is remembered, so a frame captured from an earlier
  // session becomes acceptable again as soon as the receiver has moved on.
  if (ESPNOW_DIRECT_TYPE_HELLO == type) {
    bool new_session = (!EspNowDirect.peer_known) || (session != EspNowDirect.peer_session);
    if (!new_session && (counter <= EspNowDirect.peer_counter)) { return; }   // replayed HELLO

    EspNowDirect.peer_known = true;
    EspNowDirect.peer_session = session;
    EspNowDirect.peer_counter = counter;
    if (new_session) {
      // Answer so the peer learns our session too. Bounded: the reply only goes
      // out when the announced session is new to us, so two devices greeting
      // each other settle after one exchange instead of echoing forever.
      EspNowDirectSend(ESPNOW_DIRECT_TYPE_HELLO, nullptr, 0);
      AddLog(LOG_LEVEL_INFO, PSTR("ENW: Peer session %08X"), session);
    }
    return;
  }

  if (!EspNowDirect.peer_known || (session != EspNowDirect.peer_session)) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Frame rejected, session %08X is not the established one"), session);
    return;
  }
  if (counter <= EspNowDirect.peer_counter) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Frame rejected, counter %u was already seen"), counter);
    return;
  }
  EspNowDirect.peer_counter = counter;

  switch (type) {
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

    case ESPNOW_DIRECT_TYPE_CMD:
    case ESPNOW_DIRECT_TYPE_EVENT:
      if (payload_len && (nullptr != EspNowDirectRxQueue)) {
        EspNowDirectRxItem_t item;
        memcpy(item.text, payload, payload_len);
        item.text[payload_len] = '\0';
        if (pdTRUE != xQueueSend(EspNowDirectRxQueue, &item, 0)) {
          EspNowDirectRxItem_t dropped;
          xQueueReceive(EspNowDirectRxQueue, &dropped, 0);      // make room, keep the newest
          xQueueSend(EspNowDirectRxQueue, &item, 0);
        }
      }
      break;
  }
}

/*********************************************************************************************\
 * Start and stop
\*********************************************************************************************/

// The station and ESP-NOW share one radio, so while the station is associated
// the channel is whatever the access point uses and nothing else may change it.
// Only once the station is gone is the channel free for the configured
// fallback, which is what keeps the link alive with the access point down.
static bool EspNowDirectStationChannel(uint8_t* channel) {
  wifi_ap_record_t ap;
  if (ESP_OK != esp_wifi_sta_get_ap_info(&ap)) { return false; }
  *channel = ap.primary;
  return true;
}

static uint8_t EspNowDirectTargetChannel(void) {
  uint8_t channel = 0;
  if (EspNowDirectStationChannel(&channel)) { return channel; }
  if (EspNowDirectSettings.channel) { return EspNowDirectSettings.channel; }

  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;   // no fallback configured, stay put
  esp_wifi_get_channel(&channel, &second);
  return channel;
}

// Follows the radio as the station comes and goes. Deliberately keyed off the
// association itself rather than off the "network is up" flag, which also waits
// for an address: the moment this has to act on is exactly the one where the
// network is down.
static bool EspNowDirectStart(void);
static void EspNowDirectStop(void);

static void EspNowDirectApplyChannel(void) {
  uint8_t sta_channel = 0;
  bool associated = EspNowDirectStationChannel(&sta_channel);
  uint8_t target = EspNowDirectTargetChannel();
  if (target == EspNowDirect.applied_channel) { return; }

  // Never move the radio out from under an associated station; that drops the
  // association. When the station holds the radio, following it is the only
  // option, and adopting its channel is all that is left to do here.
  if (!associated) {
    esp_err_t error = esp_wifi_set_channel(target, WIFI_SECOND_CHAN_NONE);
    if (ESP_OK != error) {
      AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Setting channel %d failed with error %d"), target, error);
      return;
    }
  }

  // Re-initialise instead of only moving the peer to the new channel. Observed
  // on hardware: after the radio changes channel and the station later comes
  // back, a peer that was registered while the radio sat elsewhere stops
  // carrying traffic, and both ends keep reporting the right channel while
  // nothing gets through. Only a full deinit/init recovers it. That is cheap
  // here and self-consistent, since starting re-derives the channel, registers
  // the peer again and greets the peer with a fresh session.
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Channel %d, station %s"), target, associated ? PSTR("associated") : PSTR("down"));
  EspNowDirectStop();
  EspNowDirectStart();
}

static bool EspNowDirectAddPeer(void) {
  uint8_t channel = EspNowDirectTargetChannel();

  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, EspNowDirectSettings.peer_mac, 6);
  peer.channel = channel;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;

  esp_err_t error = esp_now_add_peer(&peer);
  if (ESP_OK != error) {
    AddLog(LOG_LEVEL_ERROR, PSTR("ENW: Adding peer failed with error %d"), error);
    return false;
  }
  EspNowDirect.applied_channel = channel;
  return true;
}

static bool EspNowDirectStart(void) {
  if (EspNowDirect.active) { return true; }

  if (!EspNowDirectConfigured()) { return false; }

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

  if (nullptr == EspNowDirectRxQueue) {
    EspNowDirectRxQueue = xQueueCreate(ESPNOW_DIRECT_RX_QUEUE_DEPTH, sizeof(EspNowDirectRxItem_t));
  }

  EspNowDirect.session_id = esp_random();
  EspNowDirect.tx_counter = 0;
  EspNowDirect.peer_known = false;          // the peer has to greet us again
  EspNowDirect.peer_session = 0;
  EspNowDirect.peer_counter = 0;
  EspNowDirect.active = true;

  EspNowDirectSend(ESPNOW_DIRECT_TYPE_HELLO, nullptr, 0);   // retried every second until answered

  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Started, peer %02X:%02X:%02X:%02X:%02X:%02X, session %08X"),
    EspNowDirectSettings.peer_mac[0], EspNowDirectSettings.peer_mac[1], EspNowDirectSettings.peer_mac[2],
    EspNowDirectSettings.peer_mac[3], EspNowDirectSettings.peer_mac[4], EspNowDirectSettings.peer_mac[5],
    EspNowDirect.session_id);
  return true;
}

static void EspNowDirectStop(void) {
  if (!EspNowDirect.active) { return; }

  esp_now_unregister_recv_cb();
  esp_now_unregister_send_cb();
  esp_now_del_peer(EspNowDirectSettings.peer_mac);
  esp_now_deinit();

  EspNowDirect.active = false;
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Stopped"));
}

// Called every second rather than at init: ESP-NOW needs WiFi up, and the start
// is retried until it is.
static void EspNowDirectEverySecond(void) {
  if (!EspNowDirect.enabled) { return; }
  if (!EspNowDirectConfigured()) { return; }        // cleared while enabled, nothing to retry

  if (EspNowDirect.active) {
    EspNowDirectApplyChannel();
    // Keep greeting until the peer answers. Covers the peer booting later than
    // us, and a greeting lost to interference, without persisting anything.
    if (!EspNowDirect.peer_known) { EspNowDirectSend(ESPNOW_DIRECT_TYPE_HELLO, nullptr, 0); }
    return;
  }

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
    if (XdrvMailbox.payload && !EspNowDirectConfigured()) {
      ResponseCmndChar_P(PSTR("set EspNowPeerMac and EspNowSecret first"));
      return;
    }
    EspNowDirect.enabled = XdrvMailbox.payload;
    if (EspNowDirect.enabled) {
      EspNowDirectStart();       // retried every second while WiFi is still coming up
    } else {
      EspNowDirectStop();
    }
  }
  ResponseCmndStateText(EspNowDirect.active);
}

// Restarts the link so a settings change takes effect without a reboot.
static void EspNowDirectReload(void) {
  EspNowDirectSettingsSave();
  if (EspNowDirect.enabled) {
    EspNowDirectStop();
    EspNowDirectStart();
  }
}

void CmndEspNowPeerMac(void) {
  if (XdrvMailbox.data_len > 0) {
    unsigned int mac[6];
    if (6 != sscanf(XdrvMailbox.data, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])) {
      ResponseCmndError();
      return;
    }
    for (uint32_t i = 0; i < 6; i++) {
      if (mac[i] > 255) { ResponseCmndError(); return; }
      EspNowDirectSettings.peer_mac[i] = mac[i];
    }
    EspNowDirectReload();
  }
  char mac_text[18];
  ToHex_P(EspNowDirectSettings.peer_mac, 6, mac_text, sizeof(mac_text), ':');
  ResponseCmndChar(mac_text);
}

// Never echoes the secret. Index 2 (EspNowSecret2) is the silent form, matching
// how the other secret-bearing commands in the firmware behave.
void CmndEspNowSecret(void) {
  bool show_asterisk = (2 == XdrvMailbox.index);
  if (XdrvMailbox.data_len > 0) {
    uint32_t len = XdrvMailbox.data_len;
    if (len > ESPNOW_DIRECT_SECRET_SIZE) { len = ESPNOW_DIRECT_SECRET_SIZE; }
    memset(EspNowDirectSettings.secret, 0, ESPNOW_DIRECT_SECRET_SIZE);
    if (SC_CLEAR == Shortcut()) {
      EspNowDirectSettings.secret_len = 0;
    } else {
      memcpy(EspNowDirectSettings.secret, XdrvMailbox.data, len);
      EspNowDirectSettings.secret_len = len;
    }
    EspNowDirectReload();
  }
  show_asterisk = true;                        // the value itself is never reported back
  Response_P(S_JSON_COMMAND_ASTERISK, XdrvMailbox.command);
}

void CmndEspNowChannel(void) {
  if ((XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 13)) {
    EspNowDirectSettings.channel = XdrvMailbox.payload;
    EspNowDirectReload();
  }
  ResponseCmndNumber(EspNowDirectSettings.channel);
}

// Runs whatever the peer sent, from the main loop. Nothing about the payload is
// interpreted here: the two sides agree on plain command lines, which keeps the
// transport interchangeable with the other ones the application already speaks.
static void EspNowDirectDrainRx(void) {
  if (nullptr == EspNowDirectRxQueue) { return; }

  EspNowDirectRxItem_t item;
  while (pdTRUE == xQueueReceive(EspNowDirectRxQueue, &item, 0)) {
    ExecuteCommand(item.text, SRC_RULE);
  }
}

void CmndEspNowSend(void) {
  if (!EspNowDirect.active) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  if (!XdrvMailbox.data_len) {
    ResponseCmndChar_P(PSTR("nothing to send"));
    return;
  }
  if (XdrvMailbox.data_len > ESPNOW_DIRECT_MAX_PAYLOAD) {
    ResponseCmndChar_P(PSTR("too long"));
    return;
  }
  bool sent = EspNowDirectSend(ESPNOW_DIRECT_TYPE_CMD, (const uint8_t*)XdrvMailbox.data, XdrvMailbox.data_len);
  ResponseCmndChar_P(sent ? PSTR("sent") : PSTR("failed"));
}

void CmndEspNowStatus(void) {
  char mac_text[18];
  ToHex_P(EspNowDirectSettings.peer_mac, 6, mac_text, sizeof(mac_text), ':');
  Response_P(PSTR("{\"EspNowStatus\":{\"Active\":%d,\"Peer\":\"%s\",\"Channel\":%d,\"OnChannel\":%d,\"SecretSet\":%d,\"Session\":\"%08X\",\"Sent\":%u,\"PeerKnown\":%d,\"PeerSession\":\"%08X\",\"PeerCounter\":%u,\"MaxPayload\":%u}}"),
    EspNowDirect.active, mac_text, EspNowDirectSettings.channel, EspNowDirect.applied_channel,
    (EspNowDirectSettings.secret_len > 0), EspNowDirect.session_id,
    EspNowDirect.tx_counter, EspNowDirect.peer_known, EspNowDirect.peer_session,
    EspNowDirect.peer_counter, ESPNOW_DIRECT_MAX_PAYLOAD);
}

static uint8_t EspNowDirectLastPing[ESPNOW_DIRECT_OVERHEAD + 4];   // kept for EspNowReplay
static size_t EspNowDirectLastPingLen = 0;

void CmndEspNowPing(void) {
  if (!EspNowDirect.active) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  uint8_t payload[4];
  EspNowDirectPut32(payload, millis());

  EspNowDirectLastPingLen = EspNowDirectBuildFrame(EspNowDirectLastPing, ESPNOW_DIRECT_TYPE_PING, payload, sizeof(payload));
  esp_now_send(EspNowDirectSettings.peer_mac, EspNowDirectLastPing, EspNowDirectLastPingLen);
  ResponseCmndChar_P(PSTR("sent"));
}

// Resends the previous ping byte for byte. The signature is genuine and the
// counter is one the peer has already accepted, so a peer that tracks freshness
// must drop it. Checks the replay path without a second transmitter.
void CmndEspNowReplay(void) {
  if (!EspNowDirect.active || !EspNowDirectLastPingLen) {
    ResponseCmndChar_P(PSTR("send a ping first"));
    return;
  }
  esp_now_send(EspNowDirectSettings.peer_mac, EspNowDirectLastPing, EspNowDirectLastPingLen);
  ResponseCmndChar_P(PSTR("replayed"));
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
  esp_now_send(EspNowDirectSettings.peer_mac, frame, sizeof(frame));
  ResponseCmndChar_P(PSTR("forged sent"));
}

// Leading "|" marks a flat command list without a shared prefix.
const char kEspNowDirectCommands[] PROGMEM = "|" "EspNowEnable|EspNowPeerMac|EspNowSecret|EspNowChannel|EspNowSend|EspNowStatus|EspNowPing|EspNowForge|EspNowReplay";
void (* const kEspNowDirectCommand[])(void) PROGMEM = {
  &CmndEspNowEnable, &CmndEspNowPeerMac, &CmndEspNowSecret, &CmndEspNowChannel,
  &CmndEspNowSend, &CmndEspNowStatus, &CmndEspNowPing, &CmndEspNowForge, &CmndEspNowReplay };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv98(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_PRE_INIT:
      EspNowDirectSettingsLoad();
      break;
    case FUNC_LOOP:
      EspNowDirectDrainRx();
      break;
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
