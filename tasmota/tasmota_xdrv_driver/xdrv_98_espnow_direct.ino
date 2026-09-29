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
 * The two peers have to share a channel. A device on an access point uses the
 * access point's; with its station down it moves to the configured fallback
 * channel; and a device with no network saved and no fallback looks for its
 * peer channel by channel. Otherwise it stays on the channel the link is on,
 * and a scan that leaves the radio elsewhere is followed by the radio moving
 * back.
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
 * The link coming up is reported to the rule engine, every time the peer's
 * session is established: {"EspNowDirect":{"PeerUp":"<session>"}}. What the
 * application sends before then is lost.
 *
 * Build option USE_ESPNOW_DIRECT_EVENTS_ONLY: the device takes events from its
 * peer and runs no command it receives. A command frame, however well signed,
 * is dropped. For a device that only reports to its peer, this keeps a leaked
 * secret from becoming a remote console on it.
 *
 * Commands:
 *   EspNowEnable 0|1  - stop/start the radio, reports state when called bare;
 *                       enabled with no peer set, it starts once one is
 *   EspNowPeerMac     - peer address as AA:BB:CC:DD:EE:FF
 *   EspNowSecret      - shared secret, never echoed back; EspNowSecret2 is the
 *                       silent form that answers with asterisks either way
 *   EspNowChannel     - fixed channel, or 0 to follow the station
 *   EspNowSend        - send a command line to the peer, run there on arrival
 *                       unless the peer is built with USE_ESPNOW_DIRECT_EVENTS_ONLY
 *   EspNowEvent       - send a JSON event to the peer, fed to its rule engine
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
  volatile bool radio_lost = false;        // the WiFi stack stopped under the link, see EspNowDirectWifiEvent
  volatile uint32_t last_heard = 0;        // when the peer's last accepted frame arrived
  uint8_t hunt_channel = 0;                // channel tried while looking for the peer, 0 when not looking
  uint8_t hunt_wait = 0;                   // seconds on hunt_channel so far
  uint8_t hunt_dwell = 3;                  // seconds to stay on hunt_channel
  uint8_t keepalive_wait = 0;              // seconds since the last keepalive ping
  volatile uint8_t foreign_frames = 0;     // signed frames in a session this side does not hold, in a row
} EspNowDirect;

// A HELLO replayed from an earlier session makes this side adopt that session,
// and then refuse every frame of the session the peer really has, which it has
// no reason to announce again: the link stays blocked until one side restarts.
// The peer's own frames, signed and refused for their session this many times in
// a row, restart the link here with a new session, which the real peer answers.
#define ESPNOW_DIRECT_FOREIGN_LIMIT    3

// A device with no network saved looks for its peer channel by channel, see
// EspNowDirectHunt.
#define ESPNOW_DIRECT_HUNT_CHANNELS    13     // 1 to 13, what every regulatory domain but Japan's 14 allows
#define ESPNOW_DIRECT_KEEPALIVE_S      20     // a ping this often while the peer is quiet
#define ESPNOW_DIRECT_LOST_MS          65000  // silent this long, the link starts again

// What the receive callback accepts crosses from the WiFi task to the main loop
// through this queue: command lines and events, and the replies a greeting or a
// ping calls for. The callback runs on its own task, where running a command is
// not safe, so it only copies what arrived and lets the main loop act on it. A
// full queue drops the oldest arrival rather than blocking the radio task.
#define ESPNOW_DIRECT_RX_QUEUE_DEPTH   4

typedef struct {
  uint8_t type;
  uint8_t len;
  uint8_t data[ESPNOW_DIRECT_MAX_PAYLOAD + 1];   // one more keeps a text payload terminated
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
  // Nothing goes out between a stop of the WiFi stack and the restart of the link
  if (!EspNowDirect.active || EspNowDirect.radio_lost) { return false; }

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
 * Both run on the WiFi task, not on the main loop. The receive callback checks a
 * frame and keeps the peer's session up to date, and hands whatever has to
 * happen next to the main loop through the receive queue, replies included.
 * Every frame this driver sends is therefore built on the main loop: the send
 * counter has a single writer, and frames leave in counter order, which the
 * peer's replay check depends on.
\*********************************************************************************************/

// Hands an accepted frame, or the reply it calls for, to the main loop.
// `len` is at most ESPNOW_DIRECT_MAX_PAYLOAD, which the caller has ensured by
// rejecting longer frames.
static void EspNowDirectQueue(uint8_t type, const uint8_t* payload, size_t len) {
  if (nullptr == EspNowDirectRxQueue) { return; }

  EspNowDirectRxItem_t item;
  item.type = type;
  item.len = len;
  if (len) { memcpy(item.data, payload, len); }
  item.data[len] = '\0';
  if (pdTRUE != xQueueSend(EspNowDirectRxQueue, &item, 0)) {
    EspNowDirectRxItem_t dropped;
    xQueueReceive(EspNowDirectRxQueue, &dropped, 0);      // make room, keep the newest
    xQueueSend(EspNowDirectRxQueue, &item, 0);
  }
}

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
  // And long ones: ESP-NOW v2 carries up to 1470 bytes per frame, and every
  // buffer below is sized for the 250 bytes this protocol uses. A valid tag
  // proves only who sent the frame, not that it fits.
  if (len > ESPNOW_DIRECT_MAX_FRAME) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Frame of %d bytes is longer than the %u byte limit"), len, ESPNOW_DIRECT_MAX_FRAME);
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
    EspNowDirect.last_heard = millis();
    if (new_session) {
      // Answer so the peer learns our session too. Bounded: the reply only goes
      // out when the announced session is new to us, so two devices greeting
      // each other settle after one exchange instead of echoing forever.
      EspNowDirectQueue(ESPNOW_DIRECT_TYPE_HELLO, nullptr, 0);
      AddLog(LOG_LEVEL_INFO, PSTR("ENW: Peer session %08X"), session);
    }
    return;
  }

  if (!EspNowDirect.peer_known || (session != EspNowDirect.peer_session)) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Frame rejected, session %08X is not the established one"), session);
    if (EspNowDirect.peer_known && (EspNowDirect.foreign_frames < 255)) { EspNowDirect.foreign_frames++; }
    return;
  }
  EspNowDirect.foreign_frames = 0;
  if (counter <= EspNowDirect.peer_counter) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Frame rejected, counter %u was already seen"), counter);
    return;
  }
  EspNowDirect.peer_counter = counter;
  EspNowDirect.last_heard = millis();

  switch (type) {
    case ESPNOW_DIRECT_TYPE_PING:
      // The main loop echoes the payload untouched, so the sender measures the
      // round trip against its own clock, without needing the two to agree.
      EspNowDirectQueue(ESPNOW_DIRECT_TYPE_PING, payload, payload_len);
      break;

    case ESPNOW_DIRECT_TYPE_PONG:
      if (payload_len >= 4) {
        AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pong received, RTT %u ms, RSSI %d"),
          TimeDifference(EspNowDirectGet32(payload), millis()), info->rx_ctrl->rssi);
      }
      break;

    case ESPNOW_DIRECT_TYPE_CMD:
    case ESPNOW_DIRECT_TYPE_EVENT:
      if (payload_len) { EspNowDirectQueue(type, payload, payload_len); }
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
  if (EspNowDirect.hunt_channel) { return EspNowDirect.hunt_channel; }
  // No fallback configured: stay on the channel the link is on. A scan leaves
  // the radio on the last channel it listened to, and following the radio there
  // would lose the peer.
  if (EspNowDirect.applied_channel) { return EspNowDirect.applied_channel; }

  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;   // not started yet, stay put
  esp_wifi_get_channel(&channel, &second);
  return channel;
}

// Something else is using the radio: a scan, a join, or the WiFi Manager.
static bool EspNowDirectRadioBusy(void) {
  if (Wifi.config_type) { return true; }
#ifdef USE_WIFI_STATION_CONTROL
  if (StaCtrlRadioInUse()) { return true; }
#endif
  return (WIFI_SCAN_RUNNING == WiFi.scanComplete());
}

// The station keeps trying a saved network while WiFi is on: moving the radio
// under a connection attempt is not allowed (esp_wifi_set_channel), and the
// channel is the station's to set.
static bool EspNowDirectStationJoining(void) {
  return Settings->flag4.network_wifi && (strlen(SettingsText(SET_STASSID1)) || strlen(SettingsText(SET_STASSID2)));
}

// ESP-NOW sits on top of the WiFi stack, started in station mode, and touching
// it before that stack exists faults inside esp_now_deinit(): a script enabling
// the transport at startup would crash the device before the network is up, and
// keep crashing every boot. Whether the station is associated does not matter.
// With no access point the radio sits on the fallback channel, and that is what
// keeps the link up with the access point down, or with no network at all.
static bool EspNowDirectRadioReady(void) {
  return (WiFi.getMode() & WIFI_MODE_STA);
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
  if (target == EspNowDirect.applied_channel) {
    // A scan with the station down moves the radio across every channel and
    // leaves it on the last one, and nothing brings it back: the radio is put
    // back on the link's channel once the scan is over. The peer is still
    // registered on it, so moving the radio is enough.
    if (associated || EspNowDirectRadioBusy() || EspNowDirectStationJoining()) { return; }
    uint8_t radio = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    if ((ESP_OK != esp_wifi_get_channel(&radio, &second)) || (radio == target)) { return; }
    if (ESP_OK == esp_wifi_set_channel(target, WIFI_SECOND_CHAN_NONE)) {
      AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Radio back from channel %d to the link's %d"), radio, target);
    }
    return;
  }

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
  // Reachable from the command as well as from the periodic retry, which is why
  // the check lives here rather than in the caller.
  if (!EspNowDirectRadioReady()) { return false; }

  // Deinitialise first so a restart always begins from a known state. Without
  // it, a peer table left over from an earlier start would disagree with the
  // peers this driver believes it registered. A stop of the stack noted before
  // this start is behind it.
  EspNowDirect.radio_lost = false;
  esp_now_deinit();

  esp_err_t error = esp_now_init();
  if (ESP_OK != error) {
    AddLog(LOG_LEVEL_ERROR, PSTR("ENW: Init failed with error %d"), error);
    return false;
  }

  // The session starts before the receive callback is registered, so the first
  // frame it sees is judged against this session and not the previous one.
  EspNowDirect.session_id = esp_random();
  EspNowDirect.tx_counter = 0;
  EspNowDirect.peer_known = false;          // the peer has to greet us again
  EspNowDirect.peer_session = 0;
  EspNowDirect.peer_counter = 0;
  EspNowDirect.last_heard = millis();       // silence is counted from the start
  EspNowDirect.keepalive_wait = 0;
  EspNowDirect.foreign_frames = 0;

  if (nullptr == EspNowDirectRxQueue) {
    EspNowDirectRxQueue = xQueueCreate(ESPNOW_DIRECT_RX_QUEUE_DEPTH, sizeof(EspNowDirectRxItem_t));
  }

  esp_now_register_recv_cb(EspNowDirectRecvCb);
  esp_now_register_send_cb(EspNowDirectSendCb);

  if (!EspNowDirectAddPeer()) {
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    esp_now_deinit();
    return false;
  }

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

// The WiFi stack goes away under the link more often than it looks: every time
// Tasmota connects its station again, WifiBegin() switches station mode off,
// which stops the stack and deinitialises it, and then on again. ESP-NOW does
// not survive that, and a link left as it was keeps reporting itself up while
// nothing gets through, for good when the channel it comes back on is the one
// it had. The stop is only noted here, on the network event task; the link is
// started again from the main loop once the radio is back.
void EspNowDirectWifiEvent(arduino_event_t *event);
void EspNowDirectWifiEvent(arduino_event_t *event) {
  if ((ARDUINO_EVENT_WIFI_STA_STOP == event->event_id) || (ARDUINO_EVENT_WIFI_OFF == event->event_id)) {
    EspNowDirect.radio_lost = true;
  }
}

// A device with no network saved has no access point whose channel it shares
// with its peer, so it looks for the peer: while the peer is silent, the radio
// moves on to the next channel every few seconds, greeting on each, and it stays
// on the channel where the peer answers. Once the peer is lost (see
// EspNowDirectKeepAlive), the search starts again, with a new session, which
// the peer answers wherever it hears it.
//
// Only with the station down, no fallback channel configured and no network
// saved, and never while something else owns the radio: a scan, a join, or the
// WiFi Manager, whose AP would move with the channel. The time on each channel
// varies, so that two devices looking for each other at once do not keep the
// same distance between their channels forever.
static bool EspNowDirectMayHunt(void) {
  uint8_t channel;
  if (EspNowDirectStationChannel(&channel) || EspNowDirectSettings.channel) { return false; }
  if (strlen(SettingsText(SET_STASSID1)) || strlen(SettingsText(SET_STASSID2))) { return false; }
  return !EspNowDirectRadioBusy();
}

// A peer that stays quiet gets a ping now and then, and once nothing has come
// back from it for a while the link starts again, with a new session: the peer
// is reported unknown until it answers again. This holds on an access point as
// much as without one. A peer that is switched off, or moved to another channel
// or mode, would otherwise keep being reported as established for good.
static void EspNowDirectKeepAlive(void) {
  if (TimePassedSince(EspNowDirect.last_heard) > ESPNOW_DIRECT_LOST_MS) {
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: Peer silent on channel %d, starting the link again"), EspNowDirect.applied_channel);
    EspNowDirectStop();
    EspNowDirectStart();
    return;
  }
  if (++EspNowDirect.keepalive_wait >= ESPNOW_DIRECT_KEEPALIVE_S) {
    EspNowDirect.keepalive_wait = 0;
    // Empty, so the pong that answers it is not logged as a measurement
    if (TimePassedSince(EspNowDirect.last_heard) > ESPNOW_DIRECT_KEEPALIVE_S * 1000) {
      EspNowDirectSend(ESPNOW_DIRECT_TYPE_PING, nullptr, 0);
    }
  }
}

static void EspNowDirectHunt(void) {
  if (EspNowDirect.peer_known) {
    EspNowDirectKeepAlive();
    return;
  }
  if (!EspNowDirectMayHunt()) {
    EspNowDirect.hunt_wait = 0;
    return;
  }
  if (++EspNowDirect.hunt_wait < EspNowDirect.hunt_dwell) { return; }
  EspNowDirect.hunt_wait = 0;
  EspNowDirect.hunt_dwell = 2 + (esp_random() % 3);          // 2 to 4 s
  EspNowDirect.hunt_channel = (EspNowDirect.hunt_channel % ESPNOW_DIRECT_HUNT_CHANNELS) + 1;
  AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Looking for the peer on channel %d"), EspNowDirect.hunt_channel);
}

// Called every second rather than at init: ESP-NOW needs WiFi up, and the start
// is retried until it is.
static void EspNowDirectEverySecond(void) {
  if (!EspNowDirect.enabled) { return; }
  if (!EspNowDirectConfigured()) { return; }        // no peer yet: setting it starts the link (EspNowDirectReload)

  if (EspNowDirect.active && EspNowDirect.radio_lost) {
    // What ESP-NOW held went with the stack: nothing of it is touched until the
    // radio is back, and the start begins from a clean deinit.
    if (!EspNowDirectRadioReady()) { return; }
    EspNowDirect.radio_lost = false;
    EspNowDirect.active = false;
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: WiFi restarted under the link, starting it again"));
    EspNowDirectStart();
    return;
  }

  if (EspNowDirect.active && (EspNowDirect.foreign_frames >= ESPNOW_DIRECT_FOREIGN_LIMIT)) {
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: The peer keeps a session this side does not hold, starting the link again"));
    EspNowDirect.foreign_frames = 0;
    EspNowDirectStop();
    EspNowDirectStart();
    return;
  }

  if (EspNowDirect.active) {
    EspNowDirectHunt();
    if (!EspNowDirect.active) { return; }   // a lost peer's link starts again at the next second
    EspNowDirectApplyChannel();
    // Keep greeting until the peer answers. Covers the peer booting later than
    // us, and a greeting lost to interference, without persisting anything.
    if (!EspNowDirect.peer_known) { EspNowDirectSend(ESPNOW_DIRECT_TYPE_HELLO, nullptr, 0); }
    return;
  }

  if (!EspNowDirectRadioReady()) { return; }
  EspNowDirectStart();
}

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

// ESP-NOW shares the radio with the WiFi station interface, so it stays off
// until asked for. A build carrying this driver then behaves like a build
// without it until someone enables the transport.
// Enabled with no peer set, the transport waits for one: it starts once
// EspNowPeerMac and EspNowSecret are both set, with nothing else to send. A
// script that enables it before a pairing sets the peer used to be refused, and
// the peer set afterwards left the radio off.
void CmndEspNowEnable(void) {
  if ((XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 1)) {
    EspNowDirect.enabled = XdrvMailbox.payload;
    if (EspNowDirect.enabled) {
      EspNowDirectStart();       // retried every second while WiFi is still coming up, or the peer unset
    } else {
      EspNowDirectStop();
    }
  }
  if (EspNowDirect.enabled && !EspNowDirectConfigured()) {
    ResponseCmndChar_P(PSTR("waiting for EspNowPeerMac and EspNowSecret"));
    return;
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

// Delivers what the peer sent, and sends the replies it called for, from the
// main loop.
//
// A CMD is a command line and has to go through the command handler. An EVENT
// is already a JSON message, so it goes straight to the rule engine instead:
// running it as a command would cost a second trip through the command handler
// for no gain, and the rule path is the same one a locally generated event
// takes, so the application sees no difference between transports.
static void EspNowDirectDrainRx(void) {
  if (nullptr == EspNowDirectRxQueue) { return; }

  EspNowDirectRxItem_t item;
  while (pdTRUE == xQueueReceive(EspNowDirectRxQueue, &item, 0)) {
    switch (item.type) {
      case ESPNOW_DIRECT_TYPE_HELLO:           // a new peer session: greet it back, and say the link is up
        EspNowDirectSend(ESPNOW_DIRECT_TYPE_HELLO, nullptr, 0);
        Response_P(PSTR("{\"EspNowDirect\":{\"PeerUp\":\"%08X\"}}"), EspNowDirect.peer_session);
        XdrvRulesProcess(0);
        break;
      case ESPNOW_DIRECT_TYPE_PING:
        EspNowDirectSend(ESPNOW_DIRECT_TYPE_PONG, item.data, item.len);
        break;
      case ESPNOW_DIRECT_TYPE_EVENT:
        Response_P(PSTR("%s"), (const char*)item.data);
        XdrvRulesProcess(0);
        break;
      default:
#ifdef USE_ESPNOW_DIRECT_EVENTS_ONLY
        AddLog(LOG_LEVEL_INFO, PSTR("ENW: Command from the peer dropped, this device takes events only"));
#else
        ExecuteCommand((const char*)item.data, SRC_RULE);
#endif
        break;
    }
  }
}

static void EspNowDirectCmndSendAs(uint8_t type) {
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
  bool sent = EspNowDirectSend(type, (const uint8_t*)XdrvMailbox.data, XdrvMailbox.data_len);
  ResponseCmndChar_P(sent ? PSTR("sent") : PSTR("failed"));
}

void CmndEspNowSend(void) {
  EspNowDirectCmndSendAs(ESPNOW_DIRECT_TYPE_CMD);
}

void CmndEspNowEvent(void) {
  EspNowDirectCmndSendAs(ESPNOW_DIRECT_TYPE_EVENT);
}

#ifdef USE_BERRY
// Going through the command handler costs a full command dispatch on this side,
// measured at roughly 8 ms even for a command that does nothing, and it blocks
// the main loop for that long. Scripts relaying traffic pay it per message, so
// they get a direct entry point instead:
//
//   espnow_send(line)        -> command for the peer to run
//   espnow_send(json, true)  -> event for the peer's rule engine
//
// Returns true when the frame was handed to the radio. Callers should treat a
// missing global as "not available" and fall back to the commands above.
int EspNowDirectBerrySend(struct bvm *vm);
int EspNowDirectBerrySend(struct bvm *vm) {
  int32_t argc = be_top(vm);
  if ((argc >= 1) && be_isstring(vm, 1)) {
    const char* text = be_tostring(vm, 1);
    bool as_event = (argc >= 2) && be_tobool(vm, 2);
    size_t len = strlen(text);

    bool sent = false;
    if (len && (len <= ESPNOW_DIRECT_MAX_PAYLOAD)) {
      sent = EspNowDirectSend(as_event ? ESPNOW_DIRECT_TYPE_EVENT : ESPNOW_DIRECT_TYPE_CMD,
                              (const uint8_t*)text, len);
    }
    be_pushbool(vm, sent);
    be_return(vm);
  }
  be_raise(vm, kTypeError, nullptr);
}

static void EspNowDirectBerryRegister(void) {
  if (nullptr == berry.vm) { return; }
  be_pushntvfunction(berry.vm, EspNowDirectBerrySend);
  be_setglobal(berry.vm, "espnow_send");
  be_pop(berry.vm, 1);
}
#endif  // USE_BERRY

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
const char kEspNowDirectCommands[] PROGMEM = "|" "EspNowEnable|EspNowPeerMac|EspNowSecret|EspNowChannel|EspNowSend|EspNowEvent|EspNowStatus|EspNowPing|EspNowForge|EspNowReplay";
void (* const kEspNowDirectCommand[])(void) PROGMEM = {
  &CmndEspNowEnable, &CmndEspNowPeerMac, &CmndEspNowSecret, &CmndEspNowChannel,
  &CmndEspNowSend, &CmndEspNowEvent, &CmndEspNowStatus, &CmndEspNowPing, &CmndEspNowForge, &CmndEspNowReplay };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv98(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_PRE_INIT:
      EspNowDirectSettingsLoad();
      break;
    case FUNC_INIT:
      WiFi.onEvent(EspNowDirectWifiEvent);
#ifdef USE_BERRY
      EspNowDirectBerryRegister();
#endif
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
