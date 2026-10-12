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
 * receiver can tell a replayed frame from a fresh one. Within the established
 * session the counter must strictly increase.
 *
 * A session is adopted only from a HELLO, never inferred from an ordinary
 * frame, and only from a HELLO that proves to be fresh. A HELLO carries the
 * protocol version, a challenge the sender draws at every start and again
 * every time it adopts a session, the peer's challenge as the sender last heard
 * it, and whether the sender holds the receiver's session. A HELLO that repeats
 * the receiver's current challenge was made after the receiver drew it, so one
 * recorded earlier, from this session of the peer or any before it, is never
 * adopted: a receiver that adopted a replayed session would refuse every frame
 * of the session the peer really has. Every HELLO from a sender that does not
 * hold the receiver's session is answered, so that it can prove itself with the
 * answer, and three HELLOs set up both sides: a greeting, its answer, and the
 * answer to the answer. A peer speaking another protocol version never gets a
 * session, and the version it spoke is reported.
 *
 * `tag` holds an HMAC-SHA256 over the rest of the frame, keyed with the pair's
 * key and truncated to its first 8 bytes. ESP-NOW also encrypts every frame to
 * the peer (CCMP), with a local master key derived from the pair's key, so what
 * the two send each other stays between them. The peer address and the key are
 * kept per device in NVS, so nothing about a given pair is compiled in. The key
 * comes from a pairing, or is set by hand.
 *
 * Pairing, build option USE_ESPNOW_DIRECT_PAIRING: two devices that never met
 * agree on a key over ESP-NOW itself, with no access point and nothing typed.
 *   - One opens a pairing window, after something only a person next to it can
 *     do, such as holding its button: it announces itself by broadcast, a few
 *     times a second, with an X25519 key pair drawn for the window, and stays
 *     on its channel.
 *   - The other scans: it listens on its own channel, and, hearing nothing,
 *     pauses its WiFi and listens on every channel in turn, with the WiFi back
 *     at the end. It lists what it heard by key, which a copied address cannot
 *     pass for, strongest first.
 *   - The user picks one, which is asked to identify itself: the application
 *     shows it, blinking a LED for instance. On the user's confirmation the two
 *     run an X25519 exchange, with a nonce from each side, and each proves to
 *     the other that it derived the same keys, over the whole exchange and both
 *     addresses, before anything is saved.
 *   - The announcing device saves the pairing on the scanning device's proof,
 *     and repeats its own confirmation for 30 s; the scanning device saves on
 *     that confirmation. Both then bring the link up on the new key, and keep it
 *     up until the pairing ends, for what the application says over it.
 *   - A window holds one session at a time, which has 60 s from its first
 *     request to its record, and answers any other device busy. A window that
 *     closes ends no session in progress.
 *   - An announcing device that was paired with a third one tells it, over the
 *     link they still share, before the key changes, and that device reports
 *     Taken.
 * With no code to compare between the two, the pairing relies on the window
 * being short and opened on purpose, and on the identification being seen: a
 * device in radio range that answers first during the window could take the
 * place of the right one, as with any push-button pairing.
 *
 * The radio's channel is not this driver's alone: with the WiFi station driver
 * (USE_WIFI_STATION_CONTROL, which the pairing needs), a pairing claims the
 * radio for all of its run, and the link leaves the channel alone while anyone
 * holds it.
 *
 * Uses the ESP-NOW API directly instead of a wrapper library so that peer
 * bookkeeping stays owned here: esp_now_deinit() drops the driver peer table,
 * and a wrapper holding its own copy of that list would go out of sync with it
 * across a stop/start cycle.
 *
 * Settings live in their own NVS namespace rather than in the global settings
 * struct, so the driver stays self-contained and carries its own versioning.
 * They are one record: the peer's address, the key, the fallback channel, an
 * epoch that rises with every pairing saved on the device, and two values the
 * application keeps with the pairing, its link mode and the version of its
 * configuration, which a pairing clears. A record of version 1 held a secret
 * for a protocol with no version, and is dropped at start, saying so in the
 * log: that pair pairs again. Its fallback channel stays.
 *
 * Reported to the rule engine:
 *   {"EspNowDirect":{"PeerUp":"<session>"}}   every time the peer's session is
 *                                             established; what the application
 *                                             sends before then is lost
 *   {"EspNowDirect":{"PeerVersion":<n>}}      the peer speaks protocol version n,
 *                                             not this one, and the link stays down
 *   {"EspNowDirect":{"Taken":1}}              the peer paired with another device
 *   {"EspNowPair":{...}}                      the pairing, as it goes:
 *     window: "Blink":"<mac>" (a device asks this one to identify itself),
 *             "Paired":"<mac>","Epoch":<n>, "Failed":"Timeout"|"Proof"|"Key",
 *             "Window":"Closed"
 *     scan:   "Scan":"Sweeping", "Scan":"Done","Count":<n>, "Heard":{<device>},
 *             "Blinking":"<mac>" (the device picked identifies itself),
 *             "Paired":"<mac>","Epoch":<n>,
 *             "Failed":"Busy"|"NoAnswer"|"Timeout"|"NotConfirmed"|"Proof"|"Key",
 *             "Ended":"Timeout"
 *     either: "Failed":"Radio", when the WiFi Manager took the radio
 *
 * Build option USE_ESPNOW_DIRECT_EVENTS_ONLY: the device takes events from its
 * peer and runs no command it receives. A command frame, however well signed,
 * is dropped. For a device that only reports to its peer, this keeps a leaked
 * key from becoming a remote console on it.
 *
 * The saved network, with USE_WIFI_STATION_CONTROL: EspNowGiveWifi sends the
 * device's saved network to its peer, over the encrypted link, and the peer
 * reports the offer, {"EspNowDirect":{"WifiOffered":"<ssid>"}}, keeps it for
 * two minutes, and joins it on EspNowTakeWifi, with the WiFi station driver's
 * join, which saves the network only once it works. The password reaches no
 * script, no rule and no log on either side.
 * A network named in the command goes instead of the saved one, for a device
 * that moves its peer to another network before it joins it itself. Its
 * password is then in the command line, as Password1's is, and the debug log
 * level shows it as it shows any command's data.
 *
 * Build option USE_ESPNOW_DIRECT_COMMANDS_TO_RULES: the device runs no command it
 * receives either, and hands each to the rule engine instead, for the
 * application to run the ones it takes:
 *   {"EspNowDirect":{"Command":"<the line>"}}
 * The mechanism stays here and the policy there: which commands a peer may send
 * is the application's to say, not this driver's.
 *
 * Commands:
 *   EspNowEnable 0|1  - stop/start the radio, reports state when called bare;
 *                       enabled with no peer set, it starts once one is
 *   EspNowPeerMac     - peer address as AA:BB:CC:DD:EE:FF
 *   EspNowSecret      - the pair's key, up to 32 bytes, never echoed back;
 *                       EspNowSecret2 is the silent form that answers with
 *                       asterisks either way
 *   EspNowChannel     - fixed channel, or 0 to follow the station
 *   EspNowPeerMode    - a value from 0 to 255 kept with the pairing, for the application
 *   EspNowPeerConfig  - a number kept with the pairing, for the application
 *   EspNowSend        - send a command line to the peer, run there on arrival
 *                       unless the peer is built with USE_ESPNOW_DIRECT_EVENTS_ONLY
 *   EspNowEvent       - send a JSON event to the peer, fed to its rule engine
 *   EspNowStatus      - report link state, session, peer and pairing
 *   EspNowPing        - send a signed ping, RTT is logged when the pong lands
 *   EspNowForge       - send a deliberately mis-signed ping to check rejection
 *   EspNowReplay      - resend the previous ping to check replay rejection
 * With USE_WIFI_STATION_CONTROL:
 *   EspNowGiveWifi [{"SSId":"<ssid>","Password":"<password>"}] - offer the
 *                       saved network to the peer, or the one named
 *   EspNowTakeWifi [0] - join the network the peer offered; 0 drops the offer
 * With USE_ESPNOW_DIRECT_PAIRING:
 *   EspNowPairOpen <s>[,<zigbee>] - open a pairing window for s seconds, up to
 *                       600, announcing a Zigbee channel, 0 for none; reports
 *                       whether a window is open when called bare
 *   EspNowPairScan [2] - look for a window; 2 goes through every channel straight
 *                       away, without listening on the current one first
 *   EspNowPairHeard   - the devices the scan heard, strongest first
 *   EspNowPairBlink <id> - ask a device heard to identify itself
 *   EspNowPairWith <id> - pair with the device that identifies itself
 *   EspNowPairStop    - end the window or the scan, with the WiFi as it was
\*********************************************************************************************/

#define XDRV_98                        98

#include <esp_now.h>
#include <esp_wifi.h>
#include <mbedtls/md.h>
#ifdef USE_ESPNOW_DIRECT_PAIRING
#ifndef USE_WIFI_STATION_CONTROL
#error "USE_ESPNOW_DIRECT_PAIRING needs USE_WIFI_STATION_CONTROL, whose driver pauses the WiFi for a pairing"
#endif
#include <t_bearssl.h>
#endif

#ifdef USE_ESPNOW_MESH
// The ESP-NOW mesh (xdrv_98_1_espnow_mesh.ino) rides on the radio of this driver when it is up: it hears the frames that are its own before this
// driver looks at them, is told what became of the frame it was sending, and is told when ESP-NOW is started and stopped here
bool EspNowMeshHearsFrame(const uint8_t* mac, int8_t rssi, const uint8_t* data, int len);
bool EspNowMeshSendResult(const uint8_t* mac, bool ok);
void EspNowMeshDirectRadio(bool up);
#endif

#define ESPNOW_DIRECT_PROTOCOL         2                                                              // the wire protocol, in every HELLO and announcement
#define ESPNOW_DIRECT_HEADER_SIZE      9                                                              // type + session_id + counter
#define ESPNOW_DIRECT_TAG_SIZE         8
#define ESPNOW_DIRECT_OVERHEAD         (ESPNOW_DIRECT_HEADER_SIZE + ESPNOW_DIRECT_TAG_SIZE)           // 17
#define ESPNOW_DIRECT_MAX_FRAME        250
#define ESPNOW_DIRECT_MAX_PAYLOAD      (ESPNOW_DIRECT_MAX_FRAME - ESPNOW_DIRECT_OVERHEAD)             // 233

// Link frames, signed with the pair's key
#define ESPNOW_DIRECT_TYPE_PING        0x01
#define ESPNOW_DIRECT_TYPE_PONG        0x02
#define ESPNOW_DIRECT_TYPE_HELLO       0x12
#define ESPNOW_DIRECT_TYPE_CMD         0x20
#define ESPNOW_DIRECT_TYPE_EVENT       0x21
#define ESPNOW_DIRECT_TYPE_TAKEN       0x22   // the sender paired with another device
#define ESPNOW_DIRECT_TYPE_WIFI        0x23   // the sender's saved network: ssid_len | ssid | password_len | password
// Pairing frames, sent before there is a key: 0x10 to 0x17, all but the HELLO
#define ESPNOW_DIRECT_TYPE_PAIR_REQ    0x10
#define ESPNOW_DIRECT_TYPE_PAIR_ACK    0x11
#define ESPNOW_DIRECT_TYPE_ANNOUNCE    0x13
#define ESPNOW_DIRECT_TYPE_BLINK       0x14
#define ESPNOW_DIRECT_TYPE_PAIR_PROOF  0x15
#define ESPNOW_DIRECT_TYPE_RECORDED    0x16
#define ESPNOW_DIRECT_TYPE_PAIR_STATUS 0x17

// A HELLO's payload: version(1) | challenge(4) | the peer's challenge as last
// heard(4) | whether the sender holds the receiver's session(1). Protocol 1
// greeted with an empty one.
#define ESPNOW_DIRECT_HELLO_SIZE       10
// An unproven HELLO is answered at most this often: anyone can repeat one
#define ESPNOW_DIRECT_HELLO_ANSWER_MS  500

#define ESPNOW_DIRECT_SETTINGS_VERSION 2
#define ESPNOW_DIRECT_KEY_SIZE         32
#define ESPNOW_DIRECT_NVS_NAMESPACE    "espnowdir"

// The peer record, saved as one block. The first twelve bytes are laid out as
// in version 1, so a record of that version is told apart when it is loaded.
struct {
  uint32_t version;
  uint8_t peer_mac[6];
  uint8_t channel;                         // 0 follows the station channel
  uint8_t key_len;
  uint8_t key[ESPNOW_DIRECT_KEY_SIZE];
  uint32_t epoch;                          // rises with every pairing saved on this device
  uint32_t config;                         // EspNowPeerConfig, the application's
  uint8_t mode;                            // EspNowPeerMode, the application's
  uint8_t spare[3];
} EspNowDirectSettings;

struct {
  bool enabled = false;                    // requested state, see CmndEspNowEnable
  bool radio = false;                      // ESP-NOW is initialised, for the link or a pairing
  bool active = false;                     // the link is up: the peer is registered and greeted
  uint32_t session_id = 0;                 // drawn per start, travels in every frame we send
  uint32_t tx_counter = 0;                 // increases per frame sent within the session
  volatile uint32_t challenge = 0;         // drawn per start and per session adopted, see EspNowDirectHello
  uint8_t applied_channel = 0;             // channel the peer entry is currently on
  bool peer_known = false;                 // the peer's session is established, from a fresh HELLO
  uint32_t peer_session = 0;               // session the peer announced in that HELLO
  uint32_t peer_counter = 0;               // highest counter accepted within that session
  volatile uint32_t heard_session = 0;     // session of the peer's last HELLO, fresh or not
  volatile uint32_t heard_challenge = 0;   // and the challenge it carried
  volatile uint8_t peer_version = 0;       // protocol of the peer's last HELLO, 0 before any
  uint8_t reported_version = 0;            // the other version last reported, so it is said once
  volatile uint32_t hello_answered = 0;    // when an unproven HELLO was last answered
  volatile bool radio_lost = false;        // the WiFi stack stopped under ESP-NOW, see EspNowDirectWifiEvent
  volatile uint32_t last_heard = 0;        // when the peer's last accepted frame arrived
  volatile int8_t peer_rssi = 0;           // and its signal
  uint8_t hunt_channel = 0;                // channel tried while looking for the peer, 0 when not looking
  uint8_t hunt_wait = 0;                   // seconds on hunt_channel so far
  uint8_t hunt_dwell = 3;                  // seconds to stay on hunt_channel
  uint8_t keepalive_wait = 0;              // seconds since the last keepalive ping
} EspNowDirect;

// A device with no network saved looks for its peer channel by channel, see
// EspNowDirectHunt.
#define ESPNOW_DIRECT_HUNT_CHANNELS    13     // 1 to 13, what every regulatory domain but Japan's 14 allows
#define ESPNOW_DIRECT_KEEPALIVE_S      20     // a ping this often while the peer is quiet
#define ESPNOW_DIRECT_LOST_MS          65000  // silent this long, the link starts again

// What the receive callback accepts crosses from the WiFi task to the main loop
// through this queue: command lines, events and pairing frames, and the replies
// and reports a greeting or a ping calls for. The callback runs on its own task,
// where running a command is not safe, so it only copies what arrived and lets
// the main loop act on it. A full queue drops the oldest arrival rather than
// blocking the radio task.
#define ESPNOW_DIRECT_RX_QUEUE_DEPTH   4

// What the main loop is asked to do besides delivering a frame
#define ESPNOW_DIRECT_DO_HELLO         0xF0   // answer a HELLO: its session and challenge follow
#define ESPNOW_DIRECT_DO_PEER_UP       0xF1   // report the peer's session
#define ESPNOW_DIRECT_DO_VERSION       0xF2   // report the peer's protocol version, which follows

typedef struct {
  uint8_t type;
  uint8_t len;
  uint8_t mac[6];                          // the sender, for a pairing frame
  int8_t rssi;                             // and its signal
  uint8_t data[ESPNOW_DIRECT_MAX_PAYLOAD + 1];   // one more keeps a text payload terminated
} EspNowDirectRxItem_t;

static QueueHandle_t EspNowDirectRxQueue = nullptr;

static bool EspNowDirectConfigured(void) {
  static const uint8_t no_mac[6] = {0};
  return (EspNowDirectSettings.key_len > 0) && memcmp(EspNowDirectSettings.peer_mac, no_mac, 6);
}

// Wipes key material in a way the compiler does not drop as a dead store
static void EspNowDirectWipe(void* buffer, size_t len) {
  volatile uint8_t* p = (volatile uint8_t*)buffer;
  while (len--) { *p++ = 0; }
}

#ifdef USE_ESPNOW_DIRECT_PAIRING
static bool EspNowDirectPairing(void);
static bool EspNowDirectPairKeepsLink(void);
static void EspNowDirectPairAddBroadcast(void);
static uint8_t EspNowDirectPairBit(uint8_t type);
static volatile uint8_t EspNowDirectPairAccept = 0;   // the pairing frame types the receive callback takes, a bit each
#else
static bool EspNowDirectPairing(void) { return false; }
static bool EspNowDirectPairKeepsLink(void) { return false; }
#endif

#ifdef USE_WIFI_STATION_CONTROL
static void EspNowDirectWifiExpire(void);
#endif

// The link runs when it is enabled, and after a pairing saved its record, until
// the pairing ends
static bool EspNowDirectWanted(void) {
  return EspNowDirect.enabled || EspNowDirectPairKeepsLink();
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

  // A shorter record loads what it has, as NVS does; the rest stays zero
  auto loaded = EspNowDirectSettings;
  loaded.version = 0;
  if (!NvmLoad(ESPNOW_DIRECT_NVS_NAMESPACE, "settings", &loaded, sizeof(loaded)) || !loaded.version) { return; }
  if ((ESPNOW_DIRECT_SETTINGS_VERSION == loaded.version) && (loaded.key_len <= ESPNOW_DIRECT_KEY_SIZE)) {
    EspNowDirectSettings = loaded;
    EspNowDirectWipe(&loaded, sizeof(loaded));
    return;
  }
  // Version 1 kept a secret for a protocol with no version, which this one does
  // not speak: its peer has to pair again. The fallback channel is the user's,
  // and stays. Saved at once, so this is said once.
  uint32_t version = loaded.version;
  if (1 == version) { EspNowDirectSettings.channel = loaded.channel; }
  EspNowDirectWipe(&loaded, sizeof(loaded));
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Peer record of version %u dropped, the pair has to pair again"), version);
  EspNowDirectSettingsSave();
}

/*********************************************************************************************\
 * Framing
\*********************************************************************************************/

// HMAC-SHA256 over the frame, keyed with the pair's key, truncated to the first
// 8 bytes. Truncation is the standard way to trade tag length for frame budget;
// 64 bits still leaves a forgery one chance in 2^64 per attempt.
static void EspNowDirectTag(const uint8_t* data, size_t len, uint8_t* tag) {
  uint8_t digest[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if ((nullptr == info) ||
      mbedtls_md_hmac(info, EspNowDirectSettings.key, EspNowDirectSettings.key_len, data, len, digest)) {
    memset(tag, 0, ESPNOW_DIRECT_TAG_SIZE);   // never leave a stale tag behind on failure
    return;
  }
  memcpy(tag, digest, ESPNOW_DIRECT_TAG_SIZE);
}

// Compares in constant time so that a wrong tag reveals nothing about how many
// leading bytes happened to match.
static bool EspNowDirectEqual(const uint8_t* a, const uint8_t* b, size_t len) {
  uint8_t diff = 0;
  for (uint32_t i = 0; i < len; i++) { diff |= a[i] ^ b[i]; }
  return (0 == diff);
}

// The local master key ESP-NOW encrypts the frames to the peer with, derived
// from the pair's key, so both sides derive the same one. False when the key
// cannot be derived: the link then does not start, rather than go unencrypted.
static bool EspNowDirectLocalKey(uint8_t* lmk) {
  static const char label[] = "ESP-NOW direct LMK";
  uint8_t digest[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if ((nullptr == info) ||
      mbedtls_md_hmac(info, EspNowDirectSettings.key, EspNowDirectSettings.key_len,
                      (const uint8_t*)label, sizeof(label) - 1, digest)) {
    return false;
  }
  memcpy(lmk, digest, ESP_NOW_KEY_LEN);
  EspNowDirectWipe(digest, sizeof(digest));
  return true;
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
  return EspNowDirectEqual(expected, &frame[signed_len], ESPNOW_DIRECT_TAG_SIZE);
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

// A challenge is never 0, which a HELLO sends as the peer's challenge before it
// has heard one.
static uint32_t EspNowDirectChallenge(void) {
  uint32_t challenge;
  do { challenge = esp_random(); } while (!challenge);
  return challenge;
}

// Greets the peer: this side's challenge, the one `echo` repeats, and whether
// this side holds `session`, the session the HELLO answers.
static void EspNowDirectSendHello(uint32_t echo, uint32_t session) {
  uint8_t hello[ESPNOW_DIRECT_HELLO_SIZE];
  hello[0] = ESPNOW_DIRECT_PROTOCOL;
  EspNowDirectPut32(&hello[1], EspNowDirect.challenge);
  EspNowDirectPut32(&hello[5], echo);
  hello[9] = (EspNowDirect.peer_known && (EspNowDirect.peer_session == session)) ? 1 : 0;
  EspNowDirectSend(ESPNOW_DIRECT_TYPE_HELLO, hello, sizeof(hello));
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

// Hands an accepted frame, or the reply it calls for, to the main loop, with
// the sender when `info` is given. `len` is at most ESPNOW_DIRECT_MAX_PAYLOAD,
// which the caller has ensured by rejecting longer frames.
// Declared before its definition, as every function here whose signature names a
// type of the ESP-IDF or of this driver: the sketch preprocessor would otherwise
// hoist a generated prototype above the include or the typedef it needs.
static void EspNowDirectQueueFrom(uint8_t type, const esp_now_recv_info_t* info, const uint8_t* payload, size_t len);
static void EspNowDirectQueueFrom(uint8_t type, const esp_now_recv_info_t* info, const uint8_t* payload, size_t len) {
  if (nullptr == EspNowDirectRxQueue) { return; }

  EspNowDirectRxItem_t item;
  item.type = type;
  item.len = len;
  if (info) {
    memcpy(item.mac, info->src_addr, 6);
    item.rssi = info->rx_ctrl->rssi;
  }
  if (len) { memcpy(item.data, payload, len); }
  item.data[len] = '\0';
  if (pdTRUE != xQueueSend(EspNowDirectRxQueue, &item, 0)) {
    EspNowDirectRxItem_t dropped;
    xQueueReceive(EspNowDirectRxQueue, &dropped, 0);      // make room, keep the newest
    xQueueSend(EspNowDirectRxQueue, &item, 0);
  }
}

static void EspNowDirectQueue(uint8_t type, const uint8_t* payload, size_t len) {
  EspNowDirectQueueFrom(type, nullptr, payload, len);
}

// Asks the main loop to answer a HELLO of `session` that carried `challenge`.
static void EspNowDirectQueueHello(uint32_t session, uint32_t challenge) {
  uint8_t answer[8];
  EspNowDirectPut32(&answer[0], session);
  EspNowDirectPut32(&answer[4], challenge);
  EspNowDirectQueue(ESPNOW_DIRECT_DO_HELLO, answer, sizeof(answer));
}

// A HELLO that repeats this side's current challenge is fresh, and only a fresh
// one establishes the sender's session. The challenge is drawn again as soon as
// a session is adopted, so the proof that established it is used up. A sender
// that does not hold this side's session gets an answer, which carries its
// challenge back: an unproven HELLO at most every ESPNOW_DIRECT_HELLO_ANSWER_MS,
// since anyone can repeat a recorded one.
//
// The answer is queued before the report of the session adopted. It is what
// makes the peer take this side's session, and whatever the application sends
// as the link comes up goes out after it: the other way round, the first frame
// of the application reached a peer that did not hold the session yet, which
// rejected it.
static void EspNowDirectHello(uint32_t session, uint32_t counter, const uint8_t* payload, size_t len, int8_t rssi) {
  bool known = EspNowDirect.peer_known && (session == EspNowDirect.peer_session);
  if (known && (counter <= EspNowDirect.peer_counter)) { return; }   // repeated within the session

  uint8_t version = (len >= ESPNOW_DIRECT_HELLO_SIZE) ? payload[0] : 1;
  EspNowDirect.peer_version = version;
  if (ESPNOW_DIRECT_PROTOCOL != version) {
    EspNowDirectQueue(ESPNOW_DIRECT_DO_VERSION, &version, 1);
    return;
  }
  uint32_t challenge = EspNowDirectGet32(&payload[1]);
  uint32_t echo = EspNowDirectGet32(&payload[5]);
  bool held = payload[9];
  EspNowDirect.heard_session = session;
  EspNowDirect.heard_challenge = challenge;

  bool adopted = false;
  if (echo == EspNowDirect.challenge) {
    if (!known) {
      EspNowDirect.peer_known = true;
      EspNowDirect.peer_session = session;
      EspNowDirect.challenge = EspNowDirectChallenge();
      adopted = true;
      AddLog(LOG_LEVEL_INFO, PSTR("ENW: Peer session %08X"), session);
    }
  } else if (!known) {
    // Never adopted: answered, so that the sender proves itself with the answer
    if (!held && (TimePassedSince(EspNowDirect.hello_answered) >= ESPNOW_DIRECT_HELLO_ANSWER_MS)) {
      EspNowDirect.hello_answered = millis();
      EspNowDirectQueueHello(session, challenge);
    }
    return;
  }
  EspNowDirect.peer_counter = counter;
  EspNowDirect.last_heard = millis();
  EspNowDirect.peer_rssi = rssi;
  if (!held) { EspNowDirectQueueHello(session, challenge); }
  if (adopted) { EspNowDirectQueue(ESPNOW_DIRECT_DO_PEER_UP, nullptr, 0); }
}

// Both callbacks are declared before their definition so that the sketch
// preprocessor does not hoist a generated prototype above the ESP-NOW include.
void EspNowDirectSendCb(const esp_now_send_info_t* info, esp_now_send_status_t status);
void EspNowDirectSendCb(const esp_now_send_info_t* info, esp_now_send_status_t status) {
#ifdef USE_ESPNOW_MESH
  if (EspNowMeshSendResult(info->des_addr, ESP_NOW_SEND_SUCCESS == status)) { return; }
#endif
  if (ESP_NOW_SEND_SUCCESS == status) { return; }

  const uint8_t* mac = info->des_addr;
  if (0xFF == mac[0]) { return; }            // a broadcast is never acknowledged
  AddLog(LOG_LEVEL_DEBUG, PSTR("ENW: Send to %02X:%02X:%02X:%02X:%02X:%02X was not acknowledged"),
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void EspNowDirectRecvCb(const esp_now_recv_info_t* info, const uint8_t* frame, int len);
void EspNowDirectRecvCb(const esp_now_recv_info_t* info, const uint8_t* frame, int len) {
  if (len < 1) { return; }
#ifdef USE_ESPNOW_MESH
  if (EspNowMeshHearsFrame(info->src_addr, info->rx_ctrl->rssi, frame, len)) { return; }
#endif
#ifdef USE_ESPNOW_DIRECT_PAIRING
  // Pairing frames come from devices this side may never have met. Only the
  // kinds the pairing in progress waits for are taken, and only copied, with the
  // sender, for the main loop to check: version | to | body.
  uint8_t bit = EspNowDirectPairBit(frame[0]);
  if (bit) {
    if ((EspNowDirectPairAccept & bit) && (len >= 8) && (len <= 8 + 80)) {
      EspNowDirectQueueFrom(frame[0], info, &frame[1], len - 1);
    }
    return;
  }
#endif

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

  if (ESPNOW_DIRECT_TYPE_HELLO == type) {
    EspNowDirectHello(session, counter, payload, payload_len, info->rx_ctrl->rssi);
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
  EspNowDirect.last_heard = millis();
  EspNowDirect.peer_rssi = info->rx_ctrl->rssi;

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

    case ESPNOW_DIRECT_TYPE_TAKEN:
      EspNowDirectQueue(type, nullptr, 0);
      break;

    case ESPNOW_DIRECT_TYPE_WIFI:
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

static uint8_t EspNowDirectRadioChannel(void) {
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&channel, &second);
  return channel;
}

static uint8_t EspNowDirectTargetChannel(void) {
  uint8_t channel = 0;
  if (EspNowDirectStationChannel(&channel)) { return channel; }
  // A pairing holds the channel where it put the radio, the other device's
  if (EspNowDirectPairing()) { return EspNowDirectRadioChannel(); }
  if (EspNowDirectSettings.channel) { return EspNowDirectSettings.channel; }
  if (EspNowDirect.hunt_channel) { return EspNowDirect.hunt_channel; }
  // No fallback configured: stay on the channel the link is on. A scan leaves
  // the radio on the last channel it listened to, and following the radio there
  // would lose the peer.
  if (EspNowDirect.applied_channel) { return EspNowDirect.applied_channel; }
  return EspNowDirectRadioChannel();       // not started yet, stay put
}

// Something above the link holds the radio: the WiFi Manager, a join, a pairing
// or a scan, which the WiFi station driver names when it is built in.
static bool EspNowDirectRadioBusy(void) {
#ifdef USE_WIFI_STATION_CONTROL
  return (STA_RADIO_FREE != StaCtrlRadioOwner());
#else
  return Wifi.config_type || (WIFI_SCAN_RUNNING == WiFi.scanComplete());
#endif
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

// ESP-NOW itself, which the link and a pairing share. Started from a known
// state: deinitialised first, so a peer table left over from an earlier start
// never disagrees with the peers this driver believes it registered. A stop of
// the stack noted before this start is behind it.
static bool EspNowDirectRadioStart(void) {
  EspNowDirect.radio_lost = false;
#ifdef USE_ESPNOW_MESH
  EspNowMeshDirectRadio(false);            // the mesh lets go of the radio, and of any send it has under way, before it is taken apart
#endif
  esp_now_deinit();

  esp_err_t error = esp_now_init();
  if (ESP_OK != error) {
    AddLog(LOG_LEVEL_ERROR, PSTR("ENW: Init failed with error %d"), error);
    EspNowDirect.radio = false;
#ifdef USE_ESPNOW_MESH
    EspNowMeshDirectRadio(false);
#endif
    return false;
  }
  if (nullptr == EspNowDirectRxQueue) {
    EspNowDirectRxQueue = xQueueCreate(ESPNOW_DIRECT_RX_QUEUE_DEPTH, sizeof(EspNowDirectRxItem_t));
  }
  esp_now_register_recv_cb(EspNowDirectRecvCb);
  esp_now_register_send_cb(EspNowDirectSendCb);
  EspNowDirect.radio = true;
#ifdef USE_ESPNOW_MESH
  EspNowMeshDirectRadio(true);
#endif
#ifdef USE_ESPNOW_DIRECT_PAIRING
  EspNowDirectPairAddBroadcast();          // a pairing in progress keeps its broadcast entry
#endif
  return true;
}

static void EspNowDirectRadioStop(void) {
  if (!EspNowDirect.radio) { return; }
#ifdef USE_ESPNOW_MESH
  EspNowMeshDirectRadio(false);            // before the radio is taken apart, as at its start
#endif
  esp_now_unregister_recv_cb();
  esp_now_unregister_send_cb();
  esp_now_deinit();
  EspNowDirect.radio = false;
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
    uint8_t radio = EspNowDirectRadioChannel();
    if (!radio || (radio == target)) { return; }
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
  if (!EspNowDirectLocalKey(peer.lmk)) {
    AddLog(LOG_LEVEL_ERROR, PSTR("ENW: No local master key for the peer"));
    return false;
  }
  peer.encrypt = true;

  esp_err_t error = esp_now_add_peer(&peer);
  EspNowDirectWipe(peer.lmk, sizeof(peer.lmk));
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

  // The session starts before the receive callback is registered, so the first
  // frame it sees is judged against this session and not the previous one.
  EspNowDirect.session_id = esp_random();
  EspNowDirect.tx_counter = 0;
  EspNowDirect.challenge = EspNowDirectChallenge();
  EspNowDirect.peer_known = false;          // the peer has to greet us again
  EspNowDirect.peer_session = 0;
  EspNowDirect.peer_counter = 0;
  EspNowDirect.heard_session = 0;
  EspNowDirect.heard_challenge = 0;
  EspNowDirect.last_heard = millis();       // silence is counted from the start
  EspNowDirect.keepalive_wait = 0;

  if (!EspNowDirectRadioStart()) { return false; }
  if (!EspNowDirectAddPeer()) {
    if (!EspNowDirectPairing()) { EspNowDirectRadioStop(); }
    return false;
  }

  EspNowDirect.active = true;

  EspNowDirectSendHello(0, 0);              // retried every second until answered

  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Started, peer %02X:%02X:%02X:%02X:%02X:%02X, session %08X"),
    EspNowDirectSettings.peer_mac[0], EspNowDirectSettings.peer_mac[1], EspNowDirectSettings.peer_mac[2],
    EspNowDirectSettings.peer_mac[3], EspNowDirectSettings.peer_mac[4], EspNowDirectSettings.peer_mac[5],
    EspNowDirect.session_id);
  return true;
}

// Stops the link. ESP-NOW itself stays up while a pairing runs on it.
static void EspNowDirectStop(void) {
  if (!EspNowDirect.active) { return; }

  esp_now_del_peer(EspNowDirectSettings.peer_mac);
  EspNowDirect.active = false;
  if (!EspNowDirectPairing()) { EspNowDirectRadioStop(); }
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Stopped"));
}

// The WiFi stack goes away under the link more often than it looks: every time
// Tasmota connects its station again, WifiBegin() switches station mode off,
// which stops the stack and deinitialises it, and then on again. ESP-NOW does
// not survive that, and a link left as it was keeps reporting itself up while
// nothing gets through, for good when the channel it comes back on is the one
// it had. The stop is only noted here, on the network event task; ESP-NOW is
// started again from the main loop once the radio is back.
void EspNowDirectWifiEvent(arduino_event_t *event);
void EspNowDirectWifiEvent(arduino_event_t *event) {
  if ((ARDUINO_EVENT_WIFI_STA_STOP == event->event_id) || (ARDUINO_EVENT_WIFI_OFF == event->event_id)) {
    EspNowDirect.radio_lost = true;
  }
}

// What ESP-NOW held went with the stack: nothing of it is touched until the
// radio is back, and then it starts again from a clean deinit, with the link if
// the link was up. False while the radio is not back.
static bool EspNowDirectRecover(void) {
  if (!EspNowDirect.radio_lost || !EspNowDirect.radio) { return true; }
  if (!EspNowDirectRadioReady()) { return false; }
  if (EspNowDirect.active) {
    EspNowDirect.active = false;
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: WiFi restarted under the link, starting it again"));
    if (EspNowDirectStart()) { return true; }
  }
  if (EspNowDirectPairing()) {
    EspNowDirectRadioStart();
  } else {
    EspNowDirect.radio = false;            // nothing to start again: what the stack held is gone
    EspNowDirect.radio_lost = false;
#ifdef USE_ESPNOW_MESH
    EspNowMeshDirectRadio(false);
#endif
  }
  return true;
}

// A device with no network saved has no access point whose channel it shares
// with its peer, so it looks for the peer: while the peer is silent, the radio
// moves on to the next channel every few seconds, greeting on each, and it stays
// on the channel where the peer answers. Once the peer is lost (see
// EspNowDirectKeepAlive), the search starts again, with a new session, which
// the peer answers wherever it hears it.
//
// Only with the station down, no fallback channel configured and no network
// saved, and never while something else owns the radio: a scan, a join, a
// pairing, or the WiFi Manager, whose AP would move with the channel. The time
// on each channel varies, so that two devices looking for each other at once do
// not keep the same distance between their channels forever.
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
#ifdef USE_WIFI_STATION_CONTROL
  EspNowDirectWifiExpire();
#endif
  if (!EspNowDirectWanted()) { return; }
  if (!EspNowDirectConfigured()) { return; }        // no peer yet: setting it starts the link (EspNowDirectReload)

  if (EspNowDirect.radio_lost && EspNowDirect.radio) {
    EspNowDirectRecover();
    return;
  }

  if (EspNowDirect.active) {
    EspNowDirectHunt();
    if (!EspNowDirect.active) { return; }   // a lost peer's link starts again at the next second
    // A pairing holds the channel where it put the radio: the link stays on it
    if (!EspNowDirectPairing()) { EspNowDirectApplyChannel(); }
    // Keep greeting until the peer answers. Covers the peer booting later than
    // us, and a greeting lost to interference, without persisting anything.
    if (!EspNowDirect.peer_known) { EspNowDirectSendHello(EspNowDirect.heard_challenge, EspNowDirect.heard_session); }
    return;
  }

  if (!EspNowDirectRadioReady()) { return; }
  EspNowDirectStart();
}

#ifdef USE_ESPNOW_DIRECT_PAIRING
/*********************************************************************************************\
 * Pairing
 *
 * Frames go by broadcast, before there is a key: the other device has no peer
 * entry here, and a device never met gets none, so nobody fills the peer table
 * by asking. Each says who it is for:
 *
 *   type(1) | version(1) | to(6) | body
 *
 *   ANNOUNCE     window -> all      flags(1) | channel(1) | zigbee(1) | key(32) | name(0..32)
 *   BLINK        scan -> window     window key(32)
 *   PAIR_STATUS  window -> scan     window key(32) | code(1)
 *   PAIR_REQ     scan -> window     window key(32) | scan key(32) | scan nonce(16)
 *   PAIR_ACK     window -> scan     window nonce(16) | window proof(16)
 *   PAIR_PROOF   scan -> window     scan proof(16)
 *   RECORDED     window -> scan     recorded proof(16)
 *
 * `window` is the device that announces, and `scan` the one that looks for it.
 * An announcement says the channel the window is on: a frame from a channel next
 * to the radio's can be heard, and the one it was heard on is not always the
 * one it was sent on.
 *
 * The keys come from the X25519 result Z and the exchange's transcript T, by
 * HKDF (RFC 5869) over HMAC-SHA256, with the two nonces as its salt:
 *   T   = version | scan address | window address | scan key | window key |
 *         scan nonce | window nonce
 *   PRK = HMAC(scan nonce | window nonce, Z)
 *   the confirmation key = HMAC(PRK, "ESP-NOW direct confirm" | 1)
 *   the pair's key       = HMAC(PRK, "ESP-NOW direct key" | T | 1)
 * and each proof is the first 16 bytes of HMAC(confirmation key, label | T),
 * with "ESP-NOW direct window", "ESP-NOW direct scan" and "ESP-NOW direct
 * recorded" for the three.
\*********************************************************************************************/

#define ESPNOW_DIRECT_PAIR_HEADER      8      // type | version | to
#define ESPNOW_DIRECT_PAIR_BODY_MAX    80     // PAIR_REQ's
#define ESPNOW_DIRECT_NONCE_SIZE       16
#define ESPNOW_DIRECT_PROOF_SIZE       16
#define ESPNOW_DIRECT_TRANSCRIPT_SIZE  109    // 1 + 6 + 6 + 32 + 32 + 16 + 16
#define ESPNOW_DIRECT_NAME_SIZE        32     // what an announcement carries of the device's name
#define ESPNOW_DIRECT_HEARD_MAX        6      // devices a scan keeps, told apart by key
#define ESPNOW_DIRECT_WINDOW_MAX_S     600

#define ESPNOW_DIRECT_ANNOUNCE_MS      100    // how often a window announces
#define ESPNOW_DIRECT_LISTEN_MS        3000   // a scan listens on its own channel this long
#define ESPNOW_DIRECT_DWELL_MS         300    // and then this long on each channel
#define ESPNOW_DIRECT_RETRY_MS         500    // a request with no answer goes again
#define ESPNOW_DIRECT_TRIES            10     // this many times, then it failed
#define ESPNOW_DIRECT_SESSION_MS       60000  // from a session's first request to its record
#define ESPNOW_DIRECT_RECONFIRM_MS     30000  // the window repeats its confirmation this long
#define ESPNOW_DIRECT_RECORDED_EVERY_MS 1000
#define ESPNOW_DIRECT_LINGER_MS        120000 // a scan that is over, or paired, ends this long after

#define ESPNOW_DIRECT_ANNOUNCE_NETWORK 0x01   // the window is on an access point
#define ESPNOW_DIRECT_ANNOUNCE_BUSY    0x02   // the window is in a session with a device
#define ESPNOW_DIRECT_STATUS_OK        0      // the window identifies itself
#define ESPNOW_DIRECT_STATUS_BUSY      1      // the window is in a session with another device

static const uint8_t EspNowDirectBroadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

enum EspNowDirectPairPhases {
  ESPNOW_PAIR_WINDOW,                      // announcing, with no session
  ESPNOW_PAIR_SESSION,                     // a device asked for an identification, and maybe exchanged keys
  ESPNOW_PAIR_RECORDED,                    // its proof arrived: saved, and confirmed again for a while
  ESPNOW_PAIR_LISTEN,                      // scanning the current channel
  ESPNOW_PAIR_SWEEP,                       // scanning every channel, with the WiFi paused
  ESPNOW_PAIR_HEARD,                       // the scan is over, and the user picks
  ESPNOW_PAIR_BLINK,                       // the device picked is asked to identify itself
  ESPNOW_PAIR_EXCHANGE,                    // keys asked for
  ESPNOW_PAIR_CONFIRM,                     // proof sent, and its confirmation awaited
  ESPNOW_PAIR_PAIRED                       // saved
};

typedef struct {
  uint8_t mac[6];
  uint8_t key[32];
  uint8_t channel;
  int8_t rssi;                             // the strongest heard
  uint8_t version;
  uint8_t flags;
  uint8_t zigbee;
  char name[ESPNOW_DIRECT_NAME_SIZE + 1];
} EspNowDirectHeard_t;

typedef struct {
  uint8_t phase;
  bool window;                             // this side announces; otherwise it scans
  bool recorded;                           // a pairing was saved: the link stays up until the end
  bool exchanged;                          // the session has its keys
  bool blinking;                           // the device picked said it identifies itself
  bool saved;                              // the window saved the session's pairing
  bool told;                               // the window told the device paired before
  uint8_t tries;
  uint8_t zigbee;                          // what the window announces
  uint8_t sweep;                           // the channel a sweep listens on, 0 before it starts
  uint8_t home;                            // the channel the radio was on before the sweep
  uint8_t target;                          // the channel of the device picked, 0 for the station's own
  uint8_t chosen;                          // the device picked, in heard
  uint8_t heard_count;
  uint32_t window_until;
  uint32_t session_until;
  uint32_t announce_at;
  uint32_t next;                           // the next sweep step, retry or confirmation
  uint32_t linger_until;
  uint8_t own_secret[32];                  // this side's X25519 key pair, for the window or the exchange
  uint8_t own_public[32];
  uint8_t own_nonce[ESPNOW_DIRECT_NONCE_SIZE];
  uint8_t other_mac[6];                    // the device of the window's session
  uint8_t other_public[32];
  uint8_t other_nonce[ESPNOW_DIRECT_NONCE_SIZE];
  uint8_t transcript[ESPNOW_DIRECT_TRANSCRIPT_SIZE];
  uint8_t confirm_key[32];
  uint8_t link_key[ESPNOW_DIRECT_KEY_SIZE];
  uint8_t ack[ESPNOW_DIRECT_NONCE_SIZE + ESPNOW_DIRECT_PROOF_SIZE];   // the window's answer, sent again as it was
  uint8_t proof[ESPNOW_DIRECT_PROOF_SIZE]; // the scan's
  uint8_t recorded_proof[ESPNOW_DIRECT_PROOF_SIZE];
  EspNowDirectHeard_t heard[ESPNOW_DIRECT_HEARD_MAX];
} EspNowDirectPair_t;

// On the heap only while a pairing runs. The receive callback never reads it:
// it takes what EspNowDirectPairAccept lets through, and the main loop checks it.
static EspNowDirectPair_t* EspNowPair = nullptr;

static bool EspNowDirectPairing(void) {
  return (nullptr != EspNowPair);
}

static bool EspNowDirectPairKeepsLink(void) {
  return EspNowPair && EspNowPair->recorded;
}

static uint8_t EspNowDirectPairBit(uint8_t type) {
  if ((type < ESPNOW_DIRECT_TYPE_PAIR_REQ) || (type > ESPNOW_DIRECT_TYPE_PAIR_STATUS) || (ESPNOW_DIRECT_TYPE_HELLO == type)) { return 0; }
  return 1 << (type - ESPNOW_DIRECT_TYPE_PAIR_REQ);
}

static void EspNowDirectPairPhase(uint8_t phase) {
  EspNowPair->phase = phase;
  uint8_t accept = 0;
  switch (phase) {
    case ESPNOW_PAIR_WINDOW:
    case ESPNOW_PAIR_SESSION:
    case ESPNOW_PAIR_RECORDED:
      accept = EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_BLINK) | EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_PAIR_REQ) |
               EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_PAIR_PROOF);
      break;
    case ESPNOW_PAIR_LISTEN:
    case ESPNOW_PAIR_SWEEP:
    case ESPNOW_PAIR_HEARD:
      accept = EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_ANNOUNCE);
      break;
    case ESPNOW_PAIR_BLINK:
      accept = EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_PAIR_STATUS);
      break;
    case ESPNOW_PAIR_EXCHANGE:
      accept = EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_PAIR_ACK) | EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_PAIR_STATUS);
      break;
    case ESPNOW_PAIR_CONFIRM:
      accept = EspNowDirectPairBit(ESPNOW_DIRECT_TYPE_RECORDED);
      break;
  }
  EspNowDirectPairAccept = accept;
}

static const char* EspNowDirectPairPhaseText(void) {
  if (!EspNowPair) { return PSTR(""); }
  switch (EspNowPair->phase) {
    case ESPNOW_PAIR_WINDOW:   return PSTR("Window");
    case ESPNOW_PAIR_SESSION:  return PSTR("Session");
    case ESPNOW_PAIR_RECORDED: return PSTR("Recorded");
    case ESPNOW_PAIR_LISTEN:   return PSTR("Listen");
    case ESPNOW_PAIR_SWEEP:    return PSTR("Sweep");
    case ESPNOW_PAIR_HEARD:    return PSTR("Heard");
    case ESPNOW_PAIR_BLINK:    return PSTR("Blink");
    case ESPNOW_PAIR_EXCHANGE: return PSTR("Exchange");
    case ESPNOW_PAIR_CONFIRM:  return PSTR("Confirm");
    case ESPNOW_PAIR_PAIRED:   return PSTR("Paired");
  }
  return PSTR("");
}

static void EspNowDirectOwnMac(uint8_t* mac) {
  esp_wifi_get_mac(WIFI_IF_STA, mac);
}

static void EspNowDirectMacText(const uint8_t* mac, char* text) {
  ToHex_P(mac, 6, text, 18, ':');
}

static void EspNowDirectPairReport(const char* key, const char* value) {
  Response_P(PSTR("{\"EspNowPair\":{\"%s\":\"%s\"}}"), key, value);
  XdrvRulesProcess(0);
}

static void EspNowDirectPairReportMac(const char* key, const uint8_t* mac) {
  char text[18];
  EspNowDirectMacText(mac, text);
  EspNowDirectPairReport(key, text);
}

// X25519 (RFC 7748). BearSSL reads the scalar big-endian, where the RFC's is
// little-endian, so the secret goes in reversed; points are little-endian in
// both. An all-zero result comes from a point of small order and gives no key
// (RFC 7748, section 6.1).
static bool EspNowDirectX25519(uint8_t* out, const uint8_t* secret, const uint8_t* point) {
  uint8_t scalar[32];
  for (uint32_t i = 0; i < 32; i++) { scalar[i] = secret[31 - i]; }
  memcpy(out, point, 32);
  uint32_t ok = br_ec_c25519_m15.mul(out, 32, scalar, 32, BR_EC_curve25519);
  EspNowDirectWipe(scalar, sizeof(scalar));
  uint8_t any = 0;
  for (uint32_t i = 0; i < 32; i++) { any |= out[i]; }
  return ok && any;
}

static bool EspNowDirectKeyPair(uint8_t* secret, uint8_t* public_key) {
  static const uint8_t base[32] = { 9 };
  esp_fill_random(secret, 32);
  return EspNowDirectX25519(public_key, secret, base);
}

// HMAC-SHA256 over `label`, then `len` bytes of `data`, then `counter` unless it
// is 0: the one-byte block counter of an HKDF expansion.
static bool EspNowDirectHmac(const uint8_t* key, size_t key_len, const char* label,
                             const uint8_t* data, size_t len, uint8_t counter, uint8_t* out) {
  uint8_t message[32 + ESPNOW_DIRECT_TRANSCRIPT_SIZE + 1];
  size_t label_len = strlen(label);
  if (label_len + len + 1 > sizeof(message)) { return false; }
  memcpy(message, label, label_len);
  if (len) { memcpy(&message[label_len], data, len); }
  size_t total = label_len + len;
  if (counter) { message[total++] = counter; }
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  bool ok = (nullptr != info) && !mbedtls_md_hmac(info, key, key_len, message, total, out);
  EspNowDirectWipe(message, sizeof(message));
  return ok;
}

// The exchange's keys, from this side's secret and the other side's key, over
// the transcript of the exchange.
static bool EspNowDirectPairDerive(const uint8_t* scan_mac, const uint8_t* window_mac,
                                   const uint8_t* scan_key, const uint8_t* window_key,
                                   const uint8_t* scan_nonce, const uint8_t* window_nonce, const uint8_t* other_key) {
  EspNowDirectPair_t* p = EspNowPair;
  uint8_t* t = p->transcript;
  t[0] = ESPNOW_DIRECT_PROTOCOL;
  memcpy(&t[1], scan_mac, 6);
  memcpy(&t[7], window_mac, 6);
  memcpy(&t[13], scan_key, 32);
  memcpy(&t[45], window_key, 32);
  memcpy(&t[77], scan_nonce, ESPNOW_DIRECT_NONCE_SIZE);
  memcpy(&t[93], window_nonce, ESPNOW_DIRECT_NONCE_SIZE);

  uint8_t shared[32];
  uint8_t prk[32];
  bool ok = EspNowDirectX25519(shared, p->own_secret, other_key) &&
            EspNowDirectHmac(&t[77], 2 * ESPNOW_DIRECT_NONCE_SIZE, "", shared, sizeof(shared), 0, prk) &&
            EspNowDirectHmac(prk, sizeof(prk), PSTR("ESP-NOW direct confirm"), nullptr, 0, 1, p->confirm_key) &&
            EspNowDirectHmac(prk, sizeof(prk), PSTR("ESP-NOW direct key"), t, ESPNOW_DIRECT_TRANSCRIPT_SIZE, 1, p->link_key);
  EspNowDirectWipe(shared, sizeof(shared));
  EspNowDirectWipe(prk, sizeof(prk));
  return ok;
}

static void EspNowDirectPairProof(const char* label, uint8_t* out) {
  uint8_t digest[32];
  if (!EspNowDirectHmac(EspNowPair->confirm_key, sizeof(EspNowPair->confirm_key), label,
                        EspNowPair->transcript, ESPNOW_DIRECT_TRANSCRIPT_SIZE, 0, digest)) {
    esp_fill_random(digest, sizeof(digest));   // matches nothing the other side sends
  }
  memcpy(out, digest, ESPNOW_DIRECT_PROOF_SIZE);
  EspNowDirectWipe(digest, sizeof(digest));
}

// A session's keys and proofs go as soon as the session does
static void EspNowDirectPairForget(void) {
  EspNowDirectPair_t* p = EspNowPair;
  p->exchanged = false;
  p->blinking = false;
  p->saved = false;
  p->told = false;
  EspNowDirectWipe(p->other_public, sizeof(p->other_public));
  EspNowDirectWipe(p->other_nonce, sizeof(p->other_nonce));
  EspNowDirectWipe(p->transcript, sizeof(p->transcript));
  EspNowDirectWipe(p->confirm_key, sizeof(p->confirm_key));
  EspNowDirectWipe(p->link_key, sizeof(p->link_key));
  EspNowDirectWipe(p->ack, sizeof(p->ack));
  EspNowDirectWipe(p->proof, sizeof(p->proof));
  EspNowDirectWipe(p->recorded_proof, sizeof(p->recorded_proof));
  if (!p->window) {                        // the scan's key pair is the exchange's; the window's is the window's
    EspNowDirectWipe(p->own_secret, sizeof(p->own_secret));
    EspNowDirectWipe(p->own_public, sizeof(p->own_public));
    EspNowDirectWipe(p->own_nonce, sizeof(p->own_nonce));
  }
}

static bool EspNowDirectPairSend(uint8_t type, const uint8_t* to, const uint8_t* body, size_t len) {
  if (!EspNowDirect.radio || EspNowDirect.radio_lost || (len > ESPNOW_DIRECT_PAIR_BODY_MAX)) { return false; }
  uint8_t frame[ESPNOW_DIRECT_PAIR_HEADER + ESPNOW_DIRECT_PAIR_BODY_MAX];
  frame[0] = type;
  frame[1] = ESPNOW_DIRECT_PROTOCOL;
  memcpy(&frame[2], to, 6);
  if (len) { memcpy(&frame[ESPNOW_DIRECT_PAIR_HEADER], body, len); }
  return (ESP_OK == esp_now_send(EspNowDirectBroadcast, frame, ESPNOW_DIRECT_PAIR_HEADER + len));
}

static void EspNowDirectPairAddBroadcast(void) {
  if (!EspNowPair || !EspNowDirect.radio || esp_now_is_peer_exist(EspNowDirectBroadcast)) { return; }
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, EspNowDirectBroadcast, 6);
  peer.channel = 0;                        // the channel the radio is on, wherever the pairing puts it
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;
  esp_now_add_peer(&peer);
}

// Saves the pairing with `mac`, on the exchange's key: the record, with the
// epoch up and the application's two values cleared, and the link on the new
// key at once, kept up for the rest of the pairing.
static void EspNowDirectPairSave(const uint8_t* mac) {
  EspNowDirectStop();
  memcpy(EspNowDirectSettings.peer_mac, mac, 6);
  memcpy(EspNowDirectSettings.key, EspNowPair->link_key, ESPNOW_DIRECT_KEY_SIZE);
  EspNowDirectSettings.key_len = ESPNOW_DIRECT_KEY_SIZE;
  EspNowDirectSettings.epoch++;
  EspNowDirectSettings.mode = 0;
  EspNowDirectSettings.config = 0;
  EspNowDirectSettingsSave();
  EspNowPair->recorded = true;
  EspNowDirectStart();

  char text[18];
  EspNowDirectMacText(mac, text);
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Paired with %s, epoch %u"), text, EspNowDirectSettings.epoch);
  Response_P(PSTR("{\"EspNowPair\":{\"Paired\":\"%s\",\"Epoch\":%u}}"), text, EspNowDirectSettings.epoch);
  XdrvRulesProcess(0);
}

// Starts a pairing, a window or a scan: the radio claimed, ESP-NOW up with its
// broadcast entry, and the state on the heap. False when something above a
// pairing has the radio, or with no memory for it.
static bool EspNowDirectPairBegin(bool window) {
  if (!StaCtrlRadioClaim()) { return false; }
  EspNowPair = (EspNowDirectPair_t*)calloc(1, sizeof(EspNowDirectPair_t));
  if (!EspNowPair) {
    StaCtrlRadioRelease();
    return false;
  }
  EspNowPair->window = window;
  if (!EspNowDirect.radio) {
    if (EspNowDirectRadioReady()) { EspNowDirectRadioStart(); }   // otherwise from the next tick
  } else {
    EspNowDirectPairAddBroadcast();
  }
  return true;
}

// Ends the pairing: the broadcast entry and the state go, keys wiped, and the
// radio is released, with the WiFi as it was. The link carries on only when it
// is enabled, and follows the station again.
static void EspNowDirectPairEnd(void) {
  if (!EspNowPair) { return; }
  EspNowDirectPairAccept = 0;
  if (EspNowDirect.radio) { esp_now_del_peer(EspNowDirectBroadcast); }
  EspNowDirectWipe(EspNowPair, sizeof(EspNowDirectPair_t));
  free(EspNowPair);
  EspNowPair = nullptr;
  StaCtrlRadioRelease();
  if (!EspNowDirect.enabled) { EspNowDirectStop(); }
  if (!EspNowDirect.active) { EspNowDirectRadioStop(); }
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing over"));
}

static void EspNowDirectPairBusy(void) {
  Response_P(PSTR("{\"%s\":\"Busy\",\"Owner\":\"%s\"}"), XdrvMailbox.command, StaCtrlRadioOwnerText(StaCtrlRadioOwner()));
}

/*********************************************************************************************\
 * Pairing: the window
\*********************************************************************************************/

static void EspNowDirectAnnounce(void) {
  EspNowDirectPair_t* p = EspNowPair;
  uint8_t body[3 + 32 + ESPNOW_DIRECT_NAME_SIZE];
  uint8_t sta;
  body[0] = (EspNowDirectStationChannel(&sta) ? ESPNOW_DIRECT_ANNOUNCE_NETWORK : 0) |
            ((ESPNOW_PAIR_WINDOW != p->phase) ? ESPNOW_DIRECT_ANNOUNCE_BUSY : 0);
  body[1] = EspNowDirectRadioChannel();
  body[2] = p->zigbee;
  memcpy(&body[3], p->own_public, 32);
  const char* name = SettingsText(SET_FRIENDLYNAME1);
  size_t name_len = strlen(name);
  if (name_len > ESPNOW_DIRECT_NAME_SIZE) { name_len = ESPNOW_DIRECT_NAME_SIZE; }
  memcpy(&body[35], name, name_len);
  EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_ANNOUNCE, EspNowDirectBroadcast, body, 35 + name_len);
}

static void EspNowDirectPairStatus(const uint8_t* to, uint8_t code) {
  uint8_t body[33];
  memcpy(body, EspNowPair->own_public, 32);
  body[32] = code;
  EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_PAIR_STATUS, to, body, sizeof(body));
}

// Back to announcing, with no session
static void EspNowDirectWindowFree(void) {
  EspNowDirectPairForget();
  EspNowDirectPairPhase(ESPNOW_PAIR_WINDOW);
}

static void EspNowDirectWindowSession(const uint8_t* mac) {
  EspNowDirectWindowFree();
  memcpy(EspNowPair->other_mac, mac, 6);
  EspNowPair->session_until = millis() + ESPNOW_DIRECT_SESSION_MS;
  EspNowDirectPairPhase(ESPNOW_PAIR_SESSION);
  char text[18];
  EspNowDirectMacText(mac, text);
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing session with %s"), text);
  EspNowDirectPairReport(PSTR("Blink"), text);
}

static void EspNowDirectWindowReceive(const EspNowDirectRxItem_t* item);
static void EspNowDirectWindowReceive(const EspNowDirectRxItem_t* item) {
  EspNowDirectPair_t* p = EspNowPair;
  uint8_t own[6];
  EspNowDirectOwnMac(own);
  if (memcmp(&item->data[1], own, 6)) { return; }           // for another device
  const uint8_t* body = &item->data[7];
  size_t len = item->len - 7;
  bool session = (ESPNOW_PAIR_WINDOW != p->phase);
  bool same = session && !memcmp(item->mac, p->other_mac, 6);

  switch (item->type) {
    case ESPNOW_DIRECT_TYPE_BLINK:
    case ESPNOW_DIRECT_TYPE_PAIR_REQ:
      // A request names this window's key: one for an earlier window, or for
      // another device's, is not for this one
      if ((len < 32) || memcmp(body, p->own_public, 32)) { return; }
      if (session && !same) {
        EspNowDirectPairStatus(item->mac, ESPNOW_DIRECT_STATUS_BUSY);
        return;
      }
      break;
    case ESPNOW_DIRECT_TYPE_PAIR_PROOF:
      if (!same) { return; }
      break;
    default:
      return;
  }

  if (ESPNOW_DIRECT_TYPE_BLINK == item->type) {
    if (32 != len) { return; }
    // A session starts only while the window is open. The device of the session
    // asking again starts it over once it has exchanged keys: a new attempt, or,
    // after the record, a confirmation that got lost, whose pairing it replaces.
    if (!session) {
      if (TimeReached(p->window_until)) { return; }
      EspNowDirectWindowSession(item->mac);
    } else if (p->exchanged || (ESPNOW_PAIR_RECORDED == p->phase)) {
      EspNowDirectWindowSession(item->mac);
    }
    EspNowDirectPairStatus(item->mac, ESPNOW_DIRECT_STATUS_OK);
    return;
  }

  if (ESPNOW_DIRECT_TYPE_PAIR_REQ == item->type) {
    if ((32 + 32 + ESPNOW_DIRECT_NONCE_SIZE != len) || (ESPNOW_PAIR_SESSION != p->phase)) { return; }
    if (p->exchanged) {
      // One exchange per identification; the same request again lost its answer
      if (!memcmp(&body[32], p->other_public, 32) && !memcmp(&body[64], p->other_nonce, ESPNOW_DIRECT_NONCE_SIZE)) {
        EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_PAIR_ACK, p->other_mac, p->ack, sizeof(p->ack));
      }
      return;
    }
    memcpy(p->other_public, &body[32], 32);
    memcpy(p->other_nonce, &body[64], ESPNOW_DIRECT_NONCE_SIZE);
    esp_fill_random(p->own_nonce, ESPNOW_DIRECT_NONCE_SIZE);
    if (!EspNowDirectPairDerive(p->other_mac, own, p->other_public, p->own_public, p->other_nonce, p->own_nonce, p->other_public)) {
      AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing refused, no key from the device's"));
      EspNowDirectPairReport(PSTR("Failed"), PSTR("Key"));
      EspNowDirectWindowFree();
      return;
    }
    memcpy(p->ack, p->own_nonce, ESPNOW_DIRECT_NONCE_SIZE);
    EspNowDirectPairProof(PSTR("ESP-NOW direct window"), &p->ack[ESPNOW_DIRECT_NONCE_SIZE]);
    p->exchanged = true;
    EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_PAIR_ACK, p->other_mac, p->ack, sizeof(p->ack));
    return;
  }

  // PAIR_PROOF: saved at the next tick, after the device paired before is told
  if ((ESPNOW_DIRECT_PROOF_SIZE != len) || !p->exchanged || (ESPNOW_PAIR_SESSION != p->phase)) { return; }
  uint8_t expected[ESPNOW_DIRECT_PROOF_SIZE];
  EspNowDirectPairProof(PSTR("ESP-NOW direct scan"), expected);
  if (!EspNowDirectEqual(expected, body, ESPNOW_DIRECT_PROOF_SIZE)) {
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing refused, the device's proof does not match"));
    EspNowDirectPairReport(PSTR("Failed"), PSTR("Proof"));
    EspNowDirectWindowFree();
    return;
  }
  EspNowDirectPairProof(PSTR("ESP-NOW direct recorded"), p->recorded_proof);
  p->saved = false;
  p->told = false;
  p->next = millis();
  EspNowDirectPairPhase(ESPNOW_PAIR_RECORDED);
}

static void EspNowDirectWindowTick(void) {
  EspNowDirectPair_t* p = EspNowPair;

  if ((ESPNOW_PAIR_SESSION == p->phase) && TimeReached(p->session_until)) {
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing session timed out"));
    EspNowDirectPairReport(PSTR("Failed"), PSTR("Timeout"));
    EspNowDirectWindowFree();
  }

  if (ESPNOW_PAIR_RECORDED == p->phase) {
    if (!p->saved) {
      // The device paired before learns it was replaced, over the link it still
      // has, and the frame leaves before that link goes, at the next tick
      if (!p->told && EspNowDirect.active && EspNowDirect.peer_known && memcmp(EspNowDirectSettings.peer_mac, p->other_mac, 6)) {
        EspNowDirectSend(ESPNOW_DIRECT_TYPE_TAKEN, nullptr, 0);
        p->told = true;
        return;
      }
      EspNowDirectPairSave(p->other_mac);
      p->saved = true;
      p->session_until = millis() + ESPNOW_DIRECT_RECONFIRM_MS;
      p->next = millis();
    }
    // Confirmed again until the device greets on the new key, or for a while
    if ((EspNowDirect.active && EspNowDirect.peer_known) || TimeReached(p->session_until)) {
      EspNowDirectWindowFree();
    } else if (TimeReached(p->next)) {
      EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_RECORDED, p->other_mac, p->recorded_proof, sizeof(p->recorded_proof));
      p->next = millis() + ESPNOW_DIRECT_RECORDED_EVERY_MS;
    }
  }

  if (!TimeReached(p->window_until)) {
    if (TimeReached(p->announce_at)) {
      EspNowDirectAnnounce();
      p->announce_at = millis() + ESPNOW_DIRECT_ANNOUNCE_MS;
    }
  } else if (ESPNOW_PAIR_WINDOW == p->phase) {
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing window closed"));
    EspNowDirectPairReport(PSTR("Window"), PSTR("Closed"));
    EspNowDirectPairEnd();
  }
}

/*********************************************************************************************\
 * Pairing: the scan
\*********************************************************************************************/

// Moves the radio for the scan, unless the station holds it: then the station's
// channel is the one, and the pause that moving it needs comes first.
static void EspNowDirectScanChannel(uint8_t channel) {
  uint8_t sta;
  if (!channel || EspNowDirectStationChannel(&sta)) { return; }
  if (EspNowDirectRadioChannel() != channel) { esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE); }
}

// Goes to the channel of the device picked and stays there to the end: on the
// station's own, nothing moves; anywhere else, the WiFi pauses first.
static void EspNowDirectScanGoTo(uint8_t channel) {
  uint8_t sta;
  bool associated = EspNowDirectStationChannel(&sta);
  if (associated && (sta == channel)) {
    EspNowPair->target = 0;
    return;
  }
  if (associated || Settings->flag4.network_wifi) { StaCtrlRadioPause(); }
  EspNowPair->target = channel;
  EspNowDirectScanChannel(channel);
}

static void EspNowDirectScanDone(void) {
  EspNowDirectPairPhase(ESPNOW_PAIR_HEARD);
  EspNowPair->linger_until = millis() + ESPNOW_DIRECT_LINGER_MS;
  Response_P(PSTR("{\"EspNowPair\":{\"Scan\":\"Done\",\"Count\":%u}}"), EspNowPair->heard_count);
  XdrvRulesProcess(0);
}

static void EspNowDirectSweepStart(void) {
  EspNowPair->home = EspNowDirectRadioChannel();
  EspNowPair->sweep = 0;
  EspNowPair->next = millis();
  EspNowDirectPairPhase(ESPNOW_PAIR_SWEEP);
  StaCtrlRadioPause();
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Nothing heard on channel %d, looking on every channel"), EspNowPair->home);
  EspNowDirectPairReport(PSTR("Scan"), PSTR("Sweeping"));
}

// Back to the list after a session that did not pair: its keys gone, and the
// WiFi as it was
static void EspNowDirectScanBack(void) {
  EspNowDirectPairForget();
  EspNowPair->target = 0;
  EspNowDirectPairPhase(ESPNOW_PAIR_HEARD);
  EspNowPair->linger_until = millis() + ESPNOW_DIRECT_LINGER_MS;
  StaCtrlRadioResume();
}

static void EspNowDirectScanFailed(const char* why) {
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing failed, %s"), why);
  EspNowDirectPairReport(PSTR("Failed"), why);
  EspNowDirectScanBack();
}

// Keeps what an announcement says, by key. The first address a key is heard
// from keeps it: a copy of the announcement from elsewhere changes nothing.
// A name keeps printable ASCII only, and none of the two characters JSON escapes.
// With the list full, a device heard stronger than the weakest takes its place
// and its id, while the scan listens: with more devices announcing at once than
// the list holds, the nearest are kept, and not the first heard. Once the scan
// is over, the ids are what the user picks by, and they stay put.
static void EspNowDirectHeard(const EspNowDirectRxItem_t* item);
static void EspNowDirectHeard(const EspNowDirectRxItem_t* item) {
  EspNowDirectPair_t* p = EspNowPair;
  const uint8_t* body = &item->data[7];
  size_t len = item->len - 7;
  if (memcmp(&item->data[1], EspNowDirectBroadcast, 6) || (len < 35) || (len > 35 + ESPNOW_DIRECT_NAME_SIZE)) { return; }
  if (!body[1] || (body[1] > 14)) { return; }
  const uint8_t* key = &body[3];

  EspNowDirectHeard_t* h = nullptr;
  for (uint32_t i = 0; i < p->heard_count; i++) {
    if (!memcmp(p->heard[i].key, key, 32)) { h = &p->heard[i]; break; }
  }
  bool fresh = (nullptr == h);
  char replaced[18] = "";
  if (fresh) {
    if (p->heard_count < ESPNOW_DIRECT_HEARD_MAX) {
      h = &p->heard[p->heard_count++];
    } else {
      if ((ESPNOW_PAIR_LISTEN != p->phase) && (ESPNOW_PAIR_SWEEP != p->phase)) { return; }
      h = &p->heard[0];
      for (uint32_t i = 1; i < p->heard_count; i++) {
        if (p->heard[i].rssi < h->rssi) { h = &p->heard[i]; }
      }
      if (item->rssi <= h->rssi) { return; }
      EspNowDirectMacText(h->mac, replaced);
      memset(h, 0, sizeof(EspNowDirectHeard_t));
    }
    memcpy(h->key, key, 32);
    memcpy(h->mac, item->mac, 6);
    h->rssi = item->rssi;
  } else if (memcmp(h->mac, item->mac, 6)) {
    return;
  }
  if (item->rssi > h->rssi) { h->rssi = item->rssi; }
  h->version = item->data[0];
  h->flags = body[0];
  h->channel = body[1];
  h->zigbee = body[2];
  size_t name_len = len - 35;
  for (uint32_t i = 0; i < name_len; i++) {
    uint8_t c = body[35 + i];
    h->name[i] = ((c >= 0x20) && (c < 0x7F) && ('"' != c) && ('\\' != c)) ? c : '?';
  }
  h->name[name_len] = '\0';
  if (!fresh) { return; }

  char text[18];
  EspNowDirectMacText(h->mac, text);
  if (replaced[0]) {
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: Heard %s on channel %d, in the place of %s"), text, h->channel, replaced);
  } else {
    AddLog(LOG_LEVEL_INFO, PSTR("ENW: Heard %s on channel %d"), text, h->channel);
  }
  Response_P(PSTR("{\"EspNowPair\":{\"Heard\":{\"Id\":%u,\"Mac\":\"%s\",\"Rssi\":%d,\"Channel\":%u,\"Version\":%u,"
                  "\"Name\":\"%s\",\"Zigbee\":%u,\"Network\":%u,\"Busy\":%u}}}"),
    (uint32_t)(h - p->heard) + 1, text, h->rssi, h->channel, h->version, h->name, h->zigbee,
    (h->flags & ESPNOW_DIRECT_ANNOUNCE_NETWORK) ? 1 : 0, (h->flags & ESPNOW_DIRECT_ANNOUNCE_BUSY) ? 1 : 0);
  XdrvRulesProcess(0);
}

static void EspNowDirectScanReceive(const EspNowDirectRxItem_t* item);
static void EspNowDirectScanReceive(const EspNowDirectRxItem_t* item) {
  EspNowDirectPair_t* p = EspNowPair;
  if (ESPNOW_DIRECT_TYPE_ANNOUNCE == item->type) {
    EspNowDirectHeard(item);
    return;
  }
  uint8_t own[6];
  EspNowDirectOwnMac(own);
  if (memcmp(&item->data[1], own, 6)) { return; }           // for another device
  EspNowDirectHeard_t* h = &p->heard[p->chosen];
  if (memcmp(item->mac, h->mac, 6)) { return; }             // not from the device picked
  const uint8_t* body = &item->data[7];
  size_t len = item->len - 7;

  switch (item->type) {
    case ESPNOW_DIRECT_TYPE_PAIR_STATUS:
      if ((33 != len) || memcmp(body, h->key, 32)) { return; }
      if (ESPNOW_DIRECT_STATUS_BUSY == body[32]) {
        EspNowDirectScanFailed(PSTR("Busy"));
        return;
      }
      if ((ESPNOW_PAIR_BLINK == p->phase) && !p->blinking) {
        p->blinking = true;
        EspNowDirectPairReportMac(PSTR("Blinking"), h->mac);
      }
      return;

    case ESPNOW_DIRECT_TYPE_PAIR_ACK: {
      if ((ESPNOW_PAIR_EXCHANGE != p->phase) || (ESPNOW_DIRECT_NONCE_SIZE + ESPNOW_DIRECT_PROOF_SIZE != len)) { return; }
      memcpy(p->other_nonce, body, ESPNOW_DIRECT_NONCE_SIZE);
      if (!EspNowDirectPairDerive(own, h->mac, p->own_public, h->key, p->own_nonce, p->other_nonce, h->key)) {
        EspNowDirectScanFailed(PSTR("Key"));
        return;
      }
      uint8_t expected[ESPNOW_DIRECT_PROOF_SIZE];
      EspNowDirectPairProof(PSTR("ESP-NOW direct window"), expected);
      if (!EspNowDirectEqual(expected, &body[ESPNOW_DIRECT_NONCE_SIZE], ESPNOW_DIRECT_PROOF_SIZE)) {
        // Not from the device that announced this key, or not for this exchange
        EspNowDirectScanFailed(PSTR("Proof"));
        return;
      }
      EspNowDirectPairProof(PSTR("ESP-NOW direct scan"), p->proof);
      EspNowDirectPairProof(PSTR("ESP-NOW direct recorded"), p->recorded_proof);
      p->next = millis();
      p->session_until = millis() + ESPNOW_DIRECT_RECONFIRM_MS;   // as long as the window confirms
      EspNowDirectPairPhase(ESPNOW_PAIR_CONFIRM);
      return;
    }

    case ESPNOW_DIRECT_TYPE_RECORDED:
      if ((ESPNOW_PAIR_CONFIRM != p->phase) || (ESPNOW_DIRECT_PROOF_SIZE != len)) { return; }
      if (!EspNowDirectEqual(p->recorded_proof, body, ESPNOW_DIRECT_PROOF_SIZE)) { return; }   // the right one may still come
      EspNowDirectPairSave(h->mac);
      EspNowDirectPairPhase(ESPNOW_PAIR_PAIRED);
      p->linger_until = millis() + ESPNOW_DIRECT_LINGER_MS;
      return;
  }
}

// The identification, or the keys, asked of the device picked, again until it
// answers, and a failure after ESPNOW_DIRECT_TRIES
static void EspNowDirectScanAsk(void) {
  EspNowDirectPair_t* p = EspNowPair;
  if (!TimeReached(p->next)) { return; }
  if (p->tries >= ESPNOW_DIRECT_TRIES) {
    EspNowDirectScanFailed(PSTR("NoAnswer"));
    return;
  }
  p->tries++;
  p->next = millis() + ESPNOW_DIRECT_RETRY_MS;
  EspNowDirectHeard_t* h = &p->heard[p->chosen];
  if (ESPNOW_PAIR_BLINK == p->phase) {
    EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_BLINK, h->mac, h->key, 32);
    return;
  }
  uint8_t body[32 + 32 + ESPNOW_DIRECT_NONCE_SIZE];
  memcpy(body, h->key, 32);
  memcpy(&body[32], p->own_public, 32);
  memcpy(&body[64], p->own_nonce, ESPNOW_DIRECT_NONCE_SIZE);
  EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_PAIR_REQ, h->mac, body, sizeof(body));
}

static void EspNowDirectScanTick(void) {
  EspNowDirectPair_t* p = EspNowPair;

  // A pause of the WiFi, or its stack starting again, may leave the radio elsewhere
  if (p->target && (p->phase >= ESPNOW_PAIR_BLINK)) { EspNowDirectScanChannel(p->target); }

  switch (p->phase) {
    case ESPNOW_PAIR_LISTEN:
      if (TimeReached(p->next)) {
        if (p->heard_count) {
          EspNowDirectScanDone();
        } else {
          EspNowDirectSweepStart();
        }
      }
      break;

    case ESPNOW_PAIR_SWEEP:
      if (!TimeReached(p->next)) { break; }
      if (p->sweep >= ESPNOW_DIRECT_HUNT_CHANNELS) {
        EspNowDirectScanChannel(p->home);
        StaCtrlRadioResume();
        EspNowDirectScanDone();
        break;
      }
      p->sweep++;
      EspNowDirectScanChannel(p->sweep);
      p->next = millis() + ESPNOW_DIRECT_DWELL_MS;
      break;

    case ESPNOW_PAIR_HEARD:
    case ESPNOW_PAIR_PAIRED:
      if (TimeReached(p->linger_until)) {
        EspNowDirectPairReport(PSTR("Ended"), PSTR("Timeout"));
        EspNowDirectPairEnd();
      }
      break;

    case ESPNOW_PAIR_BLINK:
      if (!p->blinking) {
        EspNowDirectScanAsk();
      } else if (TimeReached(p->session_until)) {
        EspNowDirectScanFailed(PSTR("Timeout"));
      }
      break;

    case ESPNOW_PAIR_EXCHANGE:
      EspNowDirectScanAsk();
      break;

    case ESPNOW_PAIR_CONFIRM:
      if (TimeReached(p->session_until)) {
        EspNowDirectScanFailed(PSTR("NotConfirmed"));
        break;
      }
      if (TimeReached(p->next)) {
        EspNowDirectPairSend(ESPNOW_DIRECT_TYPE_PAIR_PROOF, p->heard[p->chosen].mac, p->proof, sizeof(p->proof));
        p->next = millis() + ESPNOW_DIRECT_RETRY_MS;
      }
      break;
  }
}

/*********************************************************************************************\
 * Pairing: the main loop's part
\*********************************************************************************************/

static void EspNowDirectPairReceive(const EspNowDirectRxItem_t* item);
static void EspNowDirectPairReceive(const EspNowDirectRxItem_t* item) {
  if (!EspNowPair || (item->len < 7)) { return; }
  // An announcement of another version is listed, for the application to say
  // which side needs an update; nothing else of one is taken
  if ((ESPNOW_DIRECT_TYPE_ANNOUNCE != item->type) && (ESPNOW_DIRECT_PROTOCOL != item->data[0])) { return; }
  if (EspNowPair->window) {
    EspNowDirectWindowReceive(item);
  } else {
    EspNowDirectScanReceive(item);
  }
}

static void EspNowDirectPairTick(void) {
  if (!EspNowPair) { return; }
  // The WiFi Manager took the radio, as the one that wins over everything
  if (STA_RADIO_WIFI_MANAGER == StaCtrlRadioOwner()) {
    EspNowDirectPairReport(PSTR("Failed"), PSTR("Radio"));
    EspNowDirectPairEnd();
    return;
  }
  if (!EspNowDirectRecover()) { return; }  // the WiFi stack is not back yet
  if (!EspNowDirect.radio) {
    if (!EspNowDirectRadioReady() || !EspNowDirectRadioStart()) { return; }
  }
  if (EspNowPair->window) {
    EspNowDirectWindowTick();
  } else {
    EspNowDirectScanTick();
  }
}

/*********************************************************************************************\
 * Pairing: commands
\*********************************************************************************************/

void CmndEspNowPairOpen(void) {
  if (XdrvMailbox.data_len > 0) {
    uint32_t seconds = strtoul(XdrvMailbox.data, nullptr, 10);
    const char* comma = strchr(XdrvMailbox.data, ',');
    uint32_t zigbee = comma ? strtoul(comma + 1, nullptr, 10) : 0;
    if (!seconds || (seconds > ESPNOW_DIRECT_WINDOW_MAX_S) || (zigbee > 26)) {
      ResponseCmndError();
      return;
    }
    if (EspNowPair && !EspNowPair->window) {
      ResponseCmndChar_P(PSTR("Scanning"));
      return;
    }
    if (!EspNowPair) {
      if (!EspNowDirectPairBegin(true)) {
        EspNowDirectPairBusy();
        return;
      }
      if (!EspNowDirectKeyPair(EspNowPair->own_secret, EspNowPair->own_public)) {
        EspNowDirectPairEnd();
        ResponseCmndError();
        return;
      }
      EspNowDirectPairPhase(ESPNOW_PAIR_WINDOW);
      // A station retrying a network it does not reach moves the channel under the window
      uint8_t sta;
      if (Settings->flag4.network_wifi && !EspNowDirectStationChannel(&sta)) { StaCtrlRadioPause(); }
      AddLog(LOG_LEVEL_INFO, PSTR("ENW: Pairing window open for %u s"), seconds);
    }
    EspNowPair->zigbee = zigbee;
    EspNowPair->window_until = millis() + seconds * 1000;
    EspNowPair->announce_at = millis();
  }
  bool open = EspNowPair && EspNowPair->window && !TimeReached(EspNowPair->window_until);
  ResponseCmndChar_P(open ? PSTR("Open") : PSTR("Closed"));
}

void CmndEspNowPairScan(void) {
  if (EspNowPair && EspNowPair->window) {
    ResponseCmndChar_P(PSTR("Window open"));
    return;
  }
  if (EspNowPair) {
    // A new scan forgets the last one, with the WiFi as it was
    EspNowDirectPairForget();
    EspNowPair->target = 0;
    StaCtrlRadioResume();
  } else if (!EspNowDirectPairBegin(false)) {
    EspNowDirectPairBusy();
    return;
  }
  EspNowPair->heard_count = 0;
  if (2 == XdrvMailbox.payload) {
    EspNowDirectSweepStart();
  } else {
    EspNowPair->next = millis() + ESPNOW_DIRECT_LISTEN_MS;
    EspNowDirectPairPhase(ESPNOW_PAIR_LISTEN);
  }
  ResponseCmndChar_P(PSTR("Started"));
}

void CmndEspNowPairHeard(void) {
  Response_P(PSTR("{\"%s\":["), XdrvMailbox.command);
  if (EspNowPair && !EspNowPair->window) {
    EspNowDirectPair_t* p = EspNowPair;
    uint8_t order[ESPNOW_DIRECT_HEARD_MAX];
    for (uint32_t i = 0; i < p->heard_count; i++) { order[i] = i; }
    for (uint32_t i = 0; i < p->heard_count; i++) {
      for (uint32_t j = i + 1; j < p->heard_count; j++) {
        if (p->heard[order[j]].rssi > p->heard[order[i]].rssi) { uint8_t t = order[i]; order[i] = order[j]; order[j] = t; }
      }
    }
    for (uint32_t i = 0; i < p->heard_count; i++) {
      EspNowDirectHeard_t* h = &p->heard[order[i]];
      char text[18];
      EspNowDirectMacText(h->mac, text);
      ResponseAppend_P(PSTR("%s{\"Id\":%u,\"Mac\":\"%s\",\"Rssi\":%d,\"Channel\":%u,\"Version\":%u,\"Name\":\"%s\","
                            "\"Zigbee\":%u,\"Network\":%u,\"Busy\":%u}"),
        i ? "," : "", order[i] + 1, text, h->rssi, h->channel, h->version, h->name, h->zigbee,
        (h->flags & ESPNOW_DIRECT_ANNOUNCE_NETWORK) ? 1 : 0, (h->flags & ESPNOW_DIRECT_ANNOUNCE_BUSY) ? 1 : 0);
    }
  }
  ResponseAppend_P(PSTR("]}"));
}

void CmndEspNowPairBlink(void) {
  EspNowDirectPair_t* p = EspNowPair;
  if (!p || p->window) {
    ResponseCmndChar_P(PSTR("Not scanning"));
    return;
  }
  if ((ESPNOW_PAIR_LISTEN == p->phase) || (ESPNOW_PAIR_SWEEP == p->phase)) {
    ResponseCmndChar_P(PSTR("Scanning"));
    return;
  }
  uint32_t id = XdrvMailbox.payload;
  if ((id < 1) || (id > p->heard_count)) {
    ResponseCmndError();
    return;
  }
  if (ESPNOW_DIRECT_PROTOCOL != p->heard[id - 1].version) {
    ResponseCmndChar_P(PSTR("Version"));
    return;
  }
  EspNowDirectPairForget();
  p->chosen = id - 1;
  p->tries = 0;
  p->next = millis();
  p->session_until = millis() + ESPNOW_DIRECT_SESSION_MS;
  EspNowDirectPairPhase(ESPNOW_PAIR_BLINK);
  EspNowDirectScanGoTo(p->heard[p->chosen].channel);
  ResponseCmndChar_P(PSTR("Started"));
}

void CmndEspNowPairWith(void) {
  EspNowDirectPair_t* p = EspNowPair;
  if (!p || p->window || (ESPNOW_PAIR_BLINK != p->phase) || (XdrvMailbox.payload != p->chosen + 1)) {
    ResponseCmndChar_P(PSTR("Blink first"));
    return;
  }
  if (!EspNowDirectKeyPair(p->own_secret, p->own_public)) {
    ResponseCmndError();
    return;
  }
  esp_fill_random(p->own_nonce, ESPNOW_DIRECT_NONCE_SIZE);
  p->tries = 0;
  p->next = millis();
  EspNowDirectPairPhase(ESPNOW_PAIR_EXCHANGE);
  ResponseCmndChar_P(PSTR("Started"));
}

void CmndEspNowPairStop(void) {
  bool running = EspNowDirectPairing();
  EspNowDirectPairEnd();
  ResponseCmndChar_P(running ? PSTR("Stopped") : PSTR("Idle"));
}
#endif  // USE_ESPNOW_DIRECT_PAIRING

#ifdef USE_WIFI_STATION_CONTROL
/*********************************************************************************************\
 * The saved network, handed over the link
\*********************************************************************************************/

#define ESPNOW_DIRECT_WIFI_KEEP_MS     120000 // an offer not taken by then is dropped

// The network the peer offered, on the heap only while it is kept. Its name is
// reported; the password stays here until the join takes it.
typedef struct {
  char ssid[33];
  char password[65];
  uint32_t until;
} EspNowDirectWifiOffer_t;

static EspNowDirectWifiOffer_t* EspNowDirectOffer = nullptr;

static void EspNowDirectWifiDrop(void) {
  if (!EspNowDirectOffer) { return; }
  EspNowDirectWipe(EspNowDirectOffer, sizeof(EspNowDirectWifiOffer_t));
  free(EspNowDirectOffer);
  EspNowDirectOffer = nullptr;
}

// An offer not taken in ESPNOW_DIRECT_WIFI_KEEP_MS goes
static void EspNowDirectWifiExpire(void) {
  if (!EspNowDirectOffer || !TimeReached(EspNowDirectOffer->until)) { return; }
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: The peer's network was not taken, dropped"));
  EspNowDirectWifiDrop();
}

// ssid_len(1) | ssid(1..32) | password_len(1) | password(0, or 8..64)
static void EspNowDirectWifiOffered(const uint8_t* data, size_t len) {
  if (len < 3) { return; }
  size_t ssid_len = data[0];
  if (!ssid_len || (ssid_len > 32) || (ssid_len + 2 > len)) { return; }
  size_t password_len = data[1 + ssid_len];
  if ((password_len && (password_len < 8)) || (password_len > 64) || (2 + ssid_len + password_len != len)) { return; }
  if (!EspNowDirectOffer) {
    EspNowDirectOffer = (EspNowDirectWifiOffer_t*)calloc(1, sizeof(EspNowDirectWifiOffer_t));
    if (!EspNowDirectOffer) { return; }
  }
  memset(EspNowDirectOffer, 0, sizeof(EspNowDirectWifiOffer_t));
  memcpy(EspNowDirectOffer->ssid, &data[1], ssid_len);
  memcpy(EspNowDirectOffer->password, &data[2 + ssid_len], password_len);
  EspNowDirectOffer->until = millis() + ESPNOW_DIRECT_WIFI_KEEP_MS;
  AddLog(LOG_LEVEL_INFO, PSTR("ENW: The peer offers its network %s"), EspNowDirectOffer->ssid);
  Response_P(PSTR("{\"EspNowDirect\":{\"WifiOffered\":\"%s\"}}"), EscapeJSONString(EspNowDirectOffer->ssid).c_str());
  XdrvRulesProcess(0);
}

// The saved network this device is on, or the one the command names, to the
// peer: only over a link that is up, which is encrypted, and never repeated back
void CmndEspNowGiveWifi(void) {
  if (!EspNowDirect.active || !EspNowDirect.peer_known) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  char ssid[33] = { 0 };
  char password[65] = { 0 };
  bool named = (XdrvMailbox.data_len > 0);
  bool fits = true;
  if (named) {
    JsonParser parser(XdrvMailbox.data);
    JsonParserObject root = parser.getRootObject();
    if (!root) {
      EspNowDirectWipe(XdrvMailbox.data, XdrvMailbox.data_len);
      ResponseCmndError();
      return;
    }
    const char* name = root.getStr(PSTR("SSId"), "");
    const char* key = root.getStr(PSTR("Password"), "");
    fits = (strlen(name) <= 32) && (strlen(key) <= 64);
    if (fits) {
      strlcpy(ssid, name, sizeof(ssid));
      strlcpy(password, key, sizeof(password));
    }
    // the command's buffer held the password: parsed in place, and wiped
    EspNowDirectWipe(XdrvMailbox.data, XdrvMailbox.data_len);
  } else {
    uint32_t active = Settings->sta_active ? 1 : 0;
    fits = (strlen(SettingsText(SET_STASSID1 + active)) <= 32) && (strlen(SettingsText(SET_STAPWD1 + active)) <= 64);
    if (fits) {
      strlcpy(ssid, SettingsText(SET_STASSID1 + active), sizeof(ssid));
      strlcpy(password, SettingsText(SET_STAPWD1 + active), sizeof(password));
    }
  }
  size_t ssid_len = strlen(ssid);
  size_t password_len = strlen(password);
  // the peer takes no password of 1 to 7 characters, which WPA does not allow
  if (!fits || (password_len && (password_len < 8))) {
    EspNowDirectWipe(password, sizeof(password));
    ResponseCmndError();
    return;
  }
  if (!ssid_len) {
    EspNowDirectWipe(password, sizeof(password));
    ResponseCmndChar_P(PSTR("no network"));
    return;
  }
  uint8_t payload[2 + 32 + 64];
  payload[0] = ssid_len;
  memcpy(&payload[1], ssid, ssid_len);
  payload[1 + ssid_len] = password_len;
  memcpy(&payload[2 + ssid_len], password, password_len);
  bool sent = EspNowDirectSend(ESPNOW_DIRECT_TYPE_WIFI, payload, 2 + ssid_len + password_len);
  EspNowDirectWipe(payload, sizeof(payload));
  EspNowDirectWipe(password, sizeof(password));
  ResponseCmndChar_P(sent ? PSTR("sent") : PSTR("failed"));
}

// The network the peer offered, joined; kept while the radio is busy, so the
// application may try again once it is free. 0 drops it.
void CmndEspNowTakeWifi(void) {
  if (!EspNowDirectOffer) {
    ResponseCmndChar_P(PSTR("no offer"));
    return;
  }
  if (0 == XdrvMailbox.payload) {
    EspNowDirectWifiDrop();
    ResponseCmndChar_P(PSTR("dropped"));
    return;
  }
  uint32_t result = StaCtrlJoin(EspNowDirectOffer->ssid, EspNowDirectOffer->password, 0, nullptr);
  if (STA_JOIN_BUSY == result) {
    ResponseCmndChar_P(PSTR("Busy"));
    return;
  }
  EspNowDirectWifiDrop();
  ResponseCmndChar_P((STA_JOIN_STARTED == result) ? PSTR("Joining") : PSTR("Error"));
}
#endif  // USE_WIFI_STATION_CONTROL

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
    } else if (!EspNowDirectPairKeepsLink()) {
      EspNowDirectStop();        // a pairing that saved its record keeps the link up until it ends
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
  if (EspNowDirectWanted()) {
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

// Never echoes the key. Index 2 (EspNowSecret2) is the silent form, matching
// how the other secret-bearing commands in the firmware behave.
void CmndEspNowSecret(void) {
  bool show_asterisk = (2 == XdrvMailbox.index);
  if (XdrvMailbox.data_len > 0) {
    uint32_t len = XdrvMailbox.data_len;
    if (len > ESPNOW_DIRECT_KEY_SIZE) { len = ESPNOW_DIRECT_KEY_SIZE; }
    memset(EspNowDirectSettings.key, 0, ESPNOW_DIRECT_KEY_SIZE);
    if (SC_CLEAR == Shortcut()) {
      EspNowDirectSettings.key_len = 0;
    } else {
      memcpy(EspNowDirectSettings.key, XdrvMailbox.data, len);
      EspNowDirectSettings.key_len = len;
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

// Kept with the pairing for the application, which the link itself does not read
void CmndEspNowPeerMode(void) {
  if ((XdrvMailbox.data_len > 0) && (XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 255)) {
    EspNowDirectSettings.mode = XdrvMailbox.payload;
    EspNowDirectSettingsSave();
  }
  ResponseCmndNumber(EspNowDirectSettings.mode);
}

void CmndEspNowPeerConfig(void) {
  if (XdrvMailbox.data_len > 0) {
    EspNowDirectSettings.config = strtoul(XdrvMailbox.data, nullptr, 0);
    EspNowDirectSettingsSave();
  }
  Response_P(PSTR("{\"%s\":%u}"), XdrvMailbox.command, EspNowDirectSettings.config);
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
      case ESPNOW_DIRECT_DO_HELLO:
        EspNowDirectSendHello(EspNowDirectGet32(&item.data[4]), EspNowDirectGet32(&item.data[0]));
        break;
      case ESPNOW_DIRECT_DO_PEER_UP:
        EspNowDirect.reported_version = 0;
        Response_P(PSTR("{\"EspNowDirect\":{\"PeerUp\":\"%08X\"}}"), EspNowDirect.peer_session);
        XdrvRulesProcess(0);
        break;
      case ESPNOW_DIRECT_DO_VERSION:
        if (item.data[0] == EspNowDirect.reported_version) { break; }
        EspNowDirect.reported_version = item.data[0];
        AddLog(LOG_LEVEL_INFO, PSTR("ENW: The peer speaks protocol version %u, this device %u"), item.data[0], ESPNOW_DIRECT_PROTOCOL);
        Response_P(PSTR("{\"EspNowDirect\":{\"PeerVersion\":%u}}"), item.data[0]);
        XdrvRulesProcess(0);
        break;
      case ESPNOW_DIRECT_TYPE_PING:
        EspNowDirectSend(ESPNOW_DIRECT_TYPE_PONG, item.data, item.len);
        break;
      case ESPNOW_DIRECT_TYPE_EVENT:
        Response_P(PSTR("%s"), (const char*)item.data);
        XdrvRulesProcess(0);
        break;
#ifdef USE_WIFI_STATION_CONTROL
      case ESPNOW_DIRECT_TYPE_WIFI:
        EspNowDirectWifiOffered(item.data, item.len);
        EspNowDirectWipe(item.data, sizeof(item.data));   // the password was in it
        break;
#endif
      case ESPNOW_DIRECT_TYPE_TAKEN:
        AddLog(LOG_LEVEL_INFO, PSTR("ENW: The peer paired with another device"));
        Response_P(PSTR("{\"EspNowDirect\":{\"Taken\":1}}"));
        XdrvRulesProcess(0);
        break;
      case ESPNOW_DIRECT_TYPE_CMD:
#if defined(USE_ESPNOW_DIRECT_EVENTS_ONLY)
        AddLog(LOG_LEVEL_INFO, PSTR("ENW: Command from the peer dropped, this device takes events only"));
#elif defined(USE_ESPNOW_DIRECT_COMMANDS_TO_RULES)
        Response_P(PSTR("{\"EspNowDirect\":{\"Command\":\"%s\"}}"), EscapeJSONString((const char*)item.data).c_str());
        XdrvRulesProcess(0);
#else
        ExecuteCommand((const char*)item.data, SRC_RULE);
#endif
        break;
      default:
#ifdef USE_ESPNOW_DIRECT_PAIRING
        if (EspNowDirectPairBit(item.type)) { EspNowDirectPairReceive(&item); }
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

// A key of the pair's for what the application signs another way, such as its
// messages over the access point:
//
//   espnow_key(label)        -> bytes(32), or nil with no pair
//
// It is HMAC-SHA256 of the label under the pair's key, behind a prefix none of
// the link's own derivations uses, so it changes with every pairing and gives
// the pair's key away to nobody: that key never reaches a script.
int EspNowDirectBerryKey(struct bvm *vm);
int EspNowDirectBerryKey(struct bvm *vm) {
  int32_t argc = be_top(vm);
  if ((argc >= 1) && be_isstring(vm, 1)) {
    static const char prefix[] = "ESP-NOW direct app ";
    const char* label = be_tostring(vm, 1);
    size_t label_len = strlen(label);
    uint8_t message[sizeof(prefix) - 1 + 64];
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!EspNowDirectSettings.key_len || (label_len > 64) || (nullptr == info)) { be_return_nil(vm); }
    memcpy(message, prefix, sizeof(prefix) - 1);
    memcpy(&message[sizeof(prefix) - 1], label, label_len);
    uint8_t digest[32];
    if (mbedtls_md_hmac(info, EspNowDirectSettings.key, EspNowDirectSettings.key_len,
                        message, sizeof(prefix) - 1 + label_len, digest)) {
      be_return_nil(vm);
    }
    be_pushbytes(vm, digest, sizeof(digest));
    EspNowDirectWipe(digest, sizeof(digest));
    be_return(vm);
  }
  be_raise(vm, kTypeError, nullptr);
}

static void EspNowDirectBerryRegister(void) {
  if (nullptr == berry.vm) { return; }
  be_pushntvfunction(berry.vm, EspNowDirectBerrySend);
  be_setglobal(berry.vm, "espnow_send");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowDirectBerryKey);
  be_setglobal(berry.vm, "espnow_key");
  be_pop(berry.vm, 1);
}
#endif  // USE_BERRY

void CmndEspNowStatus(void) {
  char mac_text[18];
  ToHex_P(EspNowDirectSettings.peer_mac, 6, mac_text, sizeof(mac_text), ':');
#ifdef USE_ESPNOW_DIRECT_PAIRING
  const char* pairing = EspNowDirectPairPhaseText();
#else
  const char* pairing = PSTR("");
#endif
  // Quiet: seconds since the peer's last frame, and Rssi its signal, while the link is up
  bool heard = EspNowDirect.active && EspNowDirect.peer_known;
  Response_P(PSTR("{\"EspNowStatus\":{\"Active\":%d,\"Peer\":\"%s\",\"Channel\":%d,\"OnChannel\":%d,\"SecretSet\":%d,"
                  "\"Session\":\"%08X\",\"Sent\":%u,\"PeerKnown\":%d,\"PeerSession\":\"%08X\",\"PeerCounter\":%u,"
                  "\"Quiet\":%d,\"Rssi\":%d,"
                  "\"Version\":%u,\"PeerVersion\":%u,\"Epoch\":%u,\"Mode\":%u,\"Config\":%u,\"Pairing\":\"%s\",\"MaxPayload\":%u}}"),
    EspNowDirect.active, mac_text, EspNowDirectSettings.channel, EspNowDirect.applied_channel,
    (EspNowDirectSettings.key_len > 0), EspNowDirect.session_id,
    EspNowDirect.tx_counter, EspNowDirect.peer_known, EspNowDirect.peer_session, EspNowDirect.peer_counter,
    heard ? TimePassedSince(EspNowDirect.last_heard) / 1000 : -1, heard ? EspNowDirect.peer_rssi : 0,
    ESPNOW_DIRECT_PROTOCOL, EspNowDirect.peer_version,
    EspNowDirectSettings.epoch, EspNowDirectSettings.mode, EspNowDirectSettings.config, pairing, ESPNOW_DIRECT_MAX_PAYLOAD);
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
const char kEspNowDirectCommands[] PROGMEM = "|"
  "EspNowEnable|EspNowPeerMac|EspNowSecret|EspNowChannel|EspNowPeerMode|EspNowPeerConfig|"
  "EspNowSend|EspNowEvent|EspNowStatus|EspNowPing|EspNowForge|EspNowReplay"
#ifdef USE_WIFI_STATION_CONTROL
  "|EspNowGiveWifi|EspNowTakeWifi"
#endif
#ifdef USE_ESPNOW_DIRECT_PAIRING
  "|EspNowPairOpen|EspNowPairScan|EspNowPairHeard|EspNowPairBlink|EspNowPairWith|EspNowPairStop"
#endif
  ;
void (* const kEspNowDirectCommand[])(void) PROGMEM = {
  &CmndEspNowEnable, &CmndEspNowPeerMac, &CmndEspNowSecret, &CmndEspNowChannel, &CmndEspNowPeerMode, &CmndEspNowPeerConfig,
  &CmndEspNowSend, &CmndEspNowEvent, &CmndEspNowStatus, &CmndEspNowPing, &CmndEspNowForge, &CmndEspNowReplay,
#ifdef USE_WIFI_STATION_CONTROL
  &CmndEspNowGiveWifi, &CmndEspNowTakeWifi,
#endif
#ifdef USE_ESPNOW_DIRECT_PAIRING
  &CmndEspNowPairOpen, &CmndEspNowPairScan, &CmndEspNowPairHeard, &CmndEspNowPairBlink, &CmndEspNowPairWith, &CmndEspNowPairStop,
#endif
  };

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
#ifdef USE_ESPNOW_DIRECT_PAIRING
    case FUNC_EVERY_100_MSECOND:
      EspNowDirectPairTick();
      break;
#endif
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
