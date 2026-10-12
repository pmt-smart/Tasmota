/*
  xdrv_100_espnow_mesh.ino - ESP-NOW mesh: the radio task and the commands around the mesh core

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

#ifdef USE_ESPNOW_MESH
/*********************************************************************************************\
 * A mesh of devices over ESP-NOW: every device repeats what it hears, so that a command, a state
 * or an event gets across a house whose rooms are out of each other's range, and a frame can go
 * over the network the devices share as well, to the ones the radio does not reach.
 *
 * espnow_mesh_core.h decides what a frame is, which ones to repeat, when, where an answer goes and
 * what a sender does when none comes; espnow_mesh_crypto.h gives it the keys and the cipher. This
 * file is the part that touches the radio, the network and the flash: a task that runs the core,
 * hands it what the radio and the network hear, sends what it says to send and tells the main loop
 * what arrived; and the commands that set the device up.
 *
 * Neither the radio's callback nor the core runs on the main loop. The callback, on the WiFi task,
 * only copies the frame into a queue; the task owns the core and everything of it; and what the
 * main loop asks of the core, and what the core has to tell it, cross in queues too.
 *
 * The mesh and the direct link of xdrv_98 share the radio. ESP-NOW has one receive callback and one send
 * callback, and the direct link's are the ones in place when it runs: the direct link hands the mesh the
 * frames that are its own (the first byte of a mesh frame is not one of its types), tells it what became of
 * the frame it was sending, and tells it when ESP-NOW starts and stops, which are the hooks at the top of
 * xdrv_98. With the direct link not running the mesh starts ESP-NOW itself, and gives it up for the direct
 * link's when that starts. A frame the direct link sends while the mesh waits for the radio's word on its
 * own can have that word taken for the mesh's: a send is then counted as it was not, and the core handles
 * a send that is not acknowledged as it handles a lost frame.
 *
 * Born off, like the direct link: EspNowMeshEnable 1 starts it, and it stays on across restarts
 * once the device has a number (EspNowMeshId), the key of the network (EspNowMeshGroupKey) and
 * the nodes it talks to (EspNowMeshNode, with their public keys). The number, and the bits of
 * EspNowMeshNetwork that say no radio or relay, take effect at the next start; the other bit, the key
 * and the nodes at once. The key is a command argument, which Tasmota can log: set it over the web
 * API of a device on the LAN, as scripts/mesh-bench.mjs does, and not with the log level up. The device makes its own
 * identity, an X25519 key pair, the first time, and keeps it in its own NVS namespace; its public
 * key is what the other devices are given (EspNowMeshPublic).
 *
 * Reported to the rule engine, and in the log:
 *   {"EspNowMesh":{"From":3,"Type":0,"Dest":1,"Counter":12,"Epoch":7,"Rssi":-61,"Flags":0,"Part":0,"Joins":0,"Behind":0,"Data":"68656c6c6f"}}
 *       a frame for this device, Data in hex; Flags 1 asks for an answer, 2 marks a repeat of one already given;
 *       Behind is how many numbers of its origin the frame was behind the newest heard, for the application to order by
 *   {"EspNowMesh":{"Outcome":{"Counter":12,"Dest":3,"Ok":1,"Attempts":1}}}
 *       what became of a frame sent with an answer asked for
 *   {"EspNowMesh":{"Notice":{"Kind":"Silent","Node":3,"By":2,"Value":0}}}
 *       Silent, Back, Noisy, Calm, BulkDone, BulkLost
 *
 * Commands:
 *   EspNowMeshEnable 0|1       - stop/start, reports the state when called bare
 *   EspNowMeshId <1..254>      - this device's number in the network
 *   EspNowMeshChannel <0..13>  - the channel the radio goes to when the station is not associated; 0 leaves it
 *   EspNowMeshGroupKey <64 hex>[,<version>] - the key of the network, never echoed back
 *   EspNowMeshNode <id>,<mac>,<public key, 64 hex>[,<ip>] - a node of the network; <id>,0 forgets it; bare lists
 *   EspNowMeshPublic           - this device's public key
 *   EspNowMeshNetwork <bits>   - 1 also by the network (UDP), 2 no radio in use, 4 repeat on the network for the nodes with none
 *   EspNowMeshInfo <hex>       - up to 32 bytes that every heartbeat carries
 *   EspNowMeshSend <dest>,<type>,<ack 0|1>,<text or 0xHEX> - a frame; dest 255 is everyone; type 0 command, 2 state, 3 event
 *   EspNowMeshStatus           - the state of the task and the counters
 *   EspNowMeshNeighbors [<first>] - the neighbours the heartbeats have given, six at a time
\*********************************************************************************************/

#define XDRV_100                       100

#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <WiFiUdp.h>
#include "espnow_mesh_core.h"
#include "espnow_mesh_crypto.h"

#define ESPNOW_MESH_SETTINGS_VERSION   1
#define ESPNOW_MESH_NVS_NAMESPACE      "espnowmesh"
#define ESPNOW_MESH_NODES              16
#define ESPNOW_MESH_UDP_PORT           47474
#define ESPNOW_MESH_RX_DEPTH           8
#define ESPNOW_MESH_CMD_DEPTH          4
#define ESPNOW_MESH_EVENT_DEPTH        8
#define ESPNOW_MESH_TASK_STACK         6144
#define ESPNOW_MESH_TASK_PRIORITY      5
#define ESPNOW_MESH_SEND_WAIT_MS       20          // for the radio to say what became of a frame
#define ESPNOW_MESH_BEAT_MS            5000
#define ESPNOW_MESH_SNAPSHOT_MS        500
#define ESPNOW_MESH_SENDS_PER_TURN     4

#define ESPNOW_MESH_NET_UDP            1
#define ESPNOW_MESH_NET_NO_RADIO       2
#define ESPNOW_MESH_NET_RELAY          4

typedef struct {
  uint8_t id;                                // 0: the slot is free
  uint8_t mac[6];
  uint8_t pub[32];
  uint8_t ip[4];                             // 0.0.0.0: not known
} EspNowMeshNode_t;

// The device's record, saved as one block in its own NVS namespace
struct {
  uint32_t version;
  uint8_t enabled;
  uint8_t id;
  uint8_t channel;
  uint8_t network;                           // ESPNOW_MESH_NET_*
  uint32_t epoch;                            // rises with every start
  uint8_t has_secret;
  uint8_t has_group;
  uint8_t group_version;
  uint8_t spare;
  uint8_t secret[32];                        // the identity, X25519
  uint8_t group_key[32];
  EspNowMeshNode_t node[ESPNOW_MESH_NODES];
} EspNowMeshSettings;

// What the radio's callback hands the task
typedef struct {
  uint8_t len;
  uint8_t mac[6];
  int8_t rssi;
  uint8_t data[EspNowMesh::kMaxFrame];
} EspNowMeshRx_t;

// What the main loop asks of the core
#define ESPNOW_MESH_CMD_SEND           1       // type, dest, flags 1 = answer asked, data
#define ESPNOW_MESH_CMD_INFO           2       // data
typedef struct {
  uint8_t op;
  uint8_t type;
  uint8_t dest;
  uint8_t flags;
  uint8_t len;
  uint8_t data[EspNowMesh::kMaxPayload];
} EspNowMeshCmd_t;

// What the core has to tell the main loop
#define ESPNOW_MESH_EVT_DELIVERY       1
#define ESPNOW_MESH_EVT_OUTCOME        2
#define ESPNOW_MESH_EVT_NOTICE         3
typedef struct {
  uint8_t kind;
  uint8_t origin;                            // a delivery's origin; a notice's node
  uint8_t type;                              // a delivery's type; a notice's kind
  uint8_t flags;                             // a delivery's: 1 answer asked, 2 repeat; an outcome's: ok
  uint8_t part;
  uint8_t attempt;                           // a delivery's attempt; an outcome's attempts
  uint8_t behind;                            // a delivery's: how many numbers of its origin it was behind the newest heard
  uint8_t dest;                              // a delivery's, an outcome's; a notice's: by
  int8_t rssi;
  uint32_t counter;                          // an outcome's frame; a notice's value
  uint32_t epoch;
  uint32_t joins;
  uint8_t len;
  uint8_t data[EspNowMesh::kMaxPayload];
} EspNowMeshEvent_t;

typedef struct {
  uint8_t id;
  uint8_t state;
  uint8_t lists_me;
  uint8_t no_radio;
  int8_t rssi;
  int8_t their_rssi;
  uint16_t age_s;                            // since something of it got through
  uint16_t beat_s;                           // since its last heartbeat, 0xFFFF if none
  uint8_t hears;
  uint8_t info_len;
  uint8_t info[EspNowMesh::kMaxInfo];
} EspNowMeshNeighbor_t;

// What the task publishes for the status commands
typedef struct {
  uint32_t at;
  EspNowMesh::Stats stats;
  uint8_t queued;
  uint8_t waiting;
  uint8_t noisy;
  uint8_t loss;
  uint8_t neighbors;
  uint8_t silent_count;
  uint8_t silent[ESPNOW_MESH_NODES];
  uint16_t stack_free;
  bool net_up;
  EspNowMeshNeighbor_t neighbor[EspNowMesh::kMaxNeighbors];
} EspNowMeshSnapshot_t;

// What the main loop hands the task to apply: the nodes, the key of the network, how the network is used
typedef struct {
  uint8_t id;
  uint8_t network;
  uint8_t has_group;
  uint8_t group_version;
  uint8_t group_key[32];
  EspNowMeshNode_t node[ESPNOW_MESH_NODES];
} EspNowMeshShared_t;

static struct {
  bool running = false;                      // the task runs
  volatile bool stop = false;                // asked to end
  volatile bool accepting = false;           // the callbacks may put frames in the queue
  bool retry_wait = false;                   // a start that failed is not tried again before retry_at
  uint32_t retry_at = 0;
  volatile bool exited = false;
  volatile bool radio = false;               // ESP-NOW is up, whose it is
  volatile bool direct_radio = false;        // the direct link's driver started it, and its callbacks are the ones in place
  bool own_radio = false;                    // this driver started it
  volatile bool radio_lost = false;          // the WiFi stack stopped under ESP-NOW
  volatile bool awaiting = false;            // the task waits for the radio to say what became of a send
  volatile bool send_ok = false;
  volatile bool config_dirty = false;
  volatile uint32_t dropped = 0;             // frames the callback had no room for
  uint8_t applied_channel = 0;
  EspNowMesh::Node* node = nullptr;
  EspNowMesh::Crypto* crypto = nullptr;
  EspNowMeshSnapshot_t* snapshot = nullptr;
  EspNowMeshShared_t* shared = nullptr;
  QueueHandle_t rx = nullptr;
  QueueHandle_t cmd = nullptr;
  QueueHandle_t event = nullptr;
  SemaphoreHandle_t send_done = nullptr;
  SemaphoreHandle_t lock = nullptr;          // the shared copy and the snapshot
  TaskHandle_t task = nullptr;
} EspNowMeshDriver;

static const uint8_t EspNowMeshBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*********************************************************************************************\
 * Settings
\*********************************************************************************************/

static void EspNowMeshSettingsSave(void) {
  NvmSave(ESPNOW_MESH_NVS_NAMESPACE, "settings", &EspNowMeshSettings, sizeof(EspNowMeshSettings));
}

static void EspNowMeshSettingsLoad(void) {
  memset(&EspNowMeshSettings, 0, sizeof(EspNowMeshSettings));
  if (!NvmLoad(ESPNOW_MESH_NVS_NAMESPACE, "settings", &EspNowMeshSettings, sizeof(EspNowMeshSettings)) ||
      (ESPNOW_MESH_SETTINGS_VERSION != EspNowMeshSettings.version)) {
    memset(&EspNowMeshSettings, 0, sizeof(EspNowMeshSettings));
    EspNowMeshSettings.version = ESPNOW_MESH_SETTINGS_VERSION;
  }
}

static void EspNowMeshWipe(void* buffer, size_t len) {
  volatile uint8_t* p = (volatile uint8_t*)buffer;
  while (len--) { *p++ = 0; }
}

// Exactly `len` bytes of hex digits, and nothing in `out` unless it is so
static bool EspNowMeshHex(const char* text, uint8_t* out, size_t len) {
  if (strlen(text) != 2 * len) { return false; }
  for (size_t i = 0; i < 2 * len; i++) { if (!isxdigit((unsigned char)text[i])) { return false; } }
  uint8_t decoded[64];
  if ((len > sizeof(decoded)) || (HexToBytes(text, decoded, len) != (int32_t)len)) { return false; }
  memcpy(out, decoded, len);
  EspNowMeshWipe(decoded, sizeof(decoded));
  return true;
}

/*********************************************************************************************\
 * What the core asks of this file
\*********************************************************************************************/

static uint32_t EspNowMeshRandom(void* context) {
  (void)context;
  return esp_random();
}

// The nodes the task knows, a copy of the main loop's, for the core to tell a neighbour by its address
static EspNowMeshNode_t EspNowMeshTable[ESPNOW_MESH_NODES];

static uint8_t EspNowMeshNodeOf(void* context, const uint8_t mac[6]) {
  (void)context;
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    if (EspNowMeshTable[i].id && !memcmp(EspNowMeshTable[i].mac, mac, 6)) { return EspNowMeshTable[i].id; }
  }
  return 0;
}

/*********************************************************************************************\
 * The radio
\*********************************************************************************************/

// A frame of the mesh, from the WiFi task, into the task's queue
static void EspNowMeshEnqueue(const uint8_t* mac, int8_t rssi, const uint8_t* data, int len) {
  if ((len < (int)(EspNowMesh::kHeaderLen + EspNowMesh::kTagLen)) || (len > (int)EspNowMesh::kMaxFrame)) { return; }
  if (!EspNowMeshDriver.accepting || (nullptr == EspNowMeshDriver.rx)) { return; }

  EspNowMeshRx_t item;
  item.len = len;
  memcpy(item.mac, mac, 6);
  item.rssi = rssi;
  memcpy(item.data, data, len);
  if (pdTRUE != xQueueSend(EspNowMeshDriver.rx, &item, 0)) {
    EspNowMeshDriver.dropped++;
    return;
  }
  TaskHandle_t task = EspNowMeshDriver.task;
  if (task) { xTaskNotifyGive(task); }
}

// The radio's word on the frame the task is sending. True when it was the task's to hear
bool EspNowMeshSendResult(bool ok);
bool EspNowMeshSendResult(bool ok) {
  if (!EspNowMeshDriver.awaiting) { return false; }
  EspNowMeshDriver.send_ok = ok;
  EspNowMeshDriver.awaiting = false;
  if (EspNowMeshDriver.send_done) { xSemaphoreGive(EspNowMeshDriver.send_done); }
  return true;
}

// The direct link's receive callback, first: true when the frame is the mesh's, whose first byte no direct frame has
bool EspNowMeshHearsFrame(const uint8_t* mac, int8_t rssi, const uint8_t* data, int len);
bool EspNowMeshHearsFrame(const uint8_t* mac, int8_t rssi, const uint8_t* data, int len) {
  if ((len < 1) || (EspNowMesh::kVersion != data[0])) { return false; }
  EspNowMeshEnqueue(mac, rssi, data, len);
  return true;
}

// The mesh's own callbacks, for when it started ESP-NOW itself. Declared before their definition, as every function whose
// signature names a type of the ESP-IDF: the sketch preprocessor would otherwise hoist a generated prototype above the include.
void EspNowMeshRecvCb(const esp_now_recv_info_t* info, const uint8_t* data, int len);
void EspNowMeshRecvCb(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  if ((len < 1) || (EspNowMesh::kVersion != data[0])) { return; }
  EspNowMeshEnqueue(info->src_addr, info->rx_ctrl->rssi, data, len);
}

void EspNowMeshSendCb(const esp_now_send_info_t* info, esp_now_send_status_t status);
void EspNowMeshSendCb(const esp_now_send_info_t* info, esp_now_send_status_t status) {
  (void)info;
  EspNowMeshSendResult(ESP_NOW_SEND_SUCCESS == status);
}

static bool EspNowMeshRadioReady(void) {
  return (WiFi.getMode() & WIFI_MODE_STA);
}

// The broadcast address, with no key, on whatever channel the radio is on. The addresses of the neighbours are added when
// the first frame goes to them
static void EspNowMeshAddBroadcast(void) {
  if (esp_now_is_peer_exist(EspNowMeshBroadcast)) { return; }
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, EspNowMeshBroadcast, 6);
  peer.channel = 0;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;
  esp_now_add_peer(&peer);
}

// The direct link's driver started or stopped ESP-NOW. Its start leaves no peer behind, and the mesh's addresses are added again as
// the frames go to them
void EspNowMeshDirectRadio(bool up);
void EspNowMeshDirectRadio(bool up) {
  EspNowMeshDriver.direct_radio = up;
  if (up) {
    EspNowMeshDriver.own_radio = false;            // what the mesh had started was deinitialised by the direct link's start
    EspNowMeshDriver.radio_lost = false;
    if (EspNowMeshDriver.running || EspNowMeshSettings.enabled) { EspNowMeshAddBroadcast(); }
    EspNowMeshDriver.radio = true;
  } else if (!EspNowMeshDriver.own_radio) {
    EspNowMeshDriver.radio = false;                // the mesh starts its own at the next second
  }
}

static bool EspNowMeshRadioStart(void) {
  EspNowMeshDriver.radio_lost = false;
  if (EspNowMeshDriver.direct_radio) {             // the direct link's radio is up: the mesh rides on it
    EspNowMeshAddBroadcast();
    EspNowMeshDriver.radio = true;
    return true;
  }
  esp_now_deinit();
  esp_err_t error = esp_now_init();
  if (ESP_OK != error) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EMH: ESP-NOW init failed with error %d"), error);
    EspNowMeshDriver.radio = false;
    return false;
  }
  esp_now_register_recv_cb(EspNowMeshRecvCb);
  esp_now_register_send_cb(EspNowMeshSendCb);
  EspNowMeshAddBroadcast();
  EspNowMeshDriver.own_radio = true;
  EspNowMeshDriver.radio = true;
  return true;
}

static void EspNowMeshRadioStop(void) {
  if (!EspNowMeshDriver.radio) { return; }
  EspNowMeshDriver.radio = false;
  vTaskDelay(pdMS_TO_TICKS(2 * ESPNOW_MESH_SEND_WAIT_MS));   // the task is out of a send that was under way
  if (!EspNowMeshDriver.own_radio) { return; }     // the direct link's radio stays as it is
  EspNowMeshDriver.own_radio = false;
  // esp_now_deinit() faults when the WiFi stack is not there
  if (EspNowMeshRadioReady()) {
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    esp_now_deinit();
  }
}

// The radio goes to the configured channel when the station is not associated. With the station associated, the access
// point's channel is the channel
static void EspNowMeshApplyChannel(void) {
  if (!EspNowMeshSettings.channel) { return; }
  wifi_ap_record_t ap;
  if (ESP_OK == esp_wifi_sta_get_ap_info(&ap)) { return; }
  // The station keeps trying a saved network, or a scan runs: the radio is not moved under them
  if (Settings->flag4.network_wifi && (strlen(SettingsText(SET_STASSID1)) || strlen(SettingsText(SET_STASSID2)))) { return; }
  if (WIFI_SCAN_RUNNING == WiFi.scanComplete()) { return; }
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&channel, &second);
  if (channel == EspNowMeshSettings.channel) { return; }
  if (ESP_OK == esp_wifi_set_channel(EspNowMeshSettings.channel, WIFI_SECOND_CHAN_NONE)) {
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: Radio from channel %d to %d"), channel, EspNowMeshSettings.channel);
  }
}

// One frame, to one address, and the radio's word on it. A unicast the other side did not acknowledge says so; a broadcast never
// does, and counts as sent
static bool EspNowMeshRadioSend(const uint8_t* to, const uint8_t* frame, size_t len) {
  if (!EspNowMeshDriver.radio) { return false; }
  if (!esp_now_is_peer_exist(to)) {
    esp_now_peer_info_t peer = {};
    memcpy(peer.peer_addr, to, 6);
    peer.channel = 0;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;
    if (ESP_OK != esp_now_add_peer(&peer)) { return false; }
  }
  // A word from an earlier send that came late is not this one's: the semaphore is emptied before the send is armed
  xSemaphoreTake(EspNowMeshDriver.send_done, 0);
  EspNowMeshDriver.send_ok = false;
  EspNowMeshDriver.awaiting = true;
  if (ESP_OK != esp_now_send(to, frame, len)) {
    EspNowMeshDriver.awaiting = false;
    xSemaphoreTake(EspNowMeshDriver.send_done, 0);
    return false;
  }
  if (pdTRUE != xSemaphoreTake(EspNowMeshDriver.send_done, pdMS_TO_TICKS(ESPNOW_MESH_SEND_WAIT_MS))) {
    EspNowMeshDriver.awaiting = false;       // no word: not acknowledged
    xSemaphoreTake(EspNowMeshDriver.send_done, 0);
    return false;
  }
  return EspNowMeshDriver.send_ok;
}

/*********************************************************************************************\
 * The network
\*********************************************************************************************/

static WiFiUDP* EspNowMeshUdp = nullptr;     // the task's alone

static bool EspNowMeshNetworkUp(void) {
  return (WiFi.status() == WL_CONNECTED);
}

static void EspNowMeshUdpStart(void) {
  if (nullptr == EspNowMeshUdp) { EspNowMeshUdp = new (std::nothrow) WiFiUDP; }
  if (EspNowMeshUdp) { EspNowMeshUdp->begin(ESPNOW_MESH_UDP_PORT); }
}

static void EspNowMeshUdpStop(void) {
  if (EspNowMeshUdp) {
    EspNowMeshUdp->stop();
    delete EspNowMeshUdp;
    EspNowMeshUdp = nullptr;
  }
}

static void EspNowMeshUdpSend(const uint8_t* frame, size_t len, uint8_t target) {
  if (nullptr == EspNowMeshUdp) { return; }
  IPAddress ip = WiFi.broadcastIP();
  if (target) {
    for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
      if ((EspNowMeshTable[i].id == target) && (EspNowMeshTable[i].ip[0] || EspNowMeshTable[i].ip[1] || EspNowMeshTable[i].ip[2] || EspNowMeshTable[i].ip[3])) {
        ip = IPAddress(EspNowMeshTable[i].ip[0], EspNowMeshTable[i].ip[1], EspNowMeshTable[i].ip[2], EspNowMeshTable[i].ip[3]);
        break;
      }
    }
  }
  if (EspNowMeshUdp->beginPacket(ip, ESPNOW_MESH_UDP_PORT)) {
    EspNowMeshUdp->write(frame, len);
    EspNowMeshUdp->endPacket();
  }
}

// The frames that came by the network, to the core, from the node whose address the table gives for the sender's
static void EspNowMeshUdpPoll(EspNowMesh::Node* node);
static void EspNowMeshUdpPoll(EspNowMesh::Node* node) {
  if (nullptr == EspNowMeshUdp) { return; }
  uint8_t buffer[EspNowMesh::kMaxFrame + 1];
  for (uint32_t turns = 0; turns < 4; turns++) {
    int size = EspNowMeshUdp->parsePacket();
    if (size <= 0) { return; }
    // What does not fit is thrown away whole: the rest of a datagram left unread keeps the socket from giving the next one
    if (size > (int)EspNowMesh::kMaxFrame) { EspNowMeshUdp->flush(); continue; }
    int len = EspNowMeshUdp->read(buffer, sizeof(buffer));
    IPAddress from = EspNowMeshUdp->remoteIP();
    if ((len < (int)(EspNowMesh::kHeaderLen + EspNowMesh::kTagLen)) || (len > (int)EspNowMesh::kMaxFrame)) { continue; }
    if (EspNowMesh::kVersion != buffer[0]) { continue; }
    if (from == WiFi.localIP()) { continue; }
    for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
      const EspNowMeshNode_t& entry = EspNowMeshTable[i];
      if (entry.id && (from == IPAddress(entry.ip[0], entry.ip[1], entry.ip[2], entry.ip[3]))) {
        node->OnReceive(buffer, len, entry.mac, 0, millis(), true);
        break;
      }
    }
  }
}

/*********************************************************************************************\
 * The task
\*********************************************************************************************/

// What the main loop handed over: the nodes, the key of the network, how the network is used
static void EspNowMeshApplyShared(EspNowMesh::Node* node, EspNowMeshShared_t* shared);
static void EspNowMeshApplyShared(EspNowMesh::Node* node, EspNowMeshShared_t* shared) {
  EspNowMeshShared_t fresh;
  xSemaphoreTake(EspNowMeshDriver.lock, portMAX_DELAY);
  memcpy(&fresh, shared, sizeof(fresh));
  EspNowMeshDriver.config_dirty = false;
  xSemaphoreGive(EspNowMeshDriver.lock);

  if (fresh.has_group) { EspNowMeshDriver.crypto->SetGroupKey(fresh.group_key, fresh.group_version); }
  // The keys of the nodes that left, or whose key changed, go first: a node that moved to another slot would otherwise have its
  // new key made and then forgotten
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    const EspNowMeshNode_t& old_entry = EspNowMeshTable[i];
    const EspNowMeshNode_t& entry = fresh.node[i];
    if (old_entry.id && ((old_entry.id != entry.id) || memcmp(old_entry.pub, entry.pub, sizeof(entry.pub)))) {
      EspNowMeshDriver.crypto->ForgetPeer(old_entry.id);
    }
  }
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    const EspNowMeshNode_t& old_entry = EspNowMeshTable[i];
    const EspNowMeshNode_t& entry = fresh.node[i];
    if (entry.id && ((old_entry.id != entry.id) || memcmp(old_entry.pub, entry.pub, sizeof(entry.pub)) || !EspNowMeshDriver.crypto->HasPeer(entry.id))) {
      if (!EspNowMeshDriver.crypto->SetPeer(entry.id, entry.pub)) {
        AddLog(LOG_LEVEL_INFO, PSTR("EMH: The public key of node %u gives no key"), entry.id);
      }
    }
  }
  memcpy(EspNowMeshTable, fresh.node, sizeof(EspNowMeshTable));
  if (fresh.network & ESPNOW_MESH_NET_UDP) {
    if (EspNowMeshNetworkUp()) { if (nullptr == EspNowMeshUdp) { EspNowMeshUdpStart(); } }
  } else {
    EspNowMeshUdpStop();
  }
  EspNowMeshWipe(&fresh, sizeof(fresh));      // it held the key of the network
}

static void EspNowMeshPutEvent(const EspNowMeshEvent_t* event);
static void EspNowMeshPutEvent(const EspNowMeshEvent_t* event) {
  if (pdTRUE != xQueueSend(EspNowMeshDriver.event, event, 0)) {
    EspNowMeshEvent_t dropped;
    xQueueReceive(EspNowMeshDriver.event, &dropped, 0);        // make room, keep the newest
    xQueueSend(EspNowMeshDriver.event, event, 0);
  }
}

// What the core has to tell the main loop: the frames for this device, what became of the ones that asked for an answer, and
// what the supervision found
static void EspNowMeshDrain(EspNowMesh::Node* node);
static void EspNowMeshDrain(EspNowMesh::Node* node) {
  EspNowMesh::Delivery d;
  while (node->PopDelivery(&d)) {
    EspNowMeshEvent_t e;
    memset(&e, 0, sizeof(e));
    e.kind = ESPNOW_MESH_EVT_DELIVERY;
    e.origin = d.origin;
    e.type = d.type;
    e.flags = (d.ackRequested ? 1 : 0) | (d.retry ? 2 : 0);
    e.part = d.part;
    e.attempt = d.attempt;
    e.behind = d.behind;
    e.dest = d.dest;
    e.rssi = d.rssi;
    e.counter = d.counter;
    e.epoch = d.epoch;
    e.joins = d.joins;
    e.len = d.len;
    memcpy(e.data, d.payload, d.len);
    EspNowMeshPutEvent(&e);
  }
  EspNowMesh::Outcome o;
  while (node->PopOutcome(&o)) {
    EspNowMeshEvent_t e;
    memset(&e, 0, sizeof(e));
    e.kind = ESPNOW_MESH_EVT_OUTCOME;
    e.counter = o.counter;
    e.dest = o.dest;
    e.flags = o.ok ? 1 : 0;
    e.attempt = o.attempts;
    EspNowMeshPutEvent(&e);
  }
  EspNowMesh::Notice n;
  while (node->PopNotice(&n)) {
    EspNowMeshEvent_t e;
    memset(&e, 0, sizeof(e));
    e.kind = ESPNOW_MESH_EVT_NOTICE;
    e.origin = n.node;
    e.type = n.kind;
    e.dest = n.by;
    e.counter = n.value;
    EspNowMeshPutEvent(&e);
  }
}

static void EspNowMeshDoCommand(EspNowMesh::Node* node, const EspNowMeshCmd_t* cmd);
static void EspNowMeshDoCommand(EspNowMesh::Node* node, const EspNowMeshCmd_t* cmd) {
  switch (cmd->op) {
    case ESPNOW_MESH_CMD_SEND:
      if (!node->Send((EspNowMesh::Type)cmd->type, cmd->dest, cmd->data, cmd->len, cmd->flags & 1, millis())) {
        AddLog(LOG_LEVEL_INFO, PSTR("EMH: A frame of %u bytes for %u was refused: no room, no key or too long"), cmd->len, cmd->dest);
      }
      break;
    case ESPNOW_MESH_CMD_INFO:
      node->SetBeatInfo(cmd->data, cmd->len);
      break;
  }
}

static void EspNowMeshSnapshotMake(EspNowMesh::Node* node);
static void EspNowMeshSnapshotMake(EspNowMesh::Node* node) {
  EspNowMeshSnapshot_t* s = EspNowMeshDriver.snapshot;
  if (nullptr == s) { return; }
  EspNowMeshSnapshot_t fresh;
  memset(&fresh, 0, sizeof(fresh));
  uint32_t now = millis();
  fresh.at = now;
  fresh.stats = node->stats();
  fresh.queued = node->queued();
  fresh.waiting = node->waiting();
  fresh.noisy = node->Noisy();
  fresh.loss = node->LossPercent();
  fresh.net_up = EspNowMeshNetworkUp();
  for (uint32_t i = 0; i < EspNowMesh::kMaxNeighbors; i++) {
    const EspNowMesh::Neighbor* n = node->NeighborAt(i);
    if (nullptr == n) { continue; }
    EspNowMeshNeighbor_t& out = fresh.neighbor[fresh.neighbors++];
    out.id = n->id;
    out.state = n->state;
    out.lists_me = n->listsMe;
    out.no_radio = n->noRadio;
    out.rssi = n->rssi;
    out.their_rssi = n->theirRssi;
    out.age_s = (now - n->lastHeard) / 1000;
    out.beat_s = n->beatAt ? (now - n->beatAt) / 1000 : 0xFFFF;
    out.hears = n->hearsCount;
    out.info_len = n->infoLen;
    memcpy(out.info, n->info, n->infoLen);
  }
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    if (EspNowMeshTable[i].id && node->IsSilent(EspNowMeshTable[i].id) && (fresh.silent_count < ESPNOW_MESH_NODES)) {
      fresh.silent[fresh.silent_count++] = EspNowMeshTable[i].id;
    }
  }
  fresh.stack_free = uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t);
  if (pdTRUE == xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(10))) {
    memcpy(s, &fresh, sizeof(fresh));
    xSemaphoreGive(EspNowMeshDriver.lock);
  }
}

// What the core has ready to send, one frame at a time: by the network if it says so, then by the radio, whose word on it the
// core is given
static void EspNowMeshPump(EspNowMesh::Node* node);
static void EspNowMeshPump(EspNowMesh::Node* node) {
  uint8_t frame[EspNowMesh::kMaxFrame];
  uint8_t to[6];
  uint8_t paths = 0;
  uint8_t target = 0;
  size_t len = 0;
  for (uint32_t sends = 0; (sends < ESPNOW_MESH_SENDS_PER_TURN) && !node->Busy() && node->NextTx(millis(), frame, &len, to, &paths, &target); sends++) {
    if (paths & EspNowMesh::kPathUdp) { EspNowMeshUdpSend(frame, len, target); }
    bool ok = true;
    if (paths & EspNowMesh::kPathRadio) { ok = EspNowMeshRadioSend(to, frame, len); }
    node->TxDone(ok, millis());
  }
}

static void EspNowMeshTask(void* argument) {
  (void)argument;
  EspNowMesh::Node* node = EspNowMeshDriver.node;
  uint32_t snapshot_at = 0;
  EspNowMeshApplyShared(node, EspNowMeshDriver.shared);

  while (!EspNowMeshDriver.stop) {
    if (EspNowMeshDriver.config_dirty) { EspNowMeshApplyShared(node, EspNowMeshDriver.shared); }

    EspNowMeshCmd_t cmd;
    while (pdTRUE == xQueueReceive(EspNowMeshDriver.cmd, &cmd, 0)) { EspNowMeshDoCommand(node, &cmd); }

    EspNowMeshRx_t rx;
    while (pdTRUE == xQueueReceive(EspNowMeshDriver.rx, &rx, 0)) {
      node->OnReceive(rx.data, rx.len, rx.mac, rx.rssi, millis(), false);
    }
    EspNowMeshUdpPoll(node);

    uint32_t now = millis();
    node->Tick(now);
    EspNowMeshPump(node);
    EspNowMeshDrain(node);

    if ((now - snapshot_at) >= ESPNOW_MESH_SNAPSHOT_MS) {
      snapshot_at = now;
      bool up = EspNowMeshNetworkUp();
      node->SetUdpUp(up && (EspNowMeshSettings.network & ESPNOW_MESH_NET_UDP));
      if (up && (EspNowMeshSettings.network & ESPNOW_MESH_NET_UDP) && (nullptr == EspNowMeshUdp)) { EspNowMeshUdpStart(); }
      if (!up && EspNowMeshUdp) { EspNowMeshUdpStop(); }
      EspNowMeshSnapshotMake(node);
    }

    // Until a frame comes, or something the core waits for is due
    uint32_t due = 0;
    uint32_t wait = 4;
    if (node->NextDue(&due)) {
      int32_t delta = (int32_t)(due - millis());
      wait = (delta <= 0) ? 0 : ((delta > 4) ? 4 : delta);
    }
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(wait ? wait : 1));
  }
  EspNowMeshUdpStop();
  EspNowMeshDriver.exited = true;
  vTaskDelete(nullptr);
}

/*********************************************************************************************\
 * Start and stop
\*********************************************************************************************/

// What the main loop hands the task: a copy of the settings it has to know
static void EspNowMeshPushShared(void) {
  if ((nullptr == EspNowMeshDriver.shared) || (nullptr == EspNowMeshDriver.lock)) { return; }
  if (pdTRUE != xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50))) { return; }
  EspNowMeshDriver.shared->id = EspNowMeshSettings.id;
  EspNowMeshDriver.shared->network = EspNowMeshSettings.network;
  EspNowMeshDriver.shared->has_group = EspNowMeshSettings.has_group;
  EspNowMeshDriver.shared->group_version = EspNowMeshSettings.group_version;
  memcpy(EspNowMeshDriver.shared->group_key, EspNowMeshSettings.group_key, sizeof(EspNowMeshSettings.group_key));
  memcpy(EspNowMeshDriver.shared->node, EspNowMeshSettings.node, sizeof(EspNowMeshSettings.node));
  EspNowMeshDriver.config_dirty = true;
  xSemaphoreGive(EspNowMeshDriver.lock);
}

static void EspNowMeshFree(void) {
  if (EspNowMeshDriver.rx) { vQueueDelete(EspNowMeshDriver.rx); EspNowMeshDriver.rx = nullptr; }
  if (EspNowMeshDriver.cmd) { vQueueDelete(EspNowMeshDriver.cmd); EspNowMeshDriver.cmd = nullptr; }
  if (EspNowMeshDriver.event) { vQueueDelete(EspNowMeshDriver.event); EspNowMeshDriver.event = nullptr; }
  if (EspNowMeshDriver.send_done) { vSemaphoreDelete(EspNowMeshDriver.send_done); EspNowMeshDriver.send_done = nullptr; }
  if (EspNowMeshDriver.lock) { vSemaphoreDelete(EspNowMeshDriver.lock); EspNowMeshDriver.lock = nullptr; }
  if (EspNowMeshDriver.crypto) { EspNowMeshWipe(EspNowMeshDriver.crypto, sizeof(EspNowMesh::Crypto)); }
  delete EspNowMeshDriver.node;
  delete EspNowMeshDriver.crypto;
  delete EspNowMeshDriver.snapshot;
  delete EspNowMeshDriver.shared;
  EspNowMeshDriver.node = nullptr;
  EspNowMeshDriver.crypto = nullptr;
  EspNowMeshDriver.snapshot = nullptr;
  EspNowMeshDriver.shared = nullptr;
}

static const char* EspNowMeshWhyNot(void) {
  if (!EspNowMeshSettings.id) { return PSTR("needs EspNowMeshId"); }
  if (!EspNowMeshSettings.has_group) { return PSTR("needs EspNowMeshGroupKey"); }
  if (!EspNowMeshRadioReady()) { return PSTR("WiFi is not up"); }
  return nullptr;
}

// The work of a start. Nothing is written to the flash until the whole of it has worked, and a start that fails is not tried
// again for ten seconds (EspNowMeshStart): a failing one, with the heap short, would otherwise write the flash and the log once a second
static bool EspNowMeshStartAttempt(void) {
  if (!EspNowMeshSettings.has_secret) {
    esp_fill_random(EspNowMeshSettings.secret, sizeof(EspNowMeshSettings.secret));
    EspNowMeshSettings.has_secret = 1;
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: This device has an identity now: EspNowMeshPublic gives its public key"));
  }
  // The epoch of a device that has none is drawn at random, so that a device that was erased does not repeat the numbers of the
  // frames it sent before, with the key of the network it still has; and it rises with every start after that
  uint32_t epoch = EspNowMeshSettings.epoch ? (EspNowMeshSettings.epoch + 1) : ((esp_random() >> 2) | 1);

  EspNowMeshDriver.node = new (std::nothrow) EspNowMesh::Node;
  EspNowMeshDriver.crypto = new (std::nothrow) EspNowMesh::Crypto;
  EspNowMeshDriver.snapshot = new (std::nothrow) EspNowMeshSnapshot_t;
  EspNowMeshDriver.shared = new (std::nothrow) EspNowMeshShared_t;
  EspNowMeshDriver.rx = xQueueCreate(ESPNOW_MESH_RX_DEPTH, sizeof(EspNowMeshRx_t));
  EspNowMeshDriver.cmd = xQueueCreate(ESPNOW_MESH_CMD_DEPTH, sizeof(EspNowMeshCmd_t));
  EspNowMeshDriver.event = xQueueCreate(ESPNOW_MESH_EVENT_DEPTH, sizeof(EspNowMeshEvent_t));
  EspNowMeshDriver.send_done = xSemaphoreCreateBinary();
  EspNowMeshDriver.lock = xSemaphoreCreateMutex();
  if (!EspNowMeshDriver.node || !EspNowMeshDriver.crypto || !EspNowMeshDriver.snapshot || !EspNowMeshDriver.shared ||
      !EspNowMeshDriver.rx || !EspNowMeshDriver.cmd || !EspNowMeshDriver.event || !EspNowMeshDriver.send_done || !EspNowMeshDriver.lock) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EMH: Not enough memory, %u bytes free"), ESP_getFreeHeap());
    EspNowMeshFree();
    return false;
  }
  memset(EspNowMeshDriver.snapshot, 0, sizeof(EspNowMeshSnapshot_t));
  memset(EspNowMeshDriver.shared, 0, sizeof(EspNowMeshShared_t));
  memset(EspNowMeshTable, 0, sizeof(EspNowMeshTable));

  if (!EspNowMeshDriver.crypto->Begin(EspNowMeshSettings.secret)) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EMH: The identity gives no public key"));
    EspNowMeshFree();
    return false;
  }
  EspNowMeshDriver.crypto->SetGroupKey(EspNowMeshSettings.group_key, EspNowMeshSettings.group_version);

  EspNowMesh::Config config;
  memset(&config, 0, sizeof(config));
  config.id = EspNowMeshSettings.id;
  config.epoch = epoch;
  config.random = EspNowMeshRandom;
  config.tag = EspNowMesh::Crypto::Tag;
  config.tagContext = EspNowMeshDriver.crypto;
  config.proof = EspNowMesh::Crypto::Proof;
  config.proofContext = EspNowMeshDriver.crypto;
  config.seal = EspNowMesh::Crypto::Seal;
  config.open = EspNowMesh::Crypto::Open;
  config.cipherContext = EspNowMeshDriver.crypto;
  config.nodeOf = EspNowMeshNodeOf;
  config.weakDbm = -70;
  config.suppressAt = 2;
  config.beatEveryMs = ESPNOW_MESH_BEAT_MS;
  config.udpOnly = (EspNowMeshSettings.network & ESPNOW_MESH_NET_NO_RADIO) != 0;
  config.udpRelay = (EspNowMeshSettings.network & ESPNOW_MESH_NET_RELAY) != 0;
  EspNowMeshDriver.node->Begin(config);

  EspNowMeshDriver.stop = false;
  EspNowMeshDriver.exited = false;
  EspNowMeshPushShared();
  EspNowMeshApplyChannel();
  if (!EspNowMeshRadioStart()) {
    EspNowMeshFree();
    return false;
  }
  EspNowMeshDriver.accepting = true;
  if (pdPASS != xTaskCreatePinnedToCore(EspNowMeshTask, "espnowmesh", ESPNOW_MESH_TASK_STACK, nullptr, ESPNOW_MESH_TASK_PRIORITY, &EspNowMeshDriver.task, 0)) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EMH: The task did not start"));
    EspNowMeshDriver.accepting = false;
    EspNowMeshRadioStop();
    EspNowMeshFree();
    return false;
  }
  // It works: now the epoch, and the identity if it is new, are written
  EspNowMeshSettings.epoch = epoch;
  EspNowMeshSettingsSave();
  EspNowMeshDriver.running = true;
  AddLog(LOG_LEVEL_INFO, PSTR("EMH: Started as node %u, epoch %u, %u bytes of heap free"), EspNowMeshSettings.id, epoch, ESP_getFreeHeap());
  return true;
}

static bool EspNowMeshStart(void) {
  if (EspNowMeshDriver.running) { return true; }
  if (EspNowMeshWhyNot()) { return false; }
  if (EspNowMeshStartAttempt()) { return true; }
  EspNowMeshDriver.retry_wait = true;
  EspNowMeshDriver.retry_at = millis() + 10000;
  return false;
}

// The task is gone: what it used is given back
static void EspNowMeshReap(void) {
  EspNowMeshDriver.task = nullptr;
  EspNowMeshRadioStop();
  EspNowMeshFree();
  EspNowMeshDriver.running = false;
  AddLog(LOG_LEVEL_INFO, PSTR("EMH: Stopped"));
}

static void EspNowMeshStop(void) {
  if (!EspNowMeshDriver.running) { return; }
  // The callbacks stop putting frames in the queue first, and one that was under way is given the time to finish; then the task is
  // asked to end. What it used is given back only when it has: if it has not within two seconds it ends by itself and the next
  // second finds it gone
  EspNowMeshDriver.accepting = false;
  vTaskDelay(pdMS_TO_TICKS(10));
  EspNowMeshDriver.stop = true;
  TaskHandle_t task = EspNowMeshDriver.task;
  if (task) { xTaskNotifyGive(task); }
  for (uint32_t i = 0; (i < 400) && !EspNowMeshDriver.exited; i++) { vTaskDelay(pdMS_TO_TICKS(5)); }
  if (EspNowMeshDriver.exited) {
    EspNowMeshReap();
  } else {
    AddLog(LOG_LEVEL_ERROR, PSTR("EMH: The task has not ended yet, it is given back when it has"));
  }
}

void EspNowMeshWifiEvent(arduino_event_t *event);
void EspNowMeshWifiEvent(arduino_event_t *event) {
  if ((ARDUINO_EVENT_WIFI_STA_STOP == event->event_id) || (ARDUINO_EVENT_WIFI_OFF == event->event_id)) {
    EspNowMeshDriver.radio_lost = true;
  }
}

static void EspNowMeshEverySecond(void) {
  if (EspNowMeshDriver.running && EspNowMeshDriver.exited) { EspNowMeshReap(); }       // a task that was slow to end
  if (!EspNowMeshSettings.enabled) { return; }
  if (!EspNowMeshDriver.running) {
    if (EspNowMeshDriver.retry_wait && ((int32_t)(millis() - EspNowMeshDriver.retry_at) < 0)) { return; }
    EspNowMeshDriver.retry_wait = false;
    EspNowMeshStart();
    return;
  }
  if (!EspNowMeshDriver.radio) {
    // The direct link stopped ESP-NOW, or it never was up: the mesh starts its own
    if (EspNowMeshRadioReady()) { EspNowMeshRadioStart(); }
  } else if (EspNowMeshDriver.own_radio && EspNowMeshDriver.radio_lost && EspNowMeshRadioReady()) {
    // The WiFi stack stopped under the mesh's ESP-NOW and is back: it starts again, and the neighbours' addresses are added again as
    // the frames go to them
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: The WiFi stack came back, ESP-NOW starts again"));
    EspNowMeshRadioStop();
    EspNowMeshRadioStart();
  }
  EspNowMeshApplyChannel();
}

/*********************************************************************************************\
 * What the core said, in the log and to the rules
\*********************************************************************************************/

static const char* EspNowMeshNoticeName(uint8_t kind) {
  switch (kind) {
    case EspNowMesh::kNoticeSilent: return PSTR("Silent");
    case EspNowMesh::kNoticeBack: return PSTR("Back");
    case EspNowMesh::kNoticeNoisy: return PSTR("Noisy");
    case EspNowMesh::kNoticeCalm: return PSTR("Calm");
    case EspNowMesh::kNoticeBulkDone: return PSTR("BulkDone");
    case EspNowMesh::kNoticeBulkLost: return PSTR("BulkLost");
  }
  return PSTR("?");
}

static void EspNowMeshDrainEvents(void) {
  if (nullptr == EspNowMeshDriver.event) { return; }
  EspNowMeshEvent_t e;
  while (pdTRUE == xQueueReceive(EspNowMeshDriver.event, &e, 0)) {
    switch (e.kind) {
      case ESPNOW_MESH_EVT_DELIVERY: {
        char hex[2 * EspNowMesh::kMaxPayload + 1];
        ToHex_P(e.data, e.len, hex, sizeof(hex));
        AddLog(LOG_LEVEL_INFO, PSTR("EMH: From %u type %u dest %u counter %u rssi %d%s: %d bytes"), e.origin, e.type, e.dest, e.counter, e.rssi, (e.flags & 2) ? PSTR(" repeat") : PSTR(""), e.len);
        Response_P(PSTR("{\"EspNowMesh\":{\"From\":%u,\"Type\":%u,\"Dest\":%u,\"Counter\":%u,\"Epoch\":%u,\"Rssi\":%d,\"Flags\":%u,\"Part\":%u,\"Joins\":%u,\"Behind\":%u,\"Data\":\"%s\"}}"),
          e.origin, e.type, e.dest, e.counter, e.epoch, e.rssi, e.flags, e.part, e.joins, e.behind, hex);
        XdrvRulesProcess(0);
        break;
      }
      case ESPNOW_MESH_EVT_OUTCOME:
        AddLog(LOG_LEVEL_INFO, PSTR("EMH: Frame %u for %u %s after %u attempts"), e.counter, e.dest, e.flags ? PSTR("was answered") : PSTR("was not answered"), e.attempt);
        Response_P(PSTR("{\"EspNowMesh\":{\"Outcome\":{\"Counter\":%u,\"Dest\":%u,\"Ok\":%u,\"Attempts\":%u}}}"), e.counter, e.dest, e.flags, e.attempt);
        XdrvRulesProcess(0);
        break;
      case ESPNOW_MESH_EVT_NOTICE:
        AddLog(LOG_LEVEL_INFO, PSTR("EMH: %s, node %u, said by %u"), EspNowMeshNoticeName(e.type), e.origin, e.dest);
        Response_P(PSTR("{\"EspNowMesh\":{\"Notice\":{\"Kind\":\"%s\",\"Node\":%u,\"By\":%u,\"Value\":%u}}}"), EspNowMeshNoticeName(e.type), e.origin, e.dest, e.counter);
        XdrvRulesProcess(0);
        break;
    }
  }
}

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

void CmndEspNowMeshEnable(void) {
  if (XdrvMailbox.data_len > 0) {
    EspNowMeshSettings.enabled = (atoi(XdrvMailbox.data) != 0);
    EspNowMeshSettingsSave();
    if (EspNowMeshSettings.enabled) {
      if (!EspNowMeshStart()) {
        const char* why = EspNowMeshWhyNot();
        ResponseCmndChar_P(why ? why : PSTR("did not start"));
        return;
      }
    } else {
      EspNowMeshStop();
    }
  }
  Response_P(PSTR("{\"%s\":{\"Enabled\":%u,\"Running\":%u}}"), XdrvMailbox.command, EspNowMeshSettings.enabled, EspNowMeshDriver.running);
}

void CmndEspNowMeshId(void) {
  if (XdrvMailbox.data_len > 0) {
    uint32_t id = atoi(XdrvMailbox.data);
    if ((id < 1) || (id > 254)) { ResponseCmndError(); return; }
    EspNowMeshSettings.id = id;
    EspNowMeshSettingsSave();
  }
  ResponseCmndNumber(EspNowMeshSettings.id);
}

void CmndEspNowMeshChannel(void) {
  if (XdrvMailbox.data_len > 0) {
    uint32_t channel = atoi(XdrvMailbox.data);
    if (channel > 13) { ResponseCmndError(); return; }
    EspNowMeshSettings.channel = channel;
    EspNowMeshSettingsSave();
    if (EspNowMeshDriver.running) { EspNowMeshApplyChannel(); }
  }
  ResponseCmndNumber(EspNowMeshSettings.channel);
}

void CmndEspNowMeshGroupKey(void) {
  if (XdrvMailbox.data_len > 0) {
    char text[80];
    snprintf(text, sizeof(text), "%s", XdrvMailbox.data);
    char* comma = strchr(text, ',');
    uint32_t version = 1;
    if (comma) { *comma = '\0'; version = atoi(comma + 1); }
    if ((version < 1) || (version > 255) || !EspNowMeshHex(text, EspNowMeshSettings.group_key, sizeof(EspNowMeshSettings.group_key))) {
      ResponseCmndError();
      EspNowMeshWipe(text, sizeof(text));
      return;
    }
    EspNowMeshWipe(text, sizeof(text));
    memset(XdrvMailbox.data, '*', XdrvMailbox.data_len);       // the key is not left in the command's own buffer
    EspNowMeshSettings.group_version = version;
    EspNowMeshSettings.has_group = 1;
    EspNowMeshSettingsSave();
    EspNowMeshPushShared();
  }
  Response_P(PSTR("{\"%s\":{\"Set\":%u,\"Version\":%u}}"), XdrvMailbox.command, EspNowMeshSettings.has_group, EspNowMeshSettings.group_version);
}

void CmndEspNowMeshNode(void) {
  if (!XdrvMailbox.data_len) {
    char mac[18];
    Response_P(PSTR("{\"%s\":["), XdrvMailbox.command);
    bool first = true;
    for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
      const EspNowMeshNode_t& n = EspNowMeshSettings.node[i];
      if (!n.id) { continue; }
      ToHex_P(n.mac, 6, mac, sizeof(mac), ':');
      ResponseAppend_P(PSTR("%s{\"Id\":%u,\"Mac\":\"%s\",\"Ip\":\"%u.%u.%u.%u\"}"), first ? PSTR("") : PSTR(","), n.id, mac, n.ip[0], n.ip[1], n.ip[2], n.ip[3]);
      first = false;
    }
    ResponseAppend_P(PSTR("]}"));
    return;
  }
  char text[160];
  snprintf(text, sizeof(text), "%s", XdrvMailbox.data);
  char* fields[4] = {text, nullptr, nullptr, nullptr};
  uint32_t count = 1;
  for (char* p = text; *p && (count < 4); p++) {
    if (',' == *p) { *p = '\0'; fields[count++] = p + 1; }
  }
  uint32_t id = atoi(fields[0]);
  if ((id < 1) || (id > 254)) { ResponseCmndError(); return; }

  int32_t slot = -1;
  int32_t free_slot = -1;
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    if (EspNowMeshSettings.node[i].id == id) { slot = i; }
    if (!EspNowMeshSettings.node[i].id && (free_slot < 0)) { free_slot = i; }
  }
  if ((2 == count) && !strcmp(fields[1], "0")) {          // forgotten
    if (slot >= 0) { memset(&EspNowMeshSettings.node[slot], 0, sizeof(EspNowMeshNode_t)); }
  } else {
    if (count < 3) { ResponseCmndError(); return; }
    if (slot < 0) { slot = free_slot; }
    if (slot < 0) { ResponseCmndChar_P(PSTR("no room")); return; }
    EspNowMeshNode_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.id = id;
    unsigned int mac[6];
    if ((6 != sscanf(fields[1], "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])) ||
        !EspNowMeshHex(fields[2], entry.pub, sizeof(entry.pub))) {
      ResponseCmndError();
      return;
    }
    for (uint32_t i = 0; i < 6; i++) { entry.mac[i] = mac[i]; }
    if ((4 == count) && fields[3][0]) {
      IPAddress ip;
      if (!ip.fromString(fields[3])) { ResponseCmndError(); return; }
      for (uint32_t i = 0; i < 4; i++) { entry.ip[i] = ip[i]; }
    }
    EspNowMeshSettings.node[slot] = entry;
  }
  EspNowMeshSettingsSave();
  EspNowMeshPushShared();
  ResponseCmndDone();
}

void CmndEspNowMeshPublic(void) {
  static const uint8_t base[32] = {9};
  if (!EspNowMeshSettings.has_secret) {
    // The identity is made here the first time it is asked for, and not only when the mesh starts, so that a device can be told to the others first.
    // The hardware's random numbers are strong only with the radio on
    if (!EspNowMeshRadioReady()) { ResponseCmndChar_P(PSTR("WiFi is not up")); return; }
    esp_fill_random(EspNowMeshSettings.secret, sizeof(EspNowMeshSettings.secret));
    EspNowMeshSettings.has_secret = 1;
    EspNowMeshSettingsSave();
  }
  uint8_t pub[32];
  if (!EspNowMesh::Crypto::X25519(pub, EspNowMeshSettings.secret, base)) { ResponseCmndError(); return; }
  char hex[65];
  ToHex_P(pub, sizeof(pub), hex, sizeof(hex));
  char mac[18];
  uint8_t own_mac[6];
  esp_read_mac(own_mac, ESP_MAC_WIFI_STA);
  ToHex_P(own_mac, 6, mac, sizeof(mac), ':');
  Response_P(PSTR("{\"%s\":{\"Id\":%u,\"Mac\":\"%s\",\"Public\":\"%s\"}}"), XdrvMailbox.command, EspNowMeshSettings.id, mac, hex);
}

void CmndEspNowMeshNetwork(void) {
  if (XdrvMailbox.data_len > 0) {
    EspNowMeshSettings.network = atoi(XdrvMailbox.data) & 7;
    EspNowMeshSettingsSave();
    EspNowMeshPushShared();
  }
  ResponseCmndNumber(EspNowMeshSettings.network);
}

static bool EspNowMeshQueueCommand(const EspNowMeshCmd_t* cmd);
static bool EspNowMeshQueueCommand(const EspNowMeshCmd_t* cmd) {
  if (!EspNowMeshDriver.running || (nullptr == EspNowMeshDriver.cmd)) { return false; }
  return (pdTRUE == xQueueSend(EspNowMeshDriver.cmd, cmd, 0));
}

void CmndEspNowMeshInfo(void) {
  EspNowMeshCmd_t cmd;
  memset(&cmd, 0, sizeof(cmd));
  cmd.op = ESPNOW_MESH_CMD_INFO;
  int32_t len = XdrvMailbox.data_len ? HexToBytes(XdrvMailbox.data, cmd.data, EspNowMesh::kMaxInfo) : 0;
  if (len < 0) { ResponseCmndError(); return; }
  cmd.len = len;
  ResponseCmndChar_P(EspNowMeshQueueCommand(&cmd) ? PSTR("queued") : PSTR("not running"));
}

void CmndEspNowMeshSend(void) {
  // <dest>,<type>,<ack>,<text or 0xHEX>
  char* fields[4] = {XdrvMailbox.data, nullptr, nullptr, nullptr};
  uint32_t count = 1;
  for (char* p = XdrvMailbox.data; *p && (count < 4); p++) {
    if (',' == *p) { *p = '\0'; fields[count++] = p + 1; }
  }
  if (4 != count) { ResponseCmndChar_P(PSTR("dest,type,ack,payload")); return; }
  EspNowMeshCmd_t cmd;
  memset(&cmd, 0, sizeof(cmd));
  cmd.op = ESPNOW_MESH_CMD_SEND;
  long dest = strtol(fields[0], nullptr, 10);
  long type = strtol(fields[1], nullptr, 10);
  long ack = strtol(fields[2], nullptr, 10);
  if ((dest < 0) || (dest > 255) || (type < 0) || (type > 7) || (ack < 0) || (ack > 1)) { ResponseCmndChar_P(PSTR("dest 0..255, type 0..7, ack 0|1")); return; }
  cmd.dest = dest;
  cmd.type = type;
  cmd.flags = ack;
  if (EspNowMesh::kBeat == cmd.type) { ResponseCmndChar_P(PSTR("the heartbeat is the mesh's")); return; }
  if (('0' == fields[3][0]) && (('x' == fields[3][1]) || ('X' == fields[3][1]))) {
    int32_t len = HexToBytes(fields[3] + 2, cmd.data, sizeof(cmd.data));
    if (len < 0) { ResponseCmndError(); return; }
    cmd.len = len;
  } else {
    size_t len = strlen(fields[3]);
    if (len > sizeof(cmd.data)) { ResponseCmndChar_P(PSTR("too long")); return; }
    memcpy(cmd.data, fields[3], len);
    cmd.len = len;
  }
  ResponseCmndChar_P(EspNowMeshQueueCommand(&cmd) ? PSTR("queued") : PSTR("not running"));
}

static const char* EspNowMeshStateName(uint8_t state) {
  return (EspNowMesh::kAlive == state) ? PSTR("alive") : ((EspNowMesh::kSuspect == state) ? PSTR("suspect") : PSTR("silent"));
}

void CmndEspNowMeshStatus(void) {
  char mac[18];
  uint8_t own_mac[6];
  esp_read_mac(own_mac, ESP_MAC_WIFI_STA);
  ToHex_P(own_mac, 6, mac, sizeof(mac), ':');
  EspNowMeshSnapshot_t snap;
  bool have = false;
  if (EspNowMeshDriver.running && EspNowMeshDriver.snapshot && (pdTRUE == xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    memcpy(&snap, EspNowMeshDriver.snapshot, sizeof(snap));
    xSemaphoreGive(EspNowMeshDriver.lock);
    have = true;
  }
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&channel, &second);
  Response_P(PSTR("{\"EspNowMeshStatus\":{\"Running\":%u,\"Id\":%u,\"Epoch\":%u,\"Mac\":\"%s\",\"Channel\":%u,\"Group\":%u,\"GroupVersion\":%u,\"Network\":%u,\"Radio\":%u,\"Dropped\":%u,\"Heap\":%u"),
    EspNowMeshDriver.running, EspNowMeshSettings.id, EspNowMeshSettings.epoch, mac, channel, EspNowMeshSettings.has_group, EspNowMeshSettings.group_version,
    EspNowMeshSettings.network, EspNowMeshDriver.radio, EspNowMeshDriver.dropped, ESP_getFreeHeap());
  if (have) {
    const EspNowMesh::Stats& s = snap.stats;
    ResponseAppend_P(PSTR(",\"Neighbors\":%u,\"Queued\":%u,\"Waiting\":%u,\"Noisy\":%u,\"Loss\":%u,\"NetUp\":%u,\"Stack\":%u,\"Silent\":%u,"
                          "\"Heard\":%u,\"Bad\":%u,\"Repeated\":%u,\"Delivered\":%u,\"SentOwn\":%u,\"SentRelay\":%u,\"Suppressed\":%u,"
                          "\"AcksSent\":%u,\"AcksHeard\":%u,\"Resent\":%u,\"GaveUp\":%u,\"HopFailed\":%u,\"SyncDone\":%u,\"Beats\":%u,\"Rescued\":%u,\"CipherBad\":%u,\"UdpSent\":%u,\"UdpHeard\":%u"),
      snap.neighbors, snap.queued, snap.waiting, snap.noisy, snap.loss, snap.net_up, snap.stack_free, snap.silent_count,
      s.heard, s.bad, s.repeated, s.delivered, s.sentOwn, s.sentRelay, s.suppressed,
      s.acksSent, s.acksHeard, s.resent, s.gaveUp, s.hopFailed, s.syncDone, s.beatsHeard, s.rescued, s.cipherBad, s.udpSent, s.udpHeard);
  }
  ResponseAppend_P(PSTR("}}"));
}

void CmndEspNowMeshNeighbors(void) {
  EspNowMeshSnapshot_t snap;
  if (!EspNowMeshDriver.running || (nullptr == EspNowMeshDriver.snapshot) || (pdTRUE != xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    ResponseCmndChar_P(PSTR("not running"));
    return;
  }
  memcpy(&snap, EspNowMeshDriver.snapshot, sizeof(snap));
  xSemaphoreGive(EspNowMeshDriver.lock);
  uint32_t first = XdrvMailbox.data_len ? atoi(XdrvMailbox.data) : 0;
  Response_P(PSTR("{\"%s\":{\"Count\":%u,\"From\":%u,\"List\":["), XdrvMailbox.command, snap.neighbors, first);
  for (uint32_t i = first; (i < snap.neighbors) && (i < first + 6); i++) {
    const EspNowMeshNeighbor_t& n = snap.neighbor[i];
    char info[2 * EspNowMesh::kMaxInfo + 1];
    ToHex_P(n.info, n.info_len, info, sizeof(info));
    ResponseAppend_P(PSTR("%s{\"Id\":%u,\"State\":\"%s\",\"Rssi\":%d,\"TheirRssi\":%d,\"Lists\":%u,\"NoRadio\":%u,\"Age\":%u,\"Beat\":%d,\"Hears\":%u,\"Info\":\"%s\"}"),
      (i == first) ? PSTR("") : PSTR(","), n.id, EspNowMeshStateName(n.state), n.rssi, n.their_rssi, n.lists_me, n.no_radio, n.age_s,
      (0xFFFF == n.beat_s) ? -1 : (int)n.beat_s, n.hears, info);
  }
  ResponseAppend_P(PSTR("]}}"));
}

const char kEspNowMeshCommands[] PROGMEM = "|"
  "EspNowMeshEnable|EspNowMeshId|EspNowMeshChannel|EspNowMeshGroupKey|EspNowMeshNode|EspNowMeshPublic|EspNowMeshNetwork|"
  "EspNowMeshInfo|EspNowMeshSend|EspNowMeshStatus|EspNowMeshNeighbors";
void (* const kEspNowMeshCommand[])(void) PROGMEM = {
  &CmndEspNowMeshEnable, &CmndEspNowMeshId, &CmndEspNowMeshChannel, &CmndEspNowMeshGroupKey, &CmndEspNowMeshNode, &CmndEspNowMeshPublic,
  &CmndEspNowMeshNetwork, &CmndEspNowMeshInfo, &CmndEspNowMeshSend, &CmndEspNowMeshStatus, &CmndEspNowMeshNeighbors };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv100(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_PRE_INIT:
      EspNowMeshSettingsLoad();
      break;
    case FUNC_INIT:
      WiFi.onEvent(EspNowMeshWifiEvent);
      break;
    case FUNC_LOOP:
      EspNowMeshDrainEvents();
      break;
    case FUNC_EVERY_SECOND:
      EspNowMeshEverySecond();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowMeshCommands, kEspNowMeshCommand);
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_MESH
