/*
  xdrv_98_1_espnow_mesh.ino - ESP-NOW mesh: the radio task and the commands around the mesh core

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
 * link's when that starts. The direct link tells the mesh before it deinitialises ESP-NOW, and the mesh stops using the radio and
 * waits for a send it has under way to end: the radio has a lock, which the task holds while it sends, and the main loop while it
 * takes ESP-NOW apart, and nothing is sent while the WiFi stack is stopped. The radio's word on a frame comes with the address the
 * frame went to, which tells the mesh's frame from the direct link's when both send at once (two frames to the same address cannot be
 * told apart); a send the mesh stopped waiting for after 20 ms has its late word counted, and not taken for another's. A send
 * that is not acknowledged is handled by the core as it handles a lost frame.
 *
 * The radio's channel is the direct link's while its radio is up (EspNowChannel, or the station's): EspNowMeshChannel is the
 * channel when the mesh has ESP-NOW to itself, and the two never move the radio against each other.
 *
 * ESP-NOW holds 20 peers. The mesh registers the broadcast address and each neighbour a unicast goes to; when the table is full the
 * neighbour that has gone unused longest is given up to make room for the new one. The broadcast address, the peers of the direct
 * link and a neighbour sent to in the last 3 s are never given up, and when no peer can go the frame does not either (PeerFull).
 *
 * Born off, like the direct link: EspNowMeshEnable 1 starts it, and it stays on across restarts
 * once the device has a number (EspNowMeshId), the key of the network (EspNowMeshGroupKey) and
 * the nodes it talks to (EspNowMeshNode, with their public keys). The number, and the bits of
 * EspNowMeshNetwork that say no radio or relay, take effect at the next start; the other bit, the key
 * and the nodes at once. The key is a command argument, which Tasmota can log: set it over the web
 * API of a device on the LAN, as scripts/mesh-bench.mjs does, and not with the log level up. The device makes its own
 * identity, an X25519 key pair, the first time, and keeps it in its own NVS namespace, with the station address of the chip it
 * was made on: a record that comes from another chip, as a copy of the flash brings it, keeps what is configured and not the
 * identity, which is made again, and its epoch with it. Its public key is what the other devices are given (EspNowMeshPublic).
 *
 * The epoch rises with every start, and a start with a lower or the same one would be refused by every neighbour as an old one
 * and thought alive: so the epoch is saved and read back before the task that sends under it starts. A start whose epoch the flash
 * did not take does not go on, says so in the log and is tried again in ten seconds, and a command that changes the record and
 * finds the flash did not take it answers "flash write failed" and leaves the record as it was.
 *
 * The frames for the application are not taken until it says it is ready: with Berry running, until a script calls espnow_mesh_ready()
 * (or espnow_mesh_info()), which it does once its rules are registered; EspNowMeshReady 1 says it for the device whose rules are not a
 * script's. Until then a frame for this device alone is refused as when the inbox has no room, with no answer, and its sender sends it
 * again; a frame for everyone is repeated and not delivered here. What the core has for the application waits in its inbox while the
 * queue to the main loop is full, and is never dropped after it was answered; the outcomes and the notices have a queue of their own,
 * so that a burst of frames cannot push one out.
 *
 * Reported to the rule engine, and in the log:
 *   {"EspNowMesh":{"From":3,"Type":0,"Dest":1,"Counter":12,"Epoch":7,"Rssi":-61,"Flags":0,"Part":0,"Joins":0,"Behind":0,"Data":"68656c6c6f"}}
 *       a frame for this device, Data in hex; Flags 1 asks for an answer, 2 marks a repeat of one already given;
 *       Behind is how many numbers of its origin the frame was behind the newest heard, for the application to order by
 *   {"EspNowMesh":{"Outcome":{"Counter":5,"Frame":12,"Dest":3,"Ok":1,"Attempts":1}}}
 *       what became of a frame sent with an answer asked for. Counter is the ticket the send was given (what espnow_mesh_send returned,
 *       or EspNowMeshSend answered), Frame the number the frame had on the air, which the receiver reports as its Counter. A send the
 *       core refused (no room, no key, too long) has an outcome with Ok 0, no attempts and Frame 0
 *   {"EspNowMesh":{"Notice":{"Kind":"Silent","Node":3,"By":2,"Value":0}}}
 *       Silent, Back, Noisy, Calm, BulkDone, BulkLost
 *   {"EspNowMesh":{"Timeline":{"Old":"0300000007","New":"0100000002","Ticks":12,"Delta":"1184","Synced":1}}}
 *       the device took the timeline of the mesh clock (see EspNowMeshClock) that another one counts on: the one it left, the one it took, by how many
 *       ticks of 100 ms its mesh time moved (rounded to the nearest, from half up, as the low 32 bits of it, signed) and by how many ms (as text: it can
 *       pass 32 bits), for the application to move by whatever it marked in the timeline it left. A device takes a timeline whose time is greater than
 *       its own, or within a few tens of ms of it when the timeline has the lower identity, so Ticks is never below 0 (except as the low 32 bits of a
 *       move of more than 2^31 ticks: add it with a wrap of 32 bits) and Delta is below 0 only by those few ms, which round to 0 ticks.
 *       espnow_mesh_clock() answers in the new timeline from the moment the device took it,
 *       before this reaches the rules, so what the application marks after reading the clock is in the new one, and what it marked before is for the
 *       ticks to move
 *   {"EspNowMesh":{"Synced":{"Value":1,"Timeline":"0100000002","Tag":258}}}
 *       the synced bit of the clock changed, to Value: the device has taken a timeline, or has listened for 10 s and found none to take
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
 *   EspNowMeshSend <dest>,<type>,<ack 0|1>,<text or 0xHEX> - a frame; dest 255 is everyone; type 0 command, 2 state, 3 event; answers
 *                                {"Queued":1,"Counter":<ticket>}, or "busy" when the queue to the task is full, or "not running"
 *   EspNowMeshReady [0|1]      - whether the application is ready to take frames, as above
 *   EspNowMeshStatus           - the state of the task, and the counters that say how the frames fared
 *   EspNowMeshStats [0|1]      - every counter, in two pages: 0 the frames and what the driver counts of its own (the queues, the
 *                                radio's refusals, the late word of the radio, the peers given up), 1 the supervision, the sync, the
 *                                lists in pieces and the network. All count from the start of the node
 *   EspNowMeshNeighbors [<first>] - the neighbours the heartbeats have given, as many as a message takes from the one asked for: Count is all of them, From
 *                                where this page starts, and Next, only when some remain, where the next one does (a bridge's 32 bytes of Info are 64
 *                                characters, so a page can be as few as five). EspNowMeshHealth and EspNowMeshClock page the same way
 *   EspNowMeshHealth [<first>] - what the heartbeats say of the surroundings, two hops deep: the neighbours that are counted on, how many of each one's
 *                                heartbeats come, the groups the neighbours fall in, and which neighbour is the only way to some node
 *   EspNowMeshClock [<first>]  - the mesh clock: the time this device counts since it started, ms, and the timeline it counts on (its own number and epoch, until
 *                                it takes another), whether it is synced, how many times the clock was stepped to follow a neighbour, how many timelines
 *                                were taken, and the neighbours heard, each with the timeline of its last heartbeat (Seen 0: none, 1: another,
 *                                2: this one), its synced bit, and how far its time was from this device's when the heartbeat came (Skew, ms)
 *
 * The mesh clock: the heartbeat carries the time and the timeline, and a device that hears another timeline whose time is greater takes it, and follows the
 * time of a neighbour in its own when it is greater, as the timing synchronisation function of an IEEE 802.11 IBSS does. The real-time clock is never read.
 * The heartbeat's bytes of the application (EspNowMeshInfo) begin with a layout byte, 1; the device fills in bytes 0 to 11 (the layout, the timeline, the
 * time) and bit 0 of byte 19 (synced) as it sends, and the rest are the application's, up to 32. ESPNOW_MESH_CLOCK 0 leaves the heartbeat as it was.
 *
 * And, in Berry, without the trip through the command handler:
 *   espnow_mesh_send(dest, type, ack, data) - the ticket of the send, an integer above 0, or false when it was not taken; data is bytes
 *                                             or a string, up to espnow_mesh_max_payload(dest)
 *   espnow_mesh_max_payload(dest)           - the most bytes a payload to dest can be
 *   espnow_mesh_info(data)                  - true when the task took the bytes (up to 32) every heartbeat carries; says the application is ready
 *   espnow_mesh_ready([ready])              - true; says the application is ready, or with false that it is not
 *   espnow_mesh_clock()                     - a map of the mesh clock, or false when the task is not running: synced, adopted (the device has taken a
 *                                             timeline since it started), ticks10 and ticks100 (the mesh time in ticks of 10 and 100 ms, the low 32
 *                                             bits, signed: compare two of them by their difference), tag (the 16 bits that name the timeline in a stamp),
 *                                             timeline (hex, 10 digits), taken (the timelines taken since the device started) and lo, hi (the mesh time
 *                                             in ms, the low 32 bits and the rest)
 *   espnow_mesh_stamp()                     - the 6 bytes that vouch for the time a message was made at: the tag (2 bytes) and the mesh time in ticks of 10 ms
 *                                             (4), most significant first; false when the device is not synced, or the task is not running
 *   espnow_mesh_age(stamp)                  - a map of how old a stamp is by this device's clock now: age (ms, signed: negative for one from the future),
 *                                             tag (true when the stamp is of this device's timeline: the time of another has no meaning here) and
 *                                             synced; false when the bytes are not a stamp or the task is not running
 *   espnow_mesh_neighbors()                 - a list with a map for each neighbour, as the task last saw them (up to half a second ago): id, state (0 alive,
 *                                             1 suspect, 2 silent), rssi, age (ms since something of it got through), beat (ms since its last heartbeat, -1
 *                                             if none), info (hex: the application's bytes of its last heartbeat, which are its to say), seen and skew (the
 *                                             clock of its last heartbeat: 0 it carried none, 1 another timeline than this device's, 2 the same; and how
 *                                             far its time was from this device's when it came, ms); false when the task is not running
\*********************************************************************************************/

#define XDRV_100                       100

#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <WiFiUdp.h>
#include "espnow_mesh_core.h"
#include "espnow_mesh_crypto.h"

#define ESPNOW_MESH_SETTINGS_VERSION   3           // 2: the same record without the address of the chip; 1: and with room for 16 nodes. Both are taken as they are
#define ESPNOW_MESH_NVS_NAMESPACE      "espnowmesh"
#define ESPNOW_MESH_NODES              48          // as many as the core keeps of origins and of neighbours
#define ESPNOW_MESH_UDP_PORT           47474
#define ESPNOW_MESH_RX_DEPTH           8
#define ESPNOW_MESH_CMD_DEPTH          4
#define ESPNOW_MESH_EVENT_DEPTH        8           // frames for the application on their way to the main loop: the inbox of the core keeps 8 more
#define ESPNOW_MESH_NOTE_DEPTH         16          // outcomes and notices on their way to the main loop: the core keeps 8 of each
#define ESPNOW_MESH_SENT_DEPTH         16          // the frames sent with an answer asked, whose ticket is kept until their outcome comes
#define ESPNOW_MESH_TASK_STACK         6144
#define ESPNOW_MESH_TASK_PRIORITY      5
#define ESPNOW_MESH_SEND_WAIT_MS       20          // for the radio to say what became of a frame
#define ESPNOW_MESH_LATE_WORD_MS       1000        // after which a word of the radio's that comes is no late word of a send that gave up
#define ESPNOW_MESH_PEER_KEEP_MS       3000        // a peer sent to within this is not the one to give up when the radio's table is full
#define ESPNOW_MESH_BEAT_MS            5000
#define ESPNOW_MESH_SNAPSHOT_MS        500
#define ESPNOW_MESH_SENDS_PER_TURN     4
#ifndef ESPNOW_MESH_CHOOSE_RELAYS
#define ESPNOW_MESH_CHOOSE_RELAYS      1           // 1: the device chooses the neighbours that repeat for it, says whom in its heartbeat and repeats later when a sender did not choose it; 0: every device that hears a flooded frame repeats it
#endif
#ifndef ESPNOW_MESH_CLOCK
#define ESPNOW_MESH_CLOCK              1           // 1: the heartbeat carries the mesh clock and the device takes it from the ones it hears; 0: the application's bytes go as they are
#endif
#define ESPNOW_MESH_CLOCK_REFRESH_MS   500         // the clock the main loop reads is made again at least this often, so that it never grows older than the counter can tell

#define ESPNOW_MESH_NET_UDP            1
#define ESPNOW_MESH_NET_NO_RADIO       2
#define ESPNOW_MESH_NET_RELAY          4

typedef struct {
  uint8_t id;                                // 0: the slot is free
  uint8_t mac[6];
  uint8_t pub[32];
  uint8_t ip[4];                             // 0.0.0.0: not known
} EspNowMeshNode_t;

// The device's record, saved as one block in its own NVS namespace. A record of an earlier version is the front of this one, and the
// rest of it is cleared when it is read: version 1 ends after the 16th node, version 2 after the 48th
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
  uint8_t mac[6];                            // the station address of the chip the identity was made on (since version 3)
  uint8_t spare_end[2];
} EspNowMeshSettings;

// The sizes the record has had, which a record read is held to
#define ESPNOW_MESH_RECORD_V1_SIZE     (offsetof(decltype(EspNowMeshSettings), node) + 16 * sizeof(EspNowMeshNode_t))
#define ESPNOW_MESH_RECORD_V2_SIZE     offsetof(decltype(EspNowMeshSettings), mac)
static_assert(ESPNOW_MESH_RECORD_V1_SIZE == 768, "the record of version 1 is 768 bytes");
static_assert(ESPNOW_MESH_RECORD_V2_SIZE == 2144, "the record of version 2 is 2144 bytes");
static_assert(sizeof(EspNowMeshSettings) == 2152, "the record of version 3 is 2152 bytes");

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
  uint32_t ticket;                           // what the caller is given for a send, and its outcome carries
  uint8_t data[EspNowMesh::kMaxPayload];
} EspNowMeshCmd_t;

// What the core has to tell the main loop: the frames for this device, one to an item of the queue that carries them
typedef struct {
  uint8_t origin;
  uint8_t type;
  uint8_t flags;                             // 1 answer asked, 2 repeat
  uint8_t part;
  uint8_t attempt;
  uint8_t behind;                            // how many numbers of its origin the frame was behind the newest heard
  uint8_t dest;
  int8_t rssi;
  uint32_t counter;
  uint32_t epoch;
  uint32_t joins;
  uint8_t len;
  uint8_t data[EspNowMesh::kMaxPayload];
} EspNowMeshEvent_t;

// And the rest of it, which is small and has a queue of its own: a delivery that waits for the main loop must never push out the word
// that a node went silent, or that a frame was not answered
#define ESPNOW_MESH_NOTE_OUTCOME       1
#define ESPNOW_MESH_NOTE_NOTICE        2
#define ESPNOW_MESH_NOTE_TIMELINE      3       // the clock took another timeline
#define ESPNOW_MESH_NOTE_SYNCED        4       // and the synced bit changed
typedef struct {
  uint8_t kind;
  uint8_t node;                              // a notice's node
  uint8_t type;                              // a notice's kind
  uint8_t ok;                                // an outcome's: answered; a clock note's: synced
  uint8_t attempts;                          // an outcome's
  uint8_t dest;                              // an outcome's frame's destination; a notice's: by
  uint8_t from[5];                           // a clock note's: the timeline left
  uint8_t to[5];                             // and the timeline the clock is in
  uint32_t counter;                          // an outcome's: the ticket the send gave; a notice's value; a timeline's: the ticks of 100 ms it moved by
  uint32_t frame;                            // an outcome's: the number the frame had on the air, 0 for one that was never sent; a timeline's: the ms it moved by, low 32 bits
  uint32_t delta_high;                       // and the high 32 bits of them
} EspNowMeshNote_t;

typedef struct {
  uint8_t id;
  uint8_t state;
  uint8_t lists_me;
  uint8_t no_radio;
  int8_t rssi;
  int8_t their_rssi;
  uint16_t age_s;                            // since something of it got through
  uint16_t beat_s;                           // since its last heartbeat, 0xFFFF if none
  uint32_t heard_at;                         // the millisecond counter when something of it last got through, and when its last heartbeat came (0 if none)
  uint32_t beat_at;
  uint8_t hears;
  uint8_t info_len;
  uint8_t info[EspNowMesh::kMaxInfo];
  int16_t clock_skew;                        // its mesh time in its last heartbeat less this device's when it came, ms
  uint8_t clock_seen;                        // 0 its heartbeat carried no clock, 1 it did and it is in another timeline, 2 the same
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
  EspNowMesh::Health health;                 // what the heartbeats say of the surroundings, two hops deep
  uint8_t health_links;
  EspNowMeshNeighbor_t neighbor[EspNowMesh::kMaxNeighbors];
  EspNowMesh::HealthLink link[EspNowMesh::kMaxNeighbors];
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
  uint8_t send_to[6] = {0};                  // the address of the frame the task waits for the radio's word on
  volatile bool late_pending = false;        // a send gave up waiting, and its word may still come
  uint8_t late_to[6] = {0};
  uint32_t late_at = 0;
  volatile bool config_dirty = false;
  uint32_t epoch_ahead = 0;                  // an epoch saved by a start that failed after it: no frame went under it, and the next start takes it
  volatile bool app_ready = true;            // the application has its rules registered: until it says so the frames for it are not taken
  volatile bool epoch_renew = false;         // the counter of the core is near its end: the mesh starts again, under the next epoch
  uint32_t ticket = 0;                       // the last a send was given, by the main loop alone
  volatile uint32_t dropped = 0;             // frames the callback had no room for
  uint8_t applied_channel = 0;
  EspNowMesh::Node* node = nullptr;
  EspNowMesh::Crypto* crypto = nullptr;
  EspNowMeshSnapshot_t* snapshot = nullptr;
  EspNowMeshShared_t* shared = nullptr;
  QueueHandle_t rx = nullptr;
  QueueHandle_t cmd = nullptr;
  QueueHandle_t event = nullptr;             // the frames for the application
  QueueHandle_t note = nullptr;              // the outcomes and the notices
  SemaphoreHandle_t send_done = nullptr;
  SemaphoreHandle_t lock = nullptr;          // the shared copy and the snapshot
  SemaphoreHandle_t radio_lock = nullptr;    // the radio, between the task that sends and the main loop that takes ESP-NOW apart; made once, never freed
  TaskHandle_t task = nullptr;
  // The mesh clock, as the task last made it, for the main loop to read under the lock: the mesh time at that instant of the millisecond counter, and the
  // main loop adds what the counter has gone on by. The task makes it again when the clock changes and at least every ESPNOW_MESH_CLOCK_REFRESH_MS
  bool clock_valid = false;
  EspNowMesh::ClockPoint clock_point;
  uint32_t clock_taken = 0;                  // the timelines the clock has taken since the start
  uint32_t clock_version = 0;                // the task's alone: the version of the clock that was made, and when
  uint32_t clock_made_at = 0;
} EspNowMeshDriver;

// What the driver counts of its own, for the status: the core counts the frames, this counts what happens around it
static struct {
  volatile uint32_t cmd_busy = 0;            // commands refused because the queue to the task was full
  volatile uint32_t evt_full = 0;            // turns of the task that found the queue to the main loop full: what the core had for the application waited in its inbox
  volatile uint32_t note_lost = 0;           // outcomes and notices the queue to the main loop had no room for: 0 unless the main loop stops
  volatile uint32_t refused = 0;             // sends the core refused
  volatile uint32_t send_failed = 0;         // unicast sends ESP-NOW did not take
  volatile uint32_t bcast_failed = 0;        // broadcasts it did not take, or whose address it would not register
  volatile uint32_t peer_failed = 0;         // the address of a neighbour it would not register
  volatile uint32_t peer_full = 0;           // one for which its table was full and none of its peers could be given up
  volatile uint32_t peer_evicted = 0;        // peers given up to make room
  volatile uint32_t wait_expired = 0;        // the wait for the radio's word on a frame ran out
  volatile uint32_t late_word = 0;           // and the word came later
  volatile uint32_t not_acked = 0;           // unicast sends the radio said the neighbour did not acknowledge
} EspNowMeshCount;

// What the task keeps of the frames it sent with an answer asked, for the outcome to say which send it is: the number a frame has on
// the air is the core's, and the caller was given a ticket before the frame had one. The task's alone
typedef struct {
  uint32_t frame;                            // 0: free
  uint32_t ticket;
  uint8_t dest;
} EspNowMeshSent_t;
static EspNowMeshSent_t EspNowMeshSent[ESPNOW_MESH_SENT_DEPTH];
static uint8_t EspNowMeshSentNext = 0;

static const uint8_t EspNowMeshBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*********************************************************************************************\
 * Settings
\*********************************************************************************************/

static void EspNowMeshWipe(void* buffer, size_t len) {
  volatile uint8_t* p = (volatile uint8_t*)buffer;
  while (len--) { *p++ = 0; }
}

// The record, written as one blob and read back: ESP_OK only when what the flash holds is what is here. The NvmSave that the rest of
// the firmware uses says nothing of whether it wrote, and a record that did not get there would be found as it was at the next start
static esp_err_t EspNowMeshSave(void);
static esp_err_t EspNowMeshSave(void) {
  nvs_handle_t handle;
  esp_err_t error = nvs_open(ESPNOW_MESH_NVS_NAMESPACE, NVS_READWRITE, &handle);
  if (ESP_OK != error) { return error; }
  error = nvs_set_blob(handle, "settings", &EspNowMeshSettings, sizeof(EspNowMeshSettings));
  if (ESP_OK == error) { error = nvs_commit(handle); }
  if (ESP_OK == error) {
    size_t size = 0;
    error = nvs_get_blob(handle, "settings", nullptr, &size);
    if ((ESP_OK == error) && (size != sizeof(EspNowMeshSettings))) { error = ESP_ERR_INVALID_SIZE; }
    if (ESP_OK == error) {
      uint8_t* copy = (uint8_t*)malloc(size);          // the identity is in it: wiped before it is let go
      if (nullptr == copy) {
        error = ESP_ERR_NO_MEM;
      } else {
        error = nvs_get_blob(handle, "settings", copy, &size);
        if ((ESP_OK == error) && ((size != sizeof(EspNowMeshSettings)) || memcmp(copy, &EspNowMeshSettings, sizeof(EspNowMeshSettings)))) {
          error = ESP_ERR_INVALID_CRC;
        }
        EspNowMeshWipe(copy, sizeof(EspNowMeshSettings));
        free(copy);
      }
    }
  }
  nvs_close(handle);
  return error;
}

// What the entries of the NVS partition come to, for the log: the epoch and the identity live there, and a partition with no room
// takes neither
static void EspNowMeshLogNvs(void) {
  nvs_stats_t stats;
  if (ESP_OK == nvs_get_stats(nullptr, &stats)) {
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: NVS %u of %u entries used, %u free, %u namespaces"),
      (uint32_t)stats.used_entries, (uint32_t)stats.total_entries, (uint32_t)stats.free_entries, (uint32_t)stats.namespace_count);
  }
}

// What the flash holds as the record. A record of a version this firmware knows is taken, the front of this one. One whose size is
// none the versions had, or that cannot be read, is not understood: the device starts over with an identity of its own, and says so.
// A record made on another chip, which a copy of the flash brings, keeps the key of the network and the nodes, and not what makes the
// device the one it was made on: not the identity, and not the number either, so that no two devices have one. It starts as a new one
// does, with the mesh off, until it is given a number (EspNowMeshId) and started
static void EspNowMeshSettingsLoad(void) {
  memset(&EspNowMeshSettings, 0, sizeof(EspNowMeshSettings));
  const char* trouble = nullptr;
  size_t size = 0;
  nvs_handle_t handle;
  esp_err_t error = nvs_open(ESPNOW_MESH_NVS_NAMESPACE, NVS_READONLY, &handle);
  if (ESP_OK == error) {
    error = nvs_get_blob(handle, "settings", nullptr, &size);
    if (ESP_OK == error) {
      size_t read = size;
      if (size > sizeof(EspNowMeshSettings)) {
        trouble = PSTR("is longer than any this firmware knows");
      } else if ((ESP_OK != nvs_get_blob(handle, "settings", &EspNowMeshSettings, &read)) || (read != size)) {
        trouble = PSTR("could not be read");
      } else if (!(((1 == EspNowMeshSettings.version) && (ESPNOW_MESH_RECORD_V1_SIZE == size)) ||
                   ((2 == EspNowMeshSettings.version) && (ESPNOW_MESH_RECORD_V2_SIZE == size)) ||
                   ((ESPNOW_MESH_SETTINGS_VERSION == EspNowMeshSettings.version) && (sizeof(EspNowMeshSettings) == size)))) {
        trouble = PSTR("has a size that does not go with its version");
      }
    } else if (ESP_ERR_NVS_NOT_FOUND != error) {
      trouble = PSTR("could not be sized");
    }
    nvs_close(handle);
  } else if (ESP_ERR_NVS_NOT_FOUND != error) {
    trouble = PSTR("namespace could not be opened");
  }                                            // otherwise nothing was ever saved: a device not set up yet
  if (trouble) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EMH: The saved record of %u bytes %s (error %d): the device starts over, with an identity of its own"), (uint32_t)size, trouble, error);
    EspNowMeshWipe(&EspNowMeshSettings, sizeof(EspNowMeshSettings));
  }

  uint8_t own[6];
  esp_read_mac(own, ESP_MAC_WIFI_STA);
  static const uint8_t no_mac[6] = {0, 0, 0, 0, 0, 0};
  if (memcmp(EspNowMeshSettings.mac, no_mac, 6) && memcmp(EspNowMeshSettings.mac, own, 6)) {
    char text[18];
    ToHex_P(EspNowMeshSettings.mac, 6, text, sizeof(text), ':');
    if (EspNowMeshSettings.has_secret) {
      AddLog(LOG_LEVEL_INFO, PSTR("EMH: The record was made on the chip %s, and this is another: the identity and the epoch are made again, and the new public key is to be given to the other nodes"), text);
      EspNowMeshWipe(EspNowMeshSettings.secret, sizeof(EspNowMeshSettings.secret));
      EspNowMeshSettings.has_secret = 0;
      EspNowMeshSettings.epoch = 0;
    }
    if (EspNowMeshSettings.id || EspNowMeshSettings.enabled) {
      AddLog(LOG_LEVEL_INFO, PSTR("EMH: The record was made on the chip %s: its node number %u was cleared and the mesh is off, as on a new device; give this one a number with EspNowMeshId, then EspNowMeshEnable 1"), text, EspNowMeshSettings.id);
      EspNowMeshSettings.id = 0;
      EspNowMeshSettings.enabled = 0;
    }
  }
  memcpy(EspNowMeshSettings.mac, own, 6);      // a record of version 1 or 2, or none, is taken to be this chip's
  EspNowMeshSettings.version = ESPNOW_MESH_SETTINGS_VERSION;
}

// The record saved, and read back. When the flash does not take it the record is what the flash holds, as it will be at the next start:
// what a command changed is undone, and the command says so
static bool EspNowMeshSettingsCommit(void);
static bool EspNowMeshSettingsCommit(void) {
  esp_err_t error = EspNowMeshSave();
  if (ESP_OK == error) { return true; }
  AddLog(LOG_LEVEL_ERROR, PSTR("EMH: The flash did not take the record (error 0x%X): it is as it was"), error);
  EspNowMeshSettingsLoad();
  return false;
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

// The core's counter has passed the point where it wants the next epoch. The epoch is the one the next start saves, so it is not the task's to take:
// the task says no and the main loop starts the mesh again (EspNowMeshEverySecond), which numbers from 1 under an epoch above this one that the flash
// has kept. The core goes on giving numbers, some 65 000 of them, until the main loop has done it
static bool EspNowMeshRenewEpoch(void* context, uint32_t epoch) {
  (void)context;
  (void)epoch;
  EspNowMeshDriver.epoch_renew = true;
  return false;
}

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

// The radio's word on a frame it was given, from the WiFi task, with the address the frame went to. True when the word was the task's to
// hear: the one for the frame it is sending, or the late one for a frame it gave up waiting for, which no other sender is to take as its
// own. The address is what tells the mesh's frame from the direct link's when both send at once; two frames to the same address cannot
// be told apart, and are taken in the order the task sent them
bool EspNowMeshSendResult(const uint8_t* mac, bool ok);
bool EspNowMeshSendResult(const uint8_t* mac, bool ok) {
  if (EspNowMeshDriver.awaiting && !memcmp(mac, EspNowMeshDriver.send_to, 6)) {
    EspNowMeshDriver.send_ok = ok;
    EspNowMeshDriver.awaiting = false;
    if (EspNowMeshDriver.send_done) { xSemaphoreGive(EspNowMeshDriver.send_done); }
    return true;
  }
  // A send the task stopped waiting for is answered late, within a second or so: that word is counted, and it is not the next send's
  if (EspNowMeshDriver.late_pending && !memcmp(mac, EspNowMeshDriver.late_to, 6)) {
    EspNowMeshDriver.late_pending = false;
    if ((millis() - EspNowMeshDriver.late_at) < ESPNOW_MESH_LATE_WORD_MS) {
      EspNowMeshCount.late_word++;
      return true;
    }
  }
  return false;
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
  EspNowMeshSendResult(info->des_addr, ESP_NOW_SEND_SUCCESS == status);
}

static bool EspNowMeshRadioReady(void) {
  return (WiFi.getMode() & WIFI_MODE_STA);
}

// The radio is the task's while it sends, and the main loop's while it takes ESP-NOW apart or puts peers in it: the one that has the
// lock is the only one that touches the radio's peer table, sends, starts it or stops it. Held for the few milliseconds of a send
static bool EspNowMeshRadioTake(uint32_t ms) {
  return (nullptr == EspNowMeshDriver.radio_lock) || (pdTRUE == xSemaphoreTake(EspNowMeshDriver.radio_lock, pdMS_TO_TICKS(ms)));
}

static void EspNowMeshRadioGive(void) {
  if (EspNowMeshDriver.radio_lock) { xSemaphoreGive(EspNowMeshDriver.radio_lock); }
}

// The peers the mesh has added to ESP-NOW, each with when a frame last went to it. The radio holds 20 at most, one of them the broadcast
// address and one the direct link's, and neither of those is in this table: only a peer that is in it is given up. Under the radio's lock
typedef struct {
  uint8_t mac[6];
  uint32_t used_at;
  bool used;
} EspNowMeshPeer_t;
static EspNowMeshPeer_t EspNowMeshPeers[ESP_NOW_MAX_TOTAL_PEER_NUM];

static int32_t EspNowMeshPeerFind(const uint8_t* mac) {
  for (int32_t i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
    if (EspNowMeshPeers[i].used && !memcmp(EspNowMeshPeers[i].mac, mac, 6)) { return i; }
  }
  return -1;
}

// What it is worth to give a peer up, the largest going first, and 0 for one that is never to go. A peer sent to within the last few seconds
// is never given up, and neither is one that is the only neighbour to list some node that no other neighbour lists: it is this device's only
// way to that node. Of the others the ones the device no longer hears go first, then the ones it hears and does not count on because they
// deliver too few of their heartbeats, then the redundant ones, and in each the one that has gone unused longest. What the core knows of the
// neighbours is the task's to read: from another thread the cost is the time unused alone
static uint32_t EspNowMeshPeerCost(const EspNowMeshPeer_t& peer, uint32_t now);
static uint32_t EspNowMeshPeerCost(const EspNowMeshPeer_t& peer, uint32_t now) {
  uint32_t idle = now - peer.used_at;
  if (idle < ESPNOW_MESH_PEER_KEEP_MS) { return 0; }
  uint32_t band = 1;
  if (EspNowMeshDriver.node && (xTaskGetCurrentTaskHandle() == EspNowMeshDriver.task)) {
    switch (EspNowMeshDriver.node->PeerRoleOf(peer.mac, now)) {
      case EspNowMesh::kPeerOnlyWay: return 0;
      case EspNowMesh::kPeerGone: band = 3; break;
      case EspNowMesh::kPeerWeak: band = 2; break;
      default: break;
    }
  }
  if (idle > 0x0FFFFFFF) { idle = 0x0FFFFFFF; }
  return (band << 28) | idle;
}

static int32_t EspNowMeshPeerVictim(uint32_t now) {
  int32_t victim = -1;
  uint32_t most = 0;
  for (int32_t i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
    if (!EspNowMeshPeers[i].used) { continue; }
    uint32_t cost = EspNowMeshPeerCost(EspNowMeshPeers[i], now);
    if (cost > most) { most = cost; victim = i; }
  }
  return victim;
}

// The address of a neighbour is added when the first frame goes to it. When the table of the radio is full the peer that has gone unused
// longest makes room for it, and when there is none that can go, the frame does not either. True when `to` is a peer now
static bool EspNowMeshAddPeer(const uint8_t* to, uint32_t now);
static bool EspNowMeshAddPeer(const uint8_t* to, uint32_t now) {
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, to, 6);
  peer.channel = 0;                          // the channel the radio is on, wherever it is
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;                      // the frames of the mesh are sealed by the mesh
  esp_err_t error = esp_now_add_peer(&peer);
  if (ESP_ERR_ESPNOW_FULL == error) {
    int32_t victim = EspNowMeshPeerVictim(now);
    if (victim < 0) {
      EspNowMeshCount.peer_full++;
      return false;
    }
    esp_now_del_peer(EspNowMeshPeers[victim].mac);
    EspNowMeshPeers[victim].used = false;
    EspNowMeshCount.peer_evicted++;
    error = esp_now_add_peer(&peer);
  }
  if ((ESP_OK != error) && (ESP_ERR_ESPNOW_EXIST != error)) { return false; }
  if (memcmp(to, EspNowMeshBroadcast, 6) && (ESP_ERR_ESPNOW_EXIST != error)) {
    int32_t slot = EspNowMeshPeerFind(to);
    for (int32_t i = 0; (slot < 0) && (i < ESP_NOW_MAX_TOTAL_PEER_NUM); i++) { if (!EspNowMeshPeers[i].used) { slot = i; } }
    if (slot >= 0) {
      memcpy(EspNowMeshPeers[slot].mac, to, 6);
      EspNowMeshPeers[slot].used_at = now;
      EspNowMeshPeers[slot].used = true;
    }
  }
  return true;
}

// The broadcast address, with no key, on whatever channel the radio is on. The addresses of the neighbours are added when
// the first frame goes to them
static void EspNowMeshAddBroadcast(void) {
  if (!EspNowMeshRadioTake(100)) { return; }
  if (!esp_now_is_peer_exist(EspNowMeshBroadcast)) { EspNowMeshAddPeer(EspNowMeshBroadcast, millis()); }
  EspNowMeshRadioGive();
}

// The direct link's driver is about to stop or start ESP-NOW, or has: it deinitialises it, and starts it with no peer in it, so the mesh's
// addresses are added again as the frames go to them. The mesh stops using the radio first, before the direct link touches it, and waits
// for a send that is under way to end: a deinitialisation that comes in the middle of one is a fault, or a frame that is lost
void EspNowMeshDirectRadio(bool up);
void EspNowMeshDirectRadio(bool up) {
  if (up) {
    EspNowMeshDriver.direct_radio = true;
    EspNowMeshDriver.own_radio = false;            // what the mesh had started was deinitialised by the direct link's start
    EspNowMeshDriver.radio_lost = false;
    if (EspNowMeshRadioTake(100)) {
      memset(EspNowMeshPeers, 0, sizeof(EspNowMeshPeers));
      EspNowMeshRadioGive();
    }
    if (EspNowMeshDriver.running || EspNowMeshSettings.enabled) { EspNowMeshAddBroadcast(); }
    EspNowMeshDriver.radio = true;
  } else {
    EspNowMeshDriver.direct_radio = false;
    EspNowMeshDriver.radio = false;                // the mesh starts its own at the next second
    EspNowMeshDriver.own_radio = false;            // and what it had started is the direct link's to deinitialise now
    if (EspNowMeshRadioTake(2 * ESPNOW_MESH_SEND_WAIT_MS)) {         // the task is out of a send that was under way
      memset(EspNowMeshPeers, 0, sizeof(EspNowMeshPeers));
      EspNowMeshRadioGive();
    }
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
  if (EspNowMeshRadioTake(100)) {                  // a table that was just made has no peer in it
    memset(EspNowMeshPeers, 0, sizeof(EspNowMeshPeers));
    EspNowMeshRadioGive();
  }
  EspNowMeshAddBroadcast();
  EspNowMeshDriver.own_radio = true;
  EspNowMeshDriver.radio = true;
  return true;
}

static void EspNowMeshRadioStop(void) {
  if (!EspNowMeshDriver.radio) { return; }
  EspNowMeshDriver.radio = false;
  bool own = EspNowMeshDriver.own_radio;
  if (EspNowMeshRadioTake(2 * ESPNOW_MESH_SEND_WAIT_MS)) {      // the task is out of a send that was under way, and starts none
    // The direct link's radio stays as it is, and the neighbours the mesh put in its table go: they would be in it for good, with nothing
    // to say they are the mesh's to give up
    if (!own && !EspNowMeshDriver.radio_lost && EspNowMeshRadioReady()) {
      for (int32_t i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
        if (EspNowMeshPeers[i].used) { esp_now_del_peer(EspNowMeshPeers[i].mac); }
      }
    }
    memset(EspNowMeshPeers, 0, sizeof(EspNowMeshPeers));
    EspNowMeshRadioGive();
  }
  if (!own) { return; }
  EspNowMeshDriver.own_radio = false;
  // esp_now_deinit() faults when the WiFi stack is not there
  if (EspNowMeshRadioReady()) {
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    esp_now_deinit();
  }
}

// The radio goes to the configured channel when the station is not associated. With the station associated, the access
// point's channel is the channel. With the direct link's radio up the channel is the direct link's (EspNowChannel, or the station's): it
// moves the radio and starts ESP-NOW again when it changes, and a second channel that moved it back would be a fight every second
static void EspNowMeshApplyChannel(void) {
  if (!EspNowMeshSettings.channel || EspNowMeshDriver.direct_radio) { return; }
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

// With the radio's lock: the peer, the send and the wait for the radio's word, none of which the main loop takes apart under it
static bool EspNowMeshRadioSendLocked(const uint8_t* to, const uint8_t* frame, size_t len);
static bool EspNowMeshRadioSendLocked(const uint8_t* to, const uint8_t* frame, size_t len) {
  uint32_t now = millis();
  bool broadcast = !memcmp(to, EspNowMeshBroadcast, 6);
  if (!esp_now_is_peer_exist(to)) {
    if (!EspNowMeshAddPeer(to, now)) {
      if (broadcast) { EspNowMeshCount.bcast_failed++; } else { EspNowMeshCount.peer_failed++; }
      return false;
    }
  } else if (!broadcast) {
    int32_t slot = EspNowMeshPeerFind(to);       // a peer of the direct link's is not in the table, and is never given up
    if (slot >= 0) { EspNowMeshPeers[slot].used_at = now; }
  }
  // A word from an earlier send that came late is not this one's: the semaphore is emptied before the send is armed
  xSemaphoreTake(EspNowMeshDriver.send_done, 0);
  EspNowMeshDriver.send_ok = false;
  memcpy(EspNowMeshDriver.send_to, to, 6);
  EspNowMeshDriver.awaiting = true;
  if (ESP_OK != esp_now_send(to, frame, len)) {
    EspNowMeshDriver.awaiting = false;
    xSemaphoreTake(EspNowMeshDriver.send_done, 0);
    if (broadcast) { EspNowMeshCount.bcast_failed++; } else { EspNowMeshCount.send_failed++; }
    return false;
  }
  if (pdTRUE != xSemaphoreTake(EspNowMeshDriver.send_done, pdMS_TO_TICKS(ESPNOW_MESH_SEND_WAIT_MS))) {
    EspNowMeshDriver.awaiting = false;       // no word: not acknowledged
    xSemaphoreTake(EspNowMeshDriver.send_done, 0);
    EspNowMeshCount.wait_expired++;
    memcpy(EspNowMeshDriver.late_to, to, 6);
    EspNowMeshDriver.late_at = millis();
    EspNowMeshDriver.late_pending = true;    // the word may still come: it is this send's
    return false;
  }
  if (!EspNowMeshDriver.send_ok && !broadcast) { EspNowMeshCount.not_acked++; }
  return EspNowMeshDriver.send_ok;
}

// One frame, to one address, and the radio's word on it. A unicast the other side did not acknowledge says so; a broadcast never
// does, and counts as sent. Nothing goes while the radio is not there: the direct link has it apart, or the WiFi stack stopped under it
static bool EspNowMeshRadioSend(const uint8_t* to, const uint8_t* frame, size_t len) {
  if (!EspNowMeshDriver.radio || EspNowMeshDriver.radio_lost) { return false; }
  if (!EspNowMeshRadioTake(100)) { return false; }
  bool ok = false;
  // The radio is looked at again with the lock: what took it apart has it first, and puts nothing back before it gives it up
  if (EspNowMeshDriver.radio && !EspNowMeshDriver.radio_lost) { ok = EspNowMeshRadioSendLocked(to, frame, len); }
  EspNowMeshRadioGive();
  return ok;
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
  // The copy is 2 KB with 48 nodes: on the heap for the while it takes, and not on the stack of the task. If there is no room the
  // configuration stays marked as changed, and the next turn of the task tries again
  EspNowMeshShared_t* fresh = new (std::nothrow) EspNowMeshShared_t;
  if (nullptr == fresh) { return; }
  xSemaphoreTake(EspNowMeshDriver.lock, portMAX_DELAY);
  memcpy(fresh, shared, sizeof(*fresh));
  EspNowMeshDriver.config_dirty = false;
  xSemaphoreGive(EspNowMeshDriver.lock);

  if (fresh->has_group) { EspNowMeshDriver.crypto->SetGroupKey(fresh->group_key, fresh->group_version); }
  // The keys of the nodes that left, or whose key changed, go first: a node that moved to another slot would otherwise have its
  // new key made and then forgotten
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    const EspNowMeshNode_t& old_entry = EspNowMeshTable[i];
    const EspNowMeshNode_t& entry = fresh->node[i];
    if (old_entry.id && ((old_entry.id != entry.id) || memcmp(old_entry.pub, entry.pub, sizeof(entry.pub)))) {
      EspNowMeshDriver.crypto->ForgetPeer(old_entry.id);
    }
  }
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    const EspNowMeshNode_t& old_entry = EspNowMeshTable[i];
    const EspNowMeshNode_t& entry = fresh->node[i];
    if (entry.id && ((old_entry.id != entry.id) || memcmp(old_entry.pub, entry.pub, sizeof(entry.pub)) || !EspNowMeshDriver.crypto->HasPeer(entry.id))) {
      if (!EspNowMeshDriver.crypto->SetPeer(entry.id, entry.pub)) {
        AddLog(LOG_LEVEL_INFO, PSTR("EMH: The public key of node %u gives no key"), entry.id);
      }
    }
  }
  memcpy(EspNowMeshTable, fresh->node, sizeof(EspNowMeshTable));
  if (fresh->network & ESPNOW_MESH_NET_UDP) {
    if (EspNowMeshNetworkUp()) { if (nullptr == EspNowMeshUdp) { EspNowMeshUdpStart(); } }
  } else {
    EspNowMeshUdpStop();
  }
  EspNowMeshWipe(fresh, sizeof(*fresh));      // it held the key of the network
  delete fresh;
}

// The ticket a frame sent with an answer asked was given, and the entry is free again; 0 for a frame that is not one of these
static uint32_t EspNowMeshTicketOf(uint32_t frame, uint8_t dest) {
  for (uint32_t i = 0; i < ESPNOW_MESH_SENT_DEPTH; i++) {
    EspNowMeshSent_t& sent = EspNowMeshSent[i];
    if (sent.frame && (sent.frame == frame) && (sent.dest == dest)) {
      sent.frame = 0;
      return sent.ticket;
    }
  }
  return 0;
}

static void EspNowMeshTicketKeep(uint32_t frame, uint32_t ticket, uint8_t dest) {
  EspNowMeshSent_t& sent = EspNowMeshSent[EspNowMeshSentNext];       // a ring: what has waited longest goes first, and the core holds 8
  sent.frame = frame;
  sent.ticket = ticket;
  sent.dest = dest;
  EspNowMeshSentNext = (EspNowMeshSentNext + 1) % ESPNOW_MESH_SENT_DEPTH;
}

static bool EspNowMeshPutNote(const EspNowMeshNote_t* note);
static bool EspNowMeshPutNote(const EspNowMeshNote_t* note) {
  if (pdTRUE == xQueueSend(EspNowMeshDriver.note, note, 0)) { return true; }
  EspNowMeshCount.note_lost++;
  return false;
}

// The clock, for the main loop: made again when its version has changed (the time was stepped, a timeline taken, the synced bit moved) and at least every
// ESPNOW_MESH_CLOCK_REFRESH_MS, under the lock. When the lock is not to be had at once it is tried again on the next turn: the main loop is reading, which
// takes a moment. True when the clock the main loop reads is of the version the core has: a timeline the core took is told to the application only then,
// so that no one who knows of it reads the clock of the one it left
static bool EspNowMeshClockPublish(EspNowMesh::Node* node, uint32_t now);
static bool EspNowMeshClockPublish(EspNowMesh::Node* node, uint32_t now) {
  uint32_t version = node->ClockVersion();
  bool current = EspNowMeshDriver.clock_valid && (version == EspNowMeshDriver.clock_version);
  if (current && ((now - EspNowMeshDriver.clock_made_at) < ESPNOW_MESH_CLOCK_REFRESH_MS)) { return true; }
  if (pdTRUE != xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(2))) { return current; }
  node->ClockNow(now, &EspNowMeshDriver.clock_point);
  EspNowMeshDriver.clock_taken = node->stats().timelinesTaken;
  EspNowMeshDriver.clock_valid = true;
  xSemaphoreGive(EspNowMeshDriver.lock);
  EspNowMeshDriver.clock_version = version;
  EspNowMeshDriver.clock_made_at = now;
  return true;
}

// What the core has to tell the main loop: the frames for this device, what became of the ones that asked for an answer, and
// what the supervision found.
//
// Each is taken out of the core only while the queue that carries it has room, and what the queue has no room for stays in the core: a
// frame for this device alone that the inbox has no room for is then not answered, and its sender sends it again, where one taken out
// and dropped here would have been answered and lost. The word that a node is silent, or that a frame was not answered, has a queue
// of its own and is never pushed out by frames
static void EspNowMeshDrain(EspNowMesh::Node* node);
static void EspNowMeshDrain(EspNowMesh::Node* node) {
  EspNowMesh::Outcome o;
  while ((uxQueueSpacesAvailable(EspNowMeshDriver.note) > 0) && node->PopOutcome(&o)) {
    EspNowMeshNote_t note;
    memset(&note, 0, sizeof(note));
    note.kind = ESPNOW_MESH_NOTE_OUTCOME;
    note.counter = EspNowMeshTicketOf(o.counter, o.dest);
    note.frame = o.counter;
    note.dest = o.dest;
    note.ok = o.ok ? 1 : 0;
    note.attempts = o.attempts;
    EspNowMeshPutNote(&note);
  }
  EspNowMesh::Notice n;
  while ((uxQueueSpacesAvailable(EspNowMeshDriver.note) > 0) && node->PopNotice(&n)) {
    EspNowMeshNote_t note;
    memset(&note, 0, sizeof(note));
    note.kind = ESPNOW_MESH_NOTE_NOTICE;
    note.node = n.node;
    note.type = n.kind;
    note.dest = n.by;
    note.counter = n.value;
    EspNowMeshPutNote(&note);
  }
  // what the clock has to tell: a timeline it took, and the synced bit, once the clock the main loop reads is the one the core has
  EspNowMesh::ClockEvent c;
  bool clock_current = EspNowMeshClockPublish(node, millis());
  while (clock_current && (uxQueueSpacesAvailable(EspNowMeshDriver.note) > 0) && node->PopClockEvent(&c)) {
    EspNowMeshNote_t note;
    memset(&note, 0, sizeof(note));
    note.kind = (EspNowMesh::kClockTimeline == c.kind) ? ESPNOW_MESH_NOTE_TIMELINE : ESPNOW_MESH_NOTE_SYNCED;
    note.ok = c.synced;
    memcpy(note.from, c.from, sizeof(note.from));
    memcpy(note.to, c.to, sizeof(note.to));
    note.counter = (uint32_t)c.ticks;
    note.frame = (uint32_t)c.delta;
    note.delta_high = (uint32_t)((uint64_t)c.delta >> 32);
    EspNowMeshPutNote(&note);
  }
  EspNowMesh::Delivery d;
  while ((uxQueueSpacesAvailable(EspNowMeshDriver.event) > 0) && node->PopDelivery(&d)) {
    EspNowMeshEvent_t e;
    memset(&e, 0, sizeof(e));
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
    xQueueSend(EspNowMeshDriver.event, &e, 0);                // there was room: it was looked at
  }
  if (0 == uxQueueSpacesAvailable(EspNowMeshDriver.event)) { EspNowMeshCount.evt_full++; }
}

static void EspNowMeshDoCommand(EspNowMesh::Node* node, const EspNowMeshCmd_t* cmd);
static void EspNowMeshDoCommand(EspNowMesh::Node* node, const EspNowMeshCmd_t* cmd) {
  switch (cmd->op) {
    case ESPNOW_MESH_CMD_SEND: {
      uint32_t frame = node->Send((EspNowMesh::Type)cmd->type, cmd->dest, cmd->data, cmd->len, cmd->flags & 1, millis());
      if (0 == frame) {
        // The core has no room (8 frames waiting for an answer, 16 to send), no key for the destination, or the frame is too long. The
        // caller was given a ticket when the send was queued and is told here that nothing was sent, as it is told of a frame that went
        // and was not answered: an outcome that is not ok, with no attempts
        EspNowMeshCount.refused++;
        AddLog(LOG_LEVEL_INFO, PSTR("EMH: A frame of %u bytes for %u was refused: no room, no key or too long"), cmd->len, cmd->dest);
        EspNowMeshNote_t note;
        memset(&note, 0, sizeof(note));
        note.kind = ESPNOW_MESH_NOTE_OUTCOME;
        note.counter = cmd->ticket;
        note.dest = cmd->dest;
        EspNowMeshPutNote(&note);
      } else if ((cmd->flags & 1) && (EspNowMesh::kToAll != cmd->dest)) {
        EspNowMeshTicketKeep(frame, cmd->ticket, cmd->dest);   // the outcome of this frame is this ticket's
      }
      break;
    }
    case ESPNOW_MESH_CMD_INFO:
      node->SetBeatInfo(cmd->data, cmd->len);
      break;
  }
}

static void EspNowMeshSnapshotMake(EspNowMesh::Node* node);
static void EspNowMeshSnapshotMake(EspNowMesh::Node* node) {
  EspNowMeshSnapshot_t* s = EspNowMeshDriver.snapshot;
  if (nullptr == s) { return; }
  uint32_t now = millis();
  bool net_up = EspNowMeshNetworkUp();
  uint16_t stack_free = uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t);
  // Made in place, under the lock: a copy of it kept on the stack of this task would hold 48 neighbours of 44 bytes
  if (pdTRUE != xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(10))) { return; }
  memset(s, 0, sizeof(*s));
  s->at = now;
  s->stats = node->stats();
  s->queued = node->queued();
  s->waiting = node->waiting();
  s->noisy = node->Noisy();
  s->loss = node->LossPercent();
  s->net_up = net_up;
  for (uint32_t i = 0; i < EspNowMesh::kMaxNeighbors; i++) {
    const EspNowMesh::Neighbor* n = node->NeighborAt(i);
    if (nullptr == n) { continue; }
    EspNowMeshNeighbor_t& out = s->neighbor[s->neighbors++];
    out.id = n->id;
    out.state = n->state;
    out.lists_me = n->listsMe;
    out.no_radio = n->noRadio;
    out.rssi = n->rssi;
    out.their_rssi = n->theirRssi;
    out.age_s = (now - n->lastHeard) / 1000;
    out.beat_s = n->beatAt ? (now - n->beatAt) / 1000 : 0xFFFF;
    out.heard_at = n->lastHeard;
    out.beat_at = n->beatAt;
    out.hears = n->hearsCount;
    out.info_len = n->infoLen;
    memcpy(out.info, n->info, n->infoLen);
    out.clock_skew = n->clockSkew;
    out.clock_seen = n->clockSeen;
  }
  for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
    if (EspNowMeshTable[i].id && node->IsSilent(EspNowMeshTable[i].id) && (s->silent_count < ESPNOW_MESH_NODES)) {
      s->silent[s->silent_count++] = EspNowMeshTable[i].id;
    }
  }
  s->health_links = node->HealthReport(&s->health, s->link, EspNowMesh::kMaxNeighbors, now);
  s->stack_free = stack_free;
  xSemaphoreGive(EspNowMeshDriver.lock);
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
  // The frames for the application are taken only while it says it is ready: one that is answered before the rules that would take it are
  // registered is lost, and its sender is told it arrived
  bool ready = EspNowMeshDriver.app_ready;
  node->SetDeliverEnabled(ready);
  EspNowMeshApplyShared(node, EspNowMeshDriver.shared);

  while (!EspNowMeshDriver.stop) {
    if (EspNowMeshDriver.config_dirty) { EspNowMeshApplyShared(node, EspNowMeshDriver.shared); }
    if (ready != EspNowMeshDriver.app_ready) {
      ready = EspNowMeshDriver.app_ready;
      node->SetDeliverEnabled(ready);
    }

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
  EspNowMeshDriver.clock_valid = false;
  if (EspNowMeshDriver.rx) { vQueueDelete(EspNowMeshDriver.rx); EspNowMeshDriver.rx = nullptr; }
  if (EspNowMeshDriver.cmd) { vQueueDelete(EspNowMeshDriver.cmd); EspNowMeshDriver.cmd = nullptr; }
  if (EspNowMeshDriver.event) { vQueueDelete(EspNowMeshDriver.event); EspNowMeshDriver.event = nullptr; }
  if (EspNowMeshDriver.note) { vQueueDelete(EspNowMeshDriver.note); EspNowMeshDriver.note = nullptr; }
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

// The work of a start. The epoch is what a start has to get right: a node that comes back with the epoch it had, or a lower one, is
// refused by every neighbour as an old one and asks for no sync, so it is silent and thought alive. It is therefore saved, and read
// back, before the task that sends under it starts, and a start whose epoch the flash did not take does not go on: the log says so, and
// it is tried again in ten seconds (EspNowMeshStart).
//
// The write comes before the rest of the start so that a failure of the rest does not leave the flash written and a retry write it
// again: an epoch saved by a start that then failed is kept (epoch_ahead) and is the one the next attempt takes, for no frame was sent under it
static bool EspNowMeshStartAttempt(void) {
  if (!EspNowMeshSettings.id) { return false; }          // a device with no number sends nothing, and starts nothing
  if (!EspNowMeshSettings.has_secret) {
    esp_fill_random(EspNowMeshSettings.secret, sizeof(EspNowMeshSettings.secret));
    EspNowMeshSettings.has_secret = 1;
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: This device has an identity now: EspNowMeshPublic gives its public key"));
  }
  // The epoch of a device that has none is drawn at random, so that a device that was erased does not repeat the numbers of the
  // frames it sent before, with the key of the network it still has; and it rises with every start after that
  uint32_t epoch = EspNowMeshDriver.epoch_ahead;
  if (!epoch) {
    epoch = EspNowMeshSettings.epoch ? (EspNowMeshSettings.epoch + 1) : ((esp_random() >> 2) | 1);
    if (!epoch) { epoch = 1; }
    EspNowMeshLogNvs();
    uint32_t before = EspNowMeshSettings.epoch;
    EspNowMeshSettings.epoch = epoch;
    esp_err_t error = EspNowMeshSave();
    if (ESP_OK != error) {
      EspNowMeshSettings.epoch = before;
      AddLog(LOG_LEVEL_ERROR, PSTR("EMH: The flash did not take the epoch (error 0x%X): the node does not start, and tries again in 10 s"), error);
      return false;
    }
    EspNowMeshDriver.epoch_ahead = epoch;
  }

  EspNowMeshDriver.node = new (std::nothrow) EspNowMesh::Node;
  EspNowMeshDriver.crypto = new (std::nothrow) EspNowMesh::Crypto;
  EspNowMeshDriver.snapshot = new (std::nothrow) EspNowMeshSnapshot_t;
  EspNowMeshDriver.shared = new (std::nothrow) EspNowMeshShared_t;
  EspNowMeshDriver.rx = xQueueCreate(ESPNOW_MESH_RX_DEPTH, sizeof(EspNowMeshRx_t));
  EspNowMeshDriver.cmd = xQueueCreate(ESPNOW_MESH_CMD_DEPTH, sizeof(EspNowMeshCmd_t));
  EspNowMeshDriver.event = xQueueCreate(ESPNOW_MESH_EVENT_DEPTH, sizeof(EspNowMeshEvent_t));
  EspNowMeshDriver.note = xQueueCreate(ESPNOW_MESH_NOTE_DEPTH, sizeof(EspNowMeshNote_t));
  EspNowMeshDriver.send_done = xSemaphoreCreateBinary();
  EspNowMeshDriver.lock = xSemaphoreCreateMutex();
  if (!EspNowMeshDriver.node || !EspNowMeshDriver.crypto || !EspNowMeshDriver.snapshot || !EspNowMeshDriver.shared ||
      !EspNowMeshDriver.rx || !EspNowMeshDriver.cmd || !EspNowMeshDriver.event || !EspNowMeshDriver.note || !EspNowMeshDriver.send_done || !EspNowMeshDriver.lock) {
    AddLog(LOG_LEVEL_ERROR, PSTR("EMH: Not enough memory, %u bytes free"), ESP_getFreeHeap());
    EspNowMeshFree();
    return false;
  }
  memset(EspNowMeshDriver.snapshot, 0, sizeof(EspNowMeshSnapshot_t));
  memset(EspNowMeshDriver.shared, 0, sizeof(EspNowMeshShared_t));
  memset(EspNowMeshTable, 0, sizeof(EspNowMeshTable));
  memset(EspNowMeshSent, 0, sizeof(EspNowMeshSent));
  EspNowMeshSentNext = 0;
  EspNowMeshCount.cmd_busy = 0;                    // the counters of the run, as the core's are
  EspNowMeshCount.evt_full = 0;
  EspNowMeshCount.note_lost = 0;
  EspNowMeshCount.refused = 0;
  EspNowMeshCount.send_failed = 0;
  EspNowMeshCount.bcast_failed = 0;
  EspNowMeshCount.peer_failed = 0;
  EspNowMeshCount.peer_full = 0;
  EspNowMeshCount.peer_evicted = 0;
  EspNowMeshCount.wait_expired = 0;
  EspNowMeshCount.late_word = 0;
  EspNowMeshCount.not_acked = 0;
  EspNowMeshDriver.late_pending = false;
  EspNowMeshDriver.dropped = 0;

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
  config.chooseRelays = (ESPNOW_MESH_CHOOSE_RELAYS != 0);
  config.renewEpoch = EspNowMeshRenewEpoch;
  config.clock = (ESPNOW_MESH_CLOCK != 0);
  EspNowMeshDriver.epoch_renew = false;
  EspNowMeshDriver.clock_valid = false;
  EspNowMeshDriver.clock_taken = 0;
  EspNowMeshDriver.clock_version = 0;
  EspNowMeshDriver.clock_made_at = 0;
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
  EspNowMeshDriver.epoch_ahead = 0;               // the epoch is in use now: the next start takes another
  EspNowMeshDriver.running = true;
  AddLog(LOG_LEVEL_INFO, PSTR("EMH: Started as node %u, epoch %u, %u bytes of heap free"), EspNowMeshSettings.id, epoch, ESP_getFreeHeap());
  if (!EspNowMeshDriver.app_ready) {
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: The frames for the application wait until it says it is ready: espnow_mesh_ready() in a script, or EspNowMeshReady 1"));
  }
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

#ifdef USE_BERRY
static void EspNowMeshBerryCheck(void);
#endif

static void EspNowMeshEverySecond(void) {
#ifdef USE_BERRY
  EspNowMeshBerryCheck();
#endif
  if (EspNowMeshDriver.running && EspNowMeshDriver.exited) { EspNowMeshReap(); }       // a task that was slow to end
  if (EspNowMeshDriver.running && EspNowMeshDriver.epoch_renew) {
    // The number of a frame is the nonce of its cipher and is never used twice: the counter of the core is near the end of its 32 bits, and a start
    // numbers from 1 again under the next epoch, which is saved and read back before the task that sends under it starts
    EspNowMeshDriver.epoch_renew = false;
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: The frame counter is near its end: the mesh stops and starts again under the next epoch"));
    EspNowMeshStop();
  }
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

// A signed number of up to 64 bits as text: the log and the printf of the chip do not take a 64-bit integer
static void EspNowMeshText64(char* out, size_t size, int64_t value);
static void EspNowMeshText64(char* out, size_t size, int64_t value) {
  char digits[24];
  size_t n = 0;
  bool negative = value < 0;
  uint64_t v = negative ? (uint64_t)0 - (uint64_t)value : (uint64_t)value;
  do { digits[n++] = (char)('0' + (uint32_t)(v % 10)); v /= 10; } while ((v != 0) && (n < sizeof(digits)));
  size_t at = 0;
  if (negative && (at + 1 < size)) { out[at++] = '-'; }
  while ((n > 0) && (at + 1 < size)) { out[at++] = digits[--n]; }
  if (size > 0) { out[at] = '\0'; }
}

static void EspNowMeshDrainEvents(void) {
  if ((nullptr == EspNowMeshDriver.event) || (nullptr == EspNowMeshDriver.note)) { return; }
  EspNowMeshNote_t note;
  while (pdTRUE == xQueueReceive(EspNowMeshDriver.note, &note, 0)) {
    if (ESPNOW_MESH_NOTE_OUTCOME == note.kind) {
      AddLog(LOG_LEVEL_INFO, PSTR("EMH: Send %u (frame %u) for %u %s after %u attempts"), note.counter, note.frame, note.dest, note.ok ? PSTR("was answered") : PSTR("was not answered"), note.attempts);
      Response_P(PSTR("{\"EspNowMesh\":{\"Outcome\":{\"Counter\":%u,\"Frame\":%u,\"Dest\":%u,\"Ok\":%u,\"Attempts\":%u}}}"), note.counter, note.frame, note.dest, note.ok, note.attempts);
    } else if (ESPNOW_MESH_NOTE_TIMELINE == note.kind) {
      char from[11];
      char to[11];
      char delta[24];
      ToHex_P(note.from, sizeof(note.from), from, sizeof(from));
      ToHex_P(note.to, sizeof(note.to), to, sizeof(to));
      EspNowMeshText64(delta, sizeof(delta), (int64_t)(((uint64_t)note.delta_high << 32) | note.frame));
      AddLog(LOG_LEVEL_INFO, PSTR("EMH: The clock took the timeline %s from %s: %s ms, %d ticks of 100 ms"), to, from, delta, (int32_t)note.counter);
      Response_P(PSTR("{\"EspNowMesh\":{\"Timeline\":{\"Old\":\"%s\",\"New\":\"%s\",\"Ticks\":%d,\"Delta\":\"%s\",\"Synced\":%u}}}"), from, to, (int32_t)note.counter, delta, note.ok);
    } else if (ESPNOW_MESH_NOTE_SYNCED == note.kind) {
      char to[11];
      ToHex_P(note.to, sizeof(note.to), to, sizeof(to));
      AddLog(LOG_LEVEL_INFO, PSTR("EMH: The clock is %s, in the timeline %s"), note.ok ? PSTR("synced") : PSTR("not synced"), to);
      Response_P(PSTR("{\"EspNowMesh\":{\"Synced\":{\"Value\":%u,\"Timeline\":\"%s\",\"Tag\":%u}}}"), note.ok, to, (uint32_t)EspNowMesh::TimelineTag(note.to));
    } else {
      AddLog(LOG_LEVEL_INFO, PSTR("EMH: %s, node %u, said by %u"), EspNowMeshNoticeName(note.type), note.node, note.dest);
      Response_P(PSTR("{\"EspNowMesh\":{\"Notice\":{\"Kind\":\"%s\",\"Node\":%u,\"By\":%u,\"Value\":%u}}}"), EspNowMeshNoticeName(note.type), note.node, note.dest, note.counter);
    }
    XdrvRulesProcess(0);
  }
  EspNowMeshEvent_t e;
  while (pdTRUE == xQueueReceive(EspNowMeshDriver.event, &e, 0)) {
    char hex[2 * EspNowMesh::kMaxPayload + 1];
    ToHex_P(e.data, e.len, hex, sizeof(hex));
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: From %u type %u dest %u counter %u rssi %d%s: %d bytes"), e.origin, e.type, e.dest, e.counter, e.rssi, (e.flags & 2) ? PSTR(" repeat") : PSTR(""), e.len);
    Response_P(PSTR("{\"EspNowMesh\":{\"From\":%u,\"Type\":%u,\"Dest\":%u,\"Counter\":%u,\"Epoch\":%u,\"Rssi\":%d,\"Flags\":%u,\"Part\":%u,\"Joins\":%u,\"Behind\":%u,\"Data\":\"%s\"}}"),
      e.origin, e.type, e.dest, e.counter, e.epoch, e.rssi, e.flags, e.part, e.joins, e.behind, hex);
    XdrvRulesProcess(0);
  }
}

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

void CmndEspNowMeshEnable(void) {
  if (XdrvMailbox.data_len > 0) {
    EspNowMeshSettings.enabled = (atoi(XdrvMailbox.data) != 0);
    if (!EspNowMeshSettingsCommit()) { ResponseCmndChar_P(PSTR("flash write failed")); return; }
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
    // a device is not one of its own nodes: a row of the list that has the number it now has is not another device's
    for (uint32_t i = 0; i < ESPNOW_MESH_NODES; i++) {
      if (EspNowMeshSettings.node[i].id == id) { memset(&EspNowMeshSettings.node[i], 0, sizeof(EspNowMeshNode_t)); }
    }
    if (!EspNowMeshSettingsCommit()) { ResponseCmndChar_P(PSTR("flash write failed")); return; }
  }
  ResponseCmndNumber(EspNowMeshSettings.id);
}

void CmndEspNowMeshChannel(void) {
  if (XdrvMailbox.data_len > 0) {
    uint32_t channel = atoi(XdrvMailbox.data);
    if (channel > 13) { ResponseCmndError(); return; }
    EspNowMeshSettings.channel = channel;
    if (!EspNowMeshSettingsCommit()) { ResponseCmndChar_P(PSTR("flash write failed")); return; }
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
    if (!EspNowMeshSettingsCommit()) { ResponseCmndChar_P(PSTR("flash write failed")); return; }
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
  if (!EspNowMeshSettingsCommit()) { ResponseCmndChar_P(PSTR("flash write failed")); return; }
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
    if (!EspNowMeshSettingsCommit()) { ResponseCmndChar_P(PSTR("flash write failed")); return; }
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
    if (!EspNowMeshSettingsCommit()) { ResponseCmndChar_P(PSTR("flash write failed")); return; }
    EspNowMeshPushShared();
  }
  ResponseCmndNumber(EspNowMeshSettings.network);
}

// What the main loop gets for handing the task a command: it has it, the task is not running, or its queue is full. A send is given
// its ticket here, one that the call of a script gets back and the outcome of the frame carries, so that a script can tell which of its
// sends an outcome is, and a send the core refuses has an outcome too
#define ESPNOW_MESH_QUEUED             1
#define ESPNOW_MESH_NOT_RUNNING        0
#define ESPNOW_MESH_BUSY               -1
static int32_t EspNowMeshQueueCommand(EspNowMeshCmd_t* cmd);
static int32_t EspNowMeshQueueCommand(EspNowMeshCmd_t* cmd) {
  if (!EspNowMeshDriver.running || (nullptr == EspNowMeshDriver.cmd)) { return ESPNOW_MESH_NOT_RUNNING; }
  uint32_t ticket = EspNowMeshDriver.ticket + 1;
  if (!ticket) { ticket = 1; }
  if (ESPNOW_MESH_CMD_SEND == cmd->op) { cmd->ticket = ticket; }
  if (pdTRUE != xQueueSend(EspNowMeshDriver.cmd, cmd, 0)) {
    EspNowMeshCount.cmd_busy++;
    return ESPNOW_MESH_BUSY;
  }
  if (ESPNOW_MESH_CMD_SEND == cmd->op) { EspNowMeshDriver.ticket = ticket; }
  TaskHandle_t task = EspNowMeshDriver.task;
  if (task) { xTaskNotifyGive(task); }       // the task is woken for it, and does not find it only at the end of its wait of a few ms
  return ESPNOW_MESH_QUEUED;
}

static const char* EspNowMeshQueuedText(int32_t result) {
  return (ESPNOW_MESH_QUEUED == result) ? PSTR("queued") : ((ESPNOW_MESH_BUSY == result) ? PSTR("busy") : PSTR("not running"));
}

// The most a payload to `dest` can be: the core's, which takes the seal of a frame for one node alone off what a frame can hold
static size_t EspNowMeshMaxPayload(uint8_t dest);
static size_t EspNowMeshMaxPayload(uint8_t dest) {
  if (EspNowMeshDriver.node) { return EspNowMeshDriver.node->MaxPayloadFor(dest); }
  return EspNowMesh::kMaxPayload - ((EspNowMesh::kToAll != dest) ? EspNowMesh::kPairTagLen : 0);
}

// The application says it is ready, which is that the rules that take the frames for it are registered; or that it is not. Until it is
// the frames for it are refused by the core, as when the inbox has no room, and the senders send them again
static void EspNowMeshSetReady(bool ready);
static void EspNowMeshSetReady(bool ready) {
  if (ready == EspNowMeshDriver.app_ready) { return; }
  EspNowMeshDriver.app_ready = ready;
  AddLog(LOG_LEVEL_INFO, ready ? PSTR("EMH: The application is ready: the frames for it are taken") : PSTR("EMH: The application is not ready: the frames for it are not taken"));
  TaskHandle_t task = EspNowMeshDriver.task;
  if (task) { xTaskNotifyGive(task); }
}

void CmndEspNowMeshReady(void) {
  if (XdrvMailbox.data_len > 0) { EspNowMeshSetReady(atoi(XdrvMailbox.data) != 0); }
  Response_P(PSTR("{\"%s\":{\"Ready\":%u}}"), XdrvMailbox.command, EspNowMeshDriver.app_ready);
}

void CmndEspNowMeshInfo(void) {
  EspNowMeshCmd_t cmd;
  memset(&cmd, 0, sizeof(cmd));
  cmd.op = ESPNOW_MESH_CMD_INFO;
  int32_t len = XdrvMailbox.data_len ? HexToBytes(XdrvMailbox.data, cmd.data, EspNowMesh::kMaxInfo) : 0;
  if (len < 0) { ResponseCmndError(); return; }
  cmd.len = len;
  ResponseCmndChar_P(EspNowMeshQueuedText(EspNowMeshQueueCommand(&cmd)));
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
    if (len > sizeof(cmd.data)) { Response_P(PSTR("{\"%s\":\"too long\",\"Max\":%u}"), XdrvMailbox.command, (uint32_t)EspNowMeshMaxPayload(cmd.dest)); return; }
    memcpy(cmd.data, fields[3], len);
    cmd.len = len;
  }
  if (cmd.len > EspNowMeshMaxPayload(cmd.dest)) {
    Response_P(PSTR("{\"%s\":\"too long\",\"Max\":%u}"), XdrvMailbox.command, (uint32_t)EspNowMeshMaxPayload(cmd.dest));
    return;
  }
  int32_t queued = EspNowMeshQueueCommand(&cmd);
  if (ESPNOW_MESH_QUEUED == queued) {
    Response_P(PSTR("{\"%s\":{\"Queued\":1,\"Counter\":%u}}"), XdrvMailbox.command, cmd.ticket);
  } else {
    ResponseCmndChar_P(EspNowMeshQueuedText(queued));
  }
}

static const char* EspNowMeshStateName(uint8_t state) {
  return (EspNowMesh::kAlive == state) ? PSTR("alive") : ((EspNowMesh::kSuspect == state) ? PSTR("suspect") : PSTR("silent"));
}

void CmndEspNowMeshStatus(void) {
  char mac[18];
  uint8_t own_mac[6];
  esp_read_mac(own_mac, ESP_MAC_WIFI_STA);
  ToHex_P(own_mac, 6, mac, sizeof(mac), ':');
  // The snapshot is read where it is, under its lock, which is given back after the last of it: a copy would take 2 KB of this stack
  const EspNowMeshSnapshot_t* snap = nullptr;
  if (EspNowMeshDriver.running && EspNowMeshDriver.snapshot && (pdTRUE == xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    snap = EspNowMeshDriver.snapshot;
  }
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&channel, &second);
  esp_now_peer_num_t peers = {0, 0};
  esp_now_get_peer_num(&peers);
  Response_P(PSTR("{\"EspNowMeshStatus\":{\"Running\":%u,\"Id\":%u,\"Epoch\":%u,\"Mac\":\"%s\",\"Channel\":%u,\"Group\":%u,\"GroupVersion\":%u,\"Network\":%u,\"Radio\":%u,\"Ready\":%u,\"Dropped\":%u,\"Peers\":%d,\"Heap\":%u"),
    EspNowMeshDriver.running, EspNowMeshSettings.id, EspNowMeshSettings.epoch, mac, channel, EspNowMeshSettings.has_group, EspNowMeshSettings.group_version,
    EspNowMeshSettings.network, EspNowMeshDriver.radio, EspNowMeshDriver.app_ready, EspNowMeshDriver.dropped, peers.total_num, ESP_getFreeHeap());
  if (!EspNowMeshDriver.running) {
    const char* why = EspNowMeshWhyNot();
    if (why) { ResponseAppend_P(PSTR(",\"Why\":\"%s\""), why); }
  }
  if (snap) {
    const EspNowMesh::Stats& s = snap->stats;
    ResponseAppend_P(PSTR(",\"Neighbors\":%u,\"Queued\":%u,\"Waiting\":%u,\"Noisy\":%u,\"Loss\":%u,\"NetUp\":%u,\"Stack\":%u,\"Silent\":%u,"
                          "\"Heard\":%u,\"Bad\":%u,\"Repeated\":%u,\"Replayed\":%u,\"Stale\":%u,\"Unsynced\":%u,\"Covered\":%u,\"Delivered\":%u,\"InboxFull\":%u,"
                          "\"SentOwn\":%u,\"SentRelay\":%u,\"Suppressed\":%u,\"QueueFull\":%u,\"NoRoute\":%u,\"NoKey\":%u,"
                          "\"AcksSent\":%u,\"AcksHeard\":%u,\"Resent\":%u,\"GaveUp\":%u,\"HopFailed\":%u,\"SyncDone\":%u,\"SyncShed\":%u,\"Beats\":%u,\"Rescued\":%u,\"CipherBad\":%u,\"UdpSent\":%u,\"UdpHeard\":%u"),
      snap->neighbors, snap->queued, snap->waiting, snap->noisy, snap->loss, snap->net_up, snap->stack_free, snap->silent_count,
      s.heard, s.bad, s.repeated, s.replayed, s.stale, s.unsynced, s.covered, s.delivered, s.inboxFull,
      s.sentOwn, s.sentRelay, s.suppressed, s.queueFull, s.noRoute, s.noKey,
      s.acksSent, s.acksHeard, s.resent, s.gaveUp, s.hopFailed, s.syncDone, s.syncShed, s.beatsHeard, s.rescued, s.cipherBad, s.udpSent, s.udpHeard);
    xSemaphoreGive(EspNowMeshDriver.lock);
  }
  ResponseAppend_P(PSTR("}}"));
}

// Every counter, which does not fit a response with the state, in two pages: the frames and the driver's own (page 0), and the supervision,
// the sync, the lists in pieces and the network (page 1). The core's counters are those of the snapshot, up to half a second old, and
// count from the start of the node, as the driver's do
void CmndEspNowMeshStats(void) {
  uint32_t page = XdrvMailbox.data_len ? atoi(XdrvMailbox.data) : 0;
  if (page > 1) { ResponseCmndChar_P(PSTR("page 0 or 1")); return; }
  const EspNowMeshSnapshot_t* snap = nullptr;
  if (EspNowMeshDriver.running && EspNowMeshDriver.snapshot && (pdTRUE == xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    snap = EspNowMeshDriver.snapshot;
  }
  Response_P(PSTR("{\"%s\":{\"Page\":%u,\"Running\":%u"), XdrvMailbox.command, page, EspNowMeshDriver.running);
  if (snap) {
    const EspNowMesh::Stats& s = snap->stats;
    if (0 == page) {
      ResponseAppend_P(PSTR(",\"Heard\":%u,\"Bad\":%u,\"Repeated\":%u,\"Replayed\":%u,\"Stale\":%u,\"Unsynced\":%u,\"Covered\":%u,\"Delivered\":%u,\"InboxFull\":%u,"
                            "\"SentOwn\":%u,\"SentRelay\":%u,\"Suppressed\":%u,\"QueueFull\":%u,\"NoRoute\":%u,\"NoKey\":%u,\"CipherBad\":%u,"
                            "\"AcksSent\":%u,\"AcksHeard\":%u,\"Resent\":%u,\"GaveUp\":%u,\"HopFailed\":%u"),
        s.heard, s.bad, s.repeated, s.replayed, s.stale, s.unsynced, s.covered, s.delivered, s.inboxFull,
        s.sentOwn, s.sentRelay, s.suppressed, s.queueFull, s.noRoute, s.noKey, s.cipherBad,
        s.acksSent, s.acksHeard, s.resent, s.gaveUp, s.hopFailed);
    } else {
      ResponseAppend_P(PSTR(",\"SyncAsked\":%u,\"SyncDone\":%u,\"SyncBad\":%u,\"SyncShed\":%u,\"StartAsks\":%u,"
                            "\"BeatsSent\":%u,\"BeatsHeard\":%u,\"Pings\":%u,\"Probes\":%u,\"Rescued\":%u,\"VerdictsSent\":%u,\"VerdictsHeard\":%u,\"NoiseSent\":%u,\"KeptAsOnlyWay\":%u,\"RelayHeld\":%u,\"CounterOut\":%u,"
                            "\"PartsSent\":%u,\"PiecesSent\":%u,\"PiecesNew\":%u,\"PiecesRepeated\":%u,\"NaksSent\":%u,\"BulkDone\":%u,\"BulkLost\":%u,"
                            "\"UdpSent\":%u,\"UdpHeard\":%u"),
        s.syncAsked, s.syncDone, s.syncBad, s.syncShed, s.startAsks,
        s.beatsSent, s.beatsHeard, s.pings, s.probes, s.rescued, s.verdictsSent, s.verdictsHeard, s.noiseSent, s.keptAsOnlyWay, s.relayHeld, s.counterOut,
        s.partsSent, s.piecesSent, s.piecesNew, s.piecesRepeated, s.naksSent, s.bulkDone, s.bulkLost,
        s.udpSent, s.udpHeard);
    }
    xSemaphoreGive(EspNowMeshDriver.lock);
  }
  if (0 == page) {
    // What happens around the core, that the core cannot count: the queues of the driver, the radio's refusals, the late word, the peers
    ResponseAppend_P(PSTR(",\"Dropped\":%u,\"CmdBusy\":%u,\"EvtFull\":%u,\"NoteLost\":%u,\"Refused\":%u,"
                          "\"SendFailed\":%u,\"BcastFailed\":%u,\"NotAcked\":%u,\"WaitExpired\":%u,\"LateWord\":%u,"
                          "\"PeerFailed\":%u,\"PeerFull\":%u,\"PeerEvicted\":%u"),
      EspNowMeshDriver.dropped, EspNowMeshCount.cmd_busy, EspNowMeshCount.evt_full, EspNowMeshCount.note_lost, EspNowMeshCount.refused,
      EspNowMeshCount.send_failed, EspNowMeshCount.bcast_failed, EspNowMeshCount.not_acked, EspNowMeshCount.wait_expired, EspNowMeshCount.late_word,
      EspNowMeshCount.peer_failed, EspNowMeshCount.peer_full, EspNowMeshCount.peer_evicted);
    nvs_stats_t nvs;
    if (ESP_OK == nvs_get_stats(nullptr, &nvs)) {
      ResponseAppend_P(PSTR(",\"NvsUsed\":%u,\"NvsTotal\":%u"), (uint32_t)nvs.used_entries, (uint32_t)nvs.total_entries);
    }
  }
  ResponseAppend_P(PSTR("}}"));
}

// The lists the commands answer in pages are held to what a message takes: it is MESSZ characters, and an answer that goes over is lost or arrives
// cut in the middle of an entry, which is not JSON. An entry is added while it, and the end of the answer, still fit under a margin of 40, at least
// one is always added, and when some remain the answer says where the next page starts: "Next", the index to ask for, and nothing when the list ended
#define ESPNOW_MESH_PAGE_MAX           (MESSZ - 40)
#define ESPNOW_MESH_PAGE_END           16          // the end of a page that stops early: ],"Next":255}}
#define ESPNOW_MESH_ENTRY_MAX          256         // the largest entry of any of the lists, formatted before it is known to fit

static bool EspNowMeshPageRoom(size_t entry);
static bool EspNowMeshPageRoom(size_t entry) {
  return (ResponseLength() + entry + ESPNOW_MESH_PAGE_END) <= ESPNOW_MESH_PAGE_MAX;
}

// The end of a list: the entries are closed, and, when some remain, the index the next page starts at
static void EspNowMeshPageClose(uint32_t next, uint32_t count);
static void EspNowMeshPageClose(uint32_t next, uint32_t count) {
  ResponseAppend_P(PSTR("]"));
  if (next < count) { ResponseAppend_P(PSTR(",\"Next\":%u"), next); }
}

void CmndEspNowMeshNeighbors(void) {
  if (!EspNowMeshDriver.running || (nullptr == EspNowMeshDriver.snapshot) || (pdTRUE != xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    ResponseCmndChar_P(PSTR("not running"));
    return;
  }
  // Read where it is, under the lock, and not copied: the whole of it is 2 KB of this stack
  const EspNowMeshSnapshot_t& snap = *EspNowMeshDriver.snapshot;
  uint32_t first = XdrvMailbox.data_len ? atoi(XdrvMailbox.data) : 0;
  Response_P(PSTR("{\"%s\":{\"Count\":%u,\"From\":%u,\"List\":["), XdrvMailbox.command, snap.neighbors, first);
  uint32_t i = first;
  for (; i < snap.neighbors; i++) {
    const EspNowMeshNeighbor_t& n = snap.neighbor[i];
    char info[2 * EspNowMesh::kMaxInfo + 1];
    ToHex_P(n.info, n.info_len, info, sizeof(info));
    char entry[ESPNOW_MESH_ENTRY_MAX];
    int len = snprintf_P(entry, sizeof(entry), PSTR("%s{\"Id\":%u,\"State\":\"%s\",\"Rssi\":%d,\"TheirRssi\":%d,\"Lists\":%u,\"NoRadio\":%u,\"Age\":%u,\"Beat\":%d,\"Hears\":%u,\"Info\":\"%s\"}"),
      (i == first) ? PSTR("") : PSTR(","), n.id, EspNowMeshStateName(n.state), n.rssi, n.their_rssi, n.lists_me, n.no_radio, n.age_s,
      (0xFFFF == n.beat_s) ? -1 : (int)n.beat_s, n.hears, info);
    if ((i > first) && !EspNowMeshPageRoom((len > 0) ? (size_t)len : sizeof(entry))) { break; }
    ResponseAppend_P(PSTR("%s"), entry);
  }
  uint32_t count = snap.neighbors;
  xSemaphoreGive(EspNowMeshDriver.lock);
  EspNowMeshPageClose(i, count);
  ResponseAppend_P(PSTR("}}"));
}

// What the heartbeats of the neighbours say of the surroundings, two hops deep, and of each neighbour heard on the radio: how many of its
// heartbeats come, how many nodes at two hops it lists and how many of those only it does, and the group it falls in (the neighbours that
// list each other, or the same node, are one group). More than one group (Cut) says that if this device went away those neighbours would lose
// each other unless by a way longer than two hops, which this device cannot see: a device that is a point of failure for the network always shows
// it, and one that shows it is not always one (a ring of five or more devices shows it at each). SoleWays counts the neighbours that are the only
// way this device has to some node, and Alone says it has one neighbour, which is then its point of failure. The neighbours as many as a message takes,
// from the one asked for (Next says where the following page starts, when there is one)
void CmndEspNowMeshHealth(void) {
  if (!EspNowMeshDriver.running || (nullptr == EspNowMeshDriver.snapshot) || (pdTRUE != xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    ResponseCmndChar_P(PSTR("not running"));
    return;
  }
  const EspNowMeshSnapshot_t& snap = *EspNowMeshDriver.snapshot;
  const EspNowMesh::Health& h = snap.health;
  uint32_t first = XdrvMailbox.data_len ? atoi(XdrvMailbox.data) : 0;
  Response_P(PSTR("{\"%s\":{\"Neighbors\":%u,\"Weak\":%u,\"TwoHop\":%u,\"Branches\":%u,\"Cut\":%u,\"SoleWays\":%u,\"Alone\":%u,\"Relays\":%u,\"Count\":%u,\"From\":%u,\"List\":["),
    XdrvMailbox.command, h.neighbors, h.weak, h.twoHop, h.branches, (h.branches > 1) ? 1 : 0, h.soleWays, (1 == h.neighbors) ? 1 : 0, h.relays, snap.health_links, first);
  uint32_t i = first;
  for (; i < snap.health_links; i++) {
    const EspNowMesh::HealthLink& l = snap.link[i];
    char entry[ESPNOW_MESH_ENTRY_MAX];
    int len = snprintf_P(entry, sizeof(entry), PSTR("%s{\"Id\":%u,\"Quality\":%d,\"Usable\":%u,\"Reach\":%u,\"Only\":%u,\"Branch\":%u,\"Chosen\":%u}"),
      (i == first) ? PSTR("") : PSTR(","), l.id, (EspNowMesh::kQualityUnknown == l.quality) ? -1 : (int)l.quality, l.usable, l.reach, l.only, l.branch, l.chosen);
    if ((i > first) && !EspNowMeshPageRoom((len > 0) ? (size_t)len : sizeof(entry))) { break; }
    ResponseAppend_P(PSTR("%s"), entry);
  }
  uint32_t count = snap.health_links;
  xSemaphoreGive(EspNowMeshDriver.lock);
  EspNowMeshPageClose(i, count);
  ResponseAppend_P(PSTR("}}"));
}

// The clock the task made last, for the main loop: the point it described and the timelines taken. False when the task is not running or has not made one.
// Whoever reads it finds the mesh time now with EspNowMesh::ClockAt, from the same counter the task's is
static bool EspNowMeshClockRead(EspNowMesh::ClockPoint* point, uint32_t* taken);
static bool EspNowMeshClockRead(EspNowMesh::ClockPoint* point, uint32_t* taken) {
  if (!EspNowMeshDriver.running || (nullptr == EspNowMeshDriver.lock) || (pdTRUE != xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) { return false; }
  bool valid = EspNowMeshDriver.clock_valid;
  if (valid) {
    *point = EspNowMeshDriver.clock_point;
    *taken = EspNowMeshDriver.clock_taken;
  }
  xSemaphoreGive(EspNowMeshDriver.lock);
  return valid;
}

// The mesh clock: what this device counts since it started and the timeline it counts on, whether it is synced, and the clocks of the neighbours its
// heartbeats have shown, as many as a message takes from the one asked for (Next says where the following page starts, when there is one): the timeline of the last one (Seen 0 if it carried none, 1 another than this device's, 2 the same), its synced
// bit, and how far its time was from this device's when it came, ms: negative by the wait of the frame in the queue, on the air and in the task that read it
// when the two clocks agree, positive when the neighbour's was ahead and this device followed it. Mesh is the time in ms
void CmndEspNowMeshClock(void) {
  EspNowMesh::ClockPoint point;
  uint32_t taken = 0;
  if (!EspNowMeshClockRead(&point, &taken)) {
    ResponseCmndChar_P(PSTR("not running"));
    return;
  }
  uint64_t mesh = EspNowMesh::ClockAt(point, millis());
  char timeline[11];
  char text[24];
  ToHex_P(point.timeline, sizeof(point.timeline), timeline, sizeof(timeline));
  EspNowMeshText64(text, sizeof(text), (int64_t)mesh);
  Response_P(PSTR("{\"%s\":{\"Clock\":%u,\"Synced\":%u,\"Adopted\":%u,\"Timeline\":\"%s\",\"Tag\":%u,\"Mesh\":%s,\"Ticks10\":%u,\"Taken\":%u"),
    XdrvMailbox.command, (ESPNOW_MESH_CLOCK != 0) ? 1 : 0, point.synced, point.adopted, timeline, (uint32_t)EspNowMesh::TimelineTag(point.timeline), text,
    (uint32_t)(mesh / EspNowMesh::kStampTickMs), taken);
  if (EspNowMeshDriver.snapshot && (pdTRUE == xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    const EspNowMeshSnapshot_t& snap = *EspNowMeshDriver.snapshot;
    uint32_t first = XdrvMailbox.data_len ? atoi(XdrvMailbox.data) : 0;
    ResponseAppend_P(PSTR(",\"Steps\":%u,\"EventsLost\":%u,\"Count\":%u,\"From\":%u,\"List\":["), snap.stats.clockSteps, snap.stats.clockEventsLost, snap.neighbors, first);
    uint32_t i = first;
    for (; i < snap.neighbors; i++) {
      const EspNowMeshNeighbor_t& n = snap.neighbor[i];
      bool carries = (n.info_len >= EspNowMesh::kInfoClockLen) && (EspNowMesh::kInfoLayout == n.info[0]);
      char theirs[11] = "";
      if (carries) { ToHex_P(n.info + EspNowMesh::kInfoTimelineAt, 5, theirs, sizeof(theirs)); }
      char entry[ESPNOW_MESH_ENTRY_MAX];
      int len = snprintf_P(entry, sizeof(entry), PSTR("%s{\"Id\":%u,\"Seen\":%u,\"Sync\":%u,\"Skew\":%d,\"Timeline\":\"%s\"}"),
        (i == first) ? PSTR("") : PSTR(","), n.id, n.clock_seen, carries ? (n.info[EspNowMesh::kInfoFlagsAt] & EspNowMesh::kInfoSynced) : 0, n.clock_skew, theirs);
      if ((i > first) && !EspNowMeshPageRoom((len > 0) ? (size_t)len : sizeof(entry))) { break; }
      ResponseAppend_P(PSTR("%s"), entry);
    }
    uint32_t count = snap.neighbors;
    xSemaphoreGive(EspNowMeshDriver.lock);
    EspNowMeshPageClose(i, count);
  }
  ResponseAppend_P(PSTR("}}"));
}

#ifdef USE_BERRY
// Going through the command handler costs a full dispatch on the main loop, about 8 ms even for a command that does nothing
// (xdrv_98), and a script that sends often should not pay it. So Berry gets entry points of its own:
//
//   espnow_mesh_send(dest, type, ack, data)  -> the ticket of the send, an integer above 0, or false when it was not taken (the task is not
//                                               running, its queue is full, the destination or the type is out of range, or the data is more
//                                               than espnow_mesh_max_payload(dest)); data is bytes or a string. The outcome of a frame sent
//                                               with an answer asked carries the ticket as its Counter, and so does one the core refused, with
//                                               Ok 0 and no attempts
//   espnow_mesh_max_payload(dest)            -> the most bytes a payload to dest can be
//   espnow_mesh_info(data)                   -> true when the task took it; the bytes (up to 32) every heartbeat carries. Also says the
//                                               application is ready
//   espnow_mesh_ready([ready])               -> true; says the application is ready (the default) or, with false, that it is not
//   espnow_mesh_health()                     -> a map of what EspNowMeshHealth says of the surroundings (neighbors, weak, twohop, branches, cut,
//                                               soleways, alone, relays), or false when the task is not running
//   espnow_mesh_clock()                      -> a map of the mesh clock (synced, adopted, ticks10, ticks100, tag, timeline, taken, lo, hi), or false
//   espnow_mesh_stamp()                      -> the 6 bytes that stamp a message with the mesh time and the tag of the timeline, or false when not synced
//   espnow_mesh_age(stamp)                   -> a map (age in ms, tag, synced) of how old a stamp is, or false
//   espnow_mesh_neighbors()                  -> a list of maps, one for each neighbour (id, state, rssi, age, beat, info, seen, skew), or false
//
// The frames for the application are not taken, and not answered, until it says it is ready: a script registers its rules and then
// says so. What arrives, and what became of what was sent, comes to the rules, as the log and the header say.
int EspNowMeshBerrySend(struct bvm *vm);
int EspNowMeshBerrySend(struct bvm *vm) {
  int32_t argc = be_top(vm);
  if ((argc >= 4) && be_isint(vm, 1) && be_isint(vm, 2)) {
    int dest = be_toint(vm, 1);
    int type = be_toint(vm, 2);
    bool ack = be_tobool(vm, 3);
    const void* data = nullptr;
    size_t len = 0;
    if (be_isbytes(vm, 4)) {
      data = be_tobytes(vm, 4, &len);
    } else if (be_isstring(vm, 4)) {
      data = be_tostring(vm, 4);
      len = strlen((const char*)data);
    }
    uint32_t ticket = 0;
    if (data && (dest >= 0) && (dest <= 255) && (type >= 0) && (type <= 7) && (EspNowMesh::kBeat != type) && (len <= EspNowMeshMaxPayload(dest))) {
      EspNowMeshCmd_t cmd;
      memset(&cmd, 0, sizeof(cmd));
      cmd.op = ESPNOW_MESH_CMD_SEND;
      cmd.dest = dest;
      cmd.type = type;
      cmd.flags = ack ? 1 : 0;
      cmd.len = len;
      if (len) { memcpy(cmd.data, data, len); }
      if (ESPNOW_MESH_QUEUED == EspNowMeshQueueCommand(&cmd)) { ticket = cmd.ticket; }
    }
    if (ticket) { be_pushint(vm, (bint)ticket); } else { be_pushbool(vm, false); }
    be_return(vm);
  }
  be_raise(vm, kTypeError, nullptr);
}

int EspNowMeshBerryMaxPayload(struct bvm *vm);
int EspNowMeshBerryMaxPayload(struct bvm *vm) {
  if ((be_top(vm) >= 1) && be_isint(vm, 1) && (be_toint(vm, 1) >= 0) && (be_toint(vm, 1) <= 255)) {
    be_pushint(vm, (bint)EspNowMeshMaxPayload(be_toint(vm, 1)));
    be_return(vm);
  }
  be_raise(vm, kTypeError, nullptr);
}

int EspNowMeshBerryReady(struct bvm *vm);
int EspNowMeshBerryReady(struct bvm *vm) {
  EspNowMeshSetReady((be_top(vm) < 1) || be_tobool(vm, 1));
  be_pushbool(vm, true);
  be_return(vm);
}

int EspNowMeshBerryInfo(struct bvm *vm);
int EspNowMeshBerryInfo(struct bvm *vm) {
  int32_t argc = be_top(vm);
  if (argc >= 1) {
    const void* data = nullptr;
    size_t len = 0;
    if (be_isbytes(vm, 1)) {
      data = be_tobytes(vm, 1, &len);
    } else if (be_isstring(vm, 1)) {
      data = be_tostring(vm, 1);
      len = strlen((const char*)data);
    }
    bool queued = false;
    if (data && (len <= EspNowMesh::kMaxInfo)) {
      EspNowMeshCmd_t cmd;
      memset(&cmd, 0, sizeof(cmd));
      cmd.op = ESPNOW_MESH_CMD_INFO;
      cmd.len = len;
      if (len) { memcpy(cmd.data, data, len); }
      queued = (ESPNOW_MESH_QUEUED == EspNowMeshQueueCommand(&cmd));
      EspNowMeshSetReady(true);                // a script that tells the heartbeat what it carries has the rest of its rules in place
    }
    be_pushbool(vm, queued);
    be_return(vm);
  }
  be_raise(vm, kTypeError, nullptr);
}

int EspNowMeshBerryHealth(struct bvm *vm);
int EspNowMeshBerryHealth(struct bvm *vm) {
  EspNowMesh::Health h;
  bool have = false;
  // Copied under the lock and the map made after it: Berry can raise an error, which must not leave the lock taken
  if (EspNowMeshDriver.running && EspNowMeshDriver.snapshot && (pdTRUE == xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    h = EspNowMeshDriver.snapshot->health;
    have = true;
    xSemaphoreGive(EspNowMeshDriver.lock);
  }
  if (!have) {
    be_pushbool(vm, false);
    be_return(vm);
  }
  be_newobject(vm, "map");
  be_map_insert_int(vm, "neighbors", h.neighbors);
  be_map_insert_int(vm, "weak", h.weak);
  be_map_insert_int(vm, "twohop", h.twoHop);
  be_map_insert_int(vm, "branches", h.branches);
  be_map_insert_int(vm, "cut", (h.branches > 1) ? 1 : 0);
  be_map_insert_int(vm, "soleways", h.soleWays);
  be_map_insert_int(vm, "alone", (1 == h.neighbors) ? 1 : 0);
  be_map_insert_int(vm, "relays", h.relays);
  be_pop(vm, 1);
  be_return(vm);
}

// The clock as a map: the mesh time as the task's clock has it, plus what the counter has gone on by since it was made. The numbers are integers of the
// machine, 32 bits with their sign: a time in ticks wraps in 497 days (of 10 ms) or 13.6 years (of 100 ms), and two of them are compared by their difference
// The neighbours the task has, as a list of maps, from the snapshot the task made last (up to half a second old, the commands' own): what each one's last heartbeat
// carried, which is what the application of the mesh says of itself, and how long ago it, and the neighbour itself, were heard. The times are read from the counter
// now, so that an age is exact when the snapshot is not. Copied under the lock and the list made after it, as Berry can raise an error
int EspNowMeshBerryNeighbors(struct bvm *vm);
int EspNowMeshBerryNeighbors(struct bvm *vm) {
  EspNowMeshNeighbor_t* copy = nullptr;
  uint32_t count = 0;
  if (EspNowMeshDriver.running && EspNowMeshDriver.snapshot && (pdTRUE == xSemaphoreTake(EspNowMeshDriver.lock, pdMS_TO_TICKS(50)))) {
    copy = new (std::nothrow) EspNowMeshNeighbor_t[EspNowMesh::kMaxNeighbors];
    if (copy) {
      count = EspNowMeshDriver.snapshot->neighbors;
      memcpy(copy, EspNowMeshDriver.snapshot->neighbor, count * sizeof(EspNowMeshNeighbor_t));
    }
    xSemaphoreGive(EspNowMeshDriver.lock);
  }
  if (!copy) {
    be_pushbool(vm, false);
    be_return(vm);
  }
  uint32_t now = millis();
  be_newobject(vm, "list");
  for (uint32_t i = 0; i < count; i++) {
    const EspNowMeshNeighbor_t& n = copy[i];
    char info[2 * EspNowMesh::kMaxInfo + 1];
    ToHex_P(n.info, n.info_len, info, sizeof(info));
    be_newobject(vm, "map");
    be_map_insert_int(vm, "id", n.id);
    be_map_insert_int(vm, "state", n.state);
    be_map_insert_int(vm, "rssi", n.rssi);
    be_map_insert_int(vm, "age", (bint)(int32_t)(now - n.heard_at));
    be_map_insert_int(vm, "beat", n.beat_at ? (bint)(int32_t)(now - n.beat_at) : -1);
    be_map_insert_str(vm, "info", info);
    be_map_insert_int(vm, "seen", n.clock_seen);
    be_map_insert_int(vm, "skew", n.clock_skew);
    be_pop(vm, 1);
    be_data_push(vm, -2);
    be_pop(vm, 1);
  }
  be_pop(vm, 1);
  delete[] copy;
  be_return(vm);
}

int EspNowMeshBerryClock(struct bvm *vm);
int EspNowMeshBerryClock(struct bvm *vm) {
  EspNowMesh::ClockPoint point;
  uint32_t taken = 0;
  if (!EspNowMeshClockRead(&point, &taken)) {
    be_pushbool(vm, false);
    be_return(vm);
  }
  uint64_t mesh = EspNowMesh::ClockAt(point, millis());
  char timeline[11];
  ToHex_P(point.timeline, sizeof(point.timeline), timeline, sizeof(timeline));
  be_newobject(vm, "map");
  be_map_insert_bool(vm, "synced", point.synced);
  be_map_insert_bool(vm, "adopted", point.adopted);
  be_map_insert_int(vm, "ticks10", (bint)(int32_t)(uint32_t)(mesh / EspNowMesh::kStampTickMs));
  be_map_insert_int(vm, "ticks100", (bint)(int32_t)(uint32_t)(mesh / 100));
  be_map_insert_int(vm, "tag", (bint)EspNowMesh::TimelineTag(point.timeline));
  be_map_insert_str(vm, "timeline", timeline);
  be_map_insert_int(vm, "taken", (bint)taken);
  be_map_insert_int(vm, "lo", (bint)(int32_t)(uint32_t)mesh);
  be_map_insert_int(vm, "hi", (bint)(int32_t)(uint32_t)(mesh >> 32));
  be_pop(vm, 1);
  be_return(vm);
}

int EspNowMeshBerryStamp(struct bvm *vm);
int EspNowMeshBerryStamp(struct bvm *vm) {
  EspNowMesh::ClockPoint point;
  uint32_t taken = 0;
  uint8_t stamp[EspNowMesh::kStampLen];
  if (EspNowMeshClockRead(&point, &taken) && EspNowMesh::ClockStamp(point, millis(), stamp)) {
    be_pushbytes(vm, stamp, sizeof(stamp));
  } else {
    be_pushbool(vm, false);
  }
  be_return(vm);
}

int EspNowMeshBerryAge(struct bvm *vm);
int EspNowMeshBerryAge(struct bvm *vm) {
  if ((be_top(vm) >= 1) && be_isbytes(vm, 1)) {
    size_t len = 0;
    const uint8_t* stamp = (const uint8_t*)be_tobytes(vm, 1, &len);
    EspNowMesh::ClockPoint point;
    uint32_t taken = 0;
    int32_t age = 0;
    bool same = false;
    if (EspNowMeshClockRead(&point, &taken) && EspNowMesh::ClockAge(point, millis(), stamp, len, &age, &same)) {
      be_newobject(vm, "map");
      be_map_insert_int(vm, "age", (bint)age);
      be_map_insert_bool(vm, "tag", same);
      be_map_insert_bool(vm, "synced", point.synced);
      be_pop(vm, 1);
    } else {
      be_pushbool(vm, false);
    }
    be_return(vm);
  }
  be_raise(vm, kTypeError, nullptr);
}

static void EspNowMeshBerryRegister(void) {
  if (nullptr == berry.vm) { return; }
  be_pushntvfunction(berry.vm, EspNowMeshBerrySend);
  be_setglobal(berry.vm, "espnow_mesh_send");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryMaxPayload);
  be_setglobal(berry.vm, "espnow_mesh_max_payload");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryInfo);
  be_setglobal(berry.vm, "espnow_mesh_info");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryReady);
  be_setglobal(berry.vm, "espnow_mesh_ready");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryHealth);
  be_setglobal(berry.vm, "espnow_mesh_health");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryClock);
  be_setglobal(berry.vm, "espnow_mesh_clock");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryStamp);
  be_setglobal(berry.vm, "espnow_mesh_stamp");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryAge);
  be_setglobal(berry.vm, "espnow_mesh_age");
  be_pop(berry.vm, 1);
  be_pushntvfunction(berry.vm, EspNowMeshBerryNeighbors);
  be_setglobal(berry.vm, "espnow_mesh_neighbors");
  be_pop(berry.vm, 1);
}

// The Berry machine is a new one after BrRestart, with none of what was registered in the old one: the entry points are put in it again,
// and the application is not ready, for the rules it had are gone with the machine
static void EspNowMeshBerryCheck(void) {
  if (nullptr == berry.vm) { return; }
  bool there = be_getglobal(berry.vm, "espnow_mesh_info");
  be_pop(berry.vm, 1);
  if (there) { return; }
  EspNowMeshBerryRegister();
  EspNowMeshSetReady(false);
}
#endif  // USE_BERRY

const char kEspNowMeshCommands[] PROGMEM = "|"
  "EspNowMeshEnable|EspNowMeshId|EspNowMeshChannel|EspNowMeshGroupKey|EspNowMeshNode|EspNowMeshPublic|EspNowMeshNetwork|"
  "EspNowMeshInfo|EspNowMeshSend|EspNowMeshStatus|EspNowMeshNeighbors|EspNowMeshReady|EspNowMeshStats|EspNowMeshHealth|EspNowMeshClock";
void (* const kEspNowMeshCommand[])(void) PROGMEM = {
  &CmndEspNowMeshEnable, &CmndEspNowMeshId, &CmndEspNowMeshChannel, &CmndEspNowMeshGroupKey, &CmndEspNowMeshNode, &CmndEspNowMeshPublic,
  &CmndEspNowMeshNetwork, &CmndEspNowMeshInfo, &CmndEspNowMeshSend, &CmndEspNowMeshStatus, &CmndEspNowMeshNeighbors, &CmndEspNowMeshReady, &CmndEspNowMeshStats, &CmndEspNowMeshHealth,
  &CmndEspNowMeshClock };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv100(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_PRE_INIT:
      EspNowMeshSettingsLoad();
      EspNowMeshDriver.radio_lock = xSemaphoreCreateMutex();
      break;
    case FUNC_INIT:
      WiFi.onEvent(EspNowMeshWifiEvent);
#ifdef USE_BERRY
      EspNowMeshBerryRegister();
      // With Berry running, the frames for the application wait until a script says it is ready. Without it, the rules of the device are
      // all there is to take them, and are there
      EspNowMeshDriver.app_ready = (nullptr == berry.vm);
#endif
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
