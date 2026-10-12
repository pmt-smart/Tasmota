/*
  espnow_mesh_core.h - ESP-NOW mesh: frame format, duplicate suppression, replay window, flooding,
                       routing back along the way a frame came, acknowledgement with resend, the sync exchange,
                       and the supervision of the neighbourhood

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

#ifndef _ESPNOW_MESH_CORE_H_
#define _ESPNOW_MESH_CORE_H_

/*********************************************************************************************\
 * The part of an ESP-NOW mesh that does not touch the radio: what a frame looks like, which
 * frames a node has already seen or must refuse, which of the ones it hears it repeats and when,
 * how an answer finds its way back, and what a sender does when no answer comes. It needs no
 * operating system and no radio library, and keeps all its state in fixed arrays, so the same
 * code runs in the firmware's radio task and in a host test with many nodes over a simulated air.
 *
 * A frame, 14 bytes of header, the payload, and a tag of 8 (ESP-NOW allows 250):
 *
 *   version(1) kind(1) origin(1) dest(1) next(1) hops(1) epoch(4) counter(4) payload tag(8)
 *
 *   kind     type(3 bits) | ack requested(1) | part(2: whole, first, second) | attempt(2)
 *   origin   the number of the node that created the frame
 *   dest     the number of the node it is for, or 255 for all of them
 *   next     the number of the next hop of a routed frame; 0 in a flooded one
 *   hops     how many times the frame may still be repeated: it leaves the origin with 3,
 *            and a node that repeats it sends it on with one less; at 0 it is not repeated
 *   epoch    rises at every start of the origin
 *   counter  numbers the frames of an epoch, one origin one writer
 *
 * `origin`, `epoch` and `counter` are the number of the message. The tag is computed over
 * the header, with `next` and `hops` taken as 0 because they change at every hop, and the
 * payload, so that it holds from the origin to the destination and whoever repeats a frame
 * does not recompute it. The function that computes it belongs to the user of this file.
 *
 * Flooding: a frame that is not for this node alone, with hops left and a number not yet
 * heard, is repeated once. It waits first, a random time that depends on how strongly it was
 * heard (a weak one comes from far away, so this node covers more than the senders do, and
 * waits 0 to 3 ms; a strong one waits 3 to 8 ms), and if it hears the same frame again while
 * it waits, it drops its own copy, the neighbours having covered what it would.
 *
 * Routing back: of every number it hears for the first time, a node keeps who it heard it from,
 * which is the way back to the origin. A frame with a `next` goes that way, one neighbour at a
 * time, to a unicast address: each node that is not the destination sends it on to the neighbour
 * it keeps for the destination. A hop the radio could not deliver is sent again, up to three
 * times, and then dropped. An answer to something that was flooded travels this way, so the
 * answer never floods.
 *
 * Acknowledgement: a frame that asks for one, and that is for a single node, is kept by the
 * sender, which sends it again with the attempt one higher if no answer comes in 100 ms, and
 * once more after 100 ms more; without an answer 100 ms after that, it reports the failure. The
 * destination answers every attempt it hears, as soon as it hears it, and delivers the frame to
 * its application with a flag when the number was delivered before, so that the application
 * executes a number once. Nothing is sent that is not either confirmed or reported.
 *
 * Replay: a node keeps, for each origin, the highest epoch and counter accepted and a window
 * of 32 counters behind it, one bit each. A counter already seen, one behind the window and
 * an epoch below the kept one are refused. An origin starts unsynchronised: nothing it sends
 * is accepted until this node has asked it, with a nonce of its own, and had the answer, which
 * carries the origin's epoch and counter and a proof of the nonce. An epoch above the kept
 * one makes the origin unsynchronised again, because a start of the origin is the moment a
 * recorded frame of one of its earlier epochs could be played back. A frame that repeats a
 * number with a higher attempt is a retransmission: it is repeated, and delivered as one.
 *
 * Supervision: every few seconds a node sends a heartbeat, in broadcast and never repeated, which
 * carries a few bytes of the application's own and the neighbours this node has heard lately with
 * the signal of each. From the heartbeats a node knows who its neighbours are, which of them hear
 * it back, and, from their lists, who they hear: the neighbourhood two hops deep. A neighbour not
 * heard for a while is suspected, and the node sends it a unicast, which the radio acknowledges
 * without the neighbour's software; failing that it asks two other neighbours that hear it to do
 * the same, and only when none of them has an answer within a longer wait is the neighbour
 * declared silent, to everyone, in a frame that is flooded. A silent node heard again is back.
 * A node that has heard two copies of a frame it was waiting to repeat still repeats it when it
 * is the only way to one of its neighbours, which the neighbours' lists tell. A neighbour that
 * does not list this node among the ones it hears is not a way to anywhere. The heartbeats that
 * fail to arrive from strong neighbours, the unicasts the radio does not get acknowledged and the
 * frames nobody answers are counted, and a minute of too many of them, twice running, is a noisy
 * channel, said to everyone.
 *
 * Messages longer than a frame: one that does not fit goes in two, each with a number of its own, the
 * second carrying the number of the first ahead of the rest, and the destination's application gets
 * the two, the second marked with the first's number, to join. A list that is longer still goes as a
 * bulk transfer, in pieces of 200 bytes along the way back to the node that asked for it, each piece
 * naming the transfer, its own place and the count; the destination keeps what it has had, asks
 * after 300 ms for what is missing, up to three times, and says when it has all. The sender, which
 * holds the data, sends again the pieces asked for.
 *
 * Secrecy: when the user of this file gives it a cipher, the payload of a frame is enciphered before the
 * frame's tag is computed. A frame for one node alone is sealed with the key this node shares with that
 * node, and carries 8 bytes more, a tag that only that node can check; one for everyone is enciphered
 * with the key of the network and the tag of the frame is what authenticates it. The header, with the
 * hop count, the next hop and the attempt left out because they change on the way and on a retransmission,
 * is the data the seal authenticates, and the number of the message the nonce: so a node that repeats a
 * frame reads nothing of it, and a retransmission is the very same bytes as the attempt before. A frame
 * for this node that does not open is refused before it counts for anything.
\*********************************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace EspNowMesh {

constexpr uint8_t kVersion = 0x41;           // above the types of any other ESP-NOW protocol in use on the same radio
constexpr size_t kMaxFrame = 250;
constexpr size_t kHeaderLen = 14;
constexpr size_t kTagLen = 8;
constexpr size_t kMaxPayload = kMaxFrame - kHeaderLen - kTagLen;
constexpr size_t kPairTagLen = 8;            // what the seal of a frame for one node adds to its payload
constexpr uint8_t kToAll = 255;
constexpr uint8_t kMaxHops = 3;
constexpr unsigned kReplayWindow = 32;

constexpr unsigned kMaxOrigins = 16;         // the origins a node keeps a window and a way back for
constexpr unsigned kSeenSize = 64;           // the numbers a node remembers hearing
constexpr unsigned kTxQueue = 16;            // the frames waiting to be sent
constexpr unsigned kInboxSize = 8;           // the frames waiting for the application
constexpr unsigned kPendingSize = 8;         // the frames waiting for an answer
constexpr unsigned kOutcomeSize = 8;         // the answers, or the lack of them, waiting for the application
constexpr unsigned kSyncSize = 4;            // the sync exchanges in progress
constexpr unsigned kMaxNeighbors = 16;       // the nodes heard directly that a node keeps
constexpr unsigned kMaxInfo = 32;            // the bytes of the application's own in a heartbeat
constexpr unsigned kNoticeSize = 8;          // the things the supervision tells the application, waiting to be read

constexpr uint32_t kAnswerWaitMs = 100;      // between an attempt and the next, and after the last
constexpr uint8_t kMaxAttempt = 2;           // the attempt that is the last: 0, 1 and 2
constexpr unsigned kHopTries = 3;            // times a routed hop is handed to the radio
constexpr uint32_t kSyncWaitMs = 2000;       // an exchange that has had no answer by then is given up
constexpr uint32_t kSyncAskEveryMs = 1000;   // the least between two asks to the same origin
constexpr uint32_t kBeatJitterMs = 500;      // added to the time between two heartbeats, so that nodes that started together part
constexpr uint32_t kSuspectAfterMs = 15000;  // a neighbour not heard for this long is suspected
constexpr uint32_t kSuspectJitterMs = 2000;  // added to it, a different time for each neighbour of each node
constexpr uint32_t kSilentAfterMs = 10000;   // and declared silent this long after, if nobody has an answer from it
constexpr uint32_t kHeardWindowMs = 15000;   // the neighbours a heartbeat lists are the ones heard within this
constexpr unsigned kProbeHelpers = 2;        // the neighbours asked to try a suspect
constexpr uint32_t kNoiseWindowMs = 60000;   // the span the noise is counted over
constexpr uint8_t kNoiseLimit = 35;          // the percent of what should have got through, in a window, that makes it a noisy one, when the configuration gives none

enum Type : uint8_t { kCommand = 0, kAck = 1, kState = 2, kEvent = 3, kBeat = 4, kBulk = 5, kMembership = 6, kSync = 7 };

// The sync exchange's two frames, the first byte of their payload
constexpr uint8_t kSyncAsk = 1;              // nonce(4)
constexpr uint8_t kSyncAnswer = 2;           // nonce(4) epoch(4) counter(4) proof(8)

// The supervision's frames are all of the heartbeat type, and the first byte of the payload says which
constexpr uint8_t kSubBeat = 0;              // infoLen(1) info n(1) then n of: node(1) signal(1); to all, not repeated
constexpr uint8_t kSubProbe = 1;             // node(1); to a neighbour: try this node for me
constexpr uint8_t kSubPing = 2;              // nothing; to a neighbour, for the radio's acknowledgement
constexpr uint8_t kSubAlive = 3;             // node(1); to the neighbour that asked: that node answered
constexpr uint8_t kSubVerdict = 4;           // node(1) silent(1); to all, repeated: a node is silent, or is back
constexpr uint8_t kSubNoise = 5;             // noisy(1); to all, repeated: the channel at the sender is noisy, or calm again

// The bulk transfer's frames, the first byte of their payload
constexpr uint8_t kBulkSubPiece = 0;         // id(2) index(1) total(1) data
constexpr uint8_t kBulkSubNak = 1;           // id(2) missing(4): a bit for each piece not had; to the sender
constexpr uint8_t kBulkSubDone = 2;          // id(2); to the sender: all the pieces have come
constexpr size_t kBulkPieceMax = 200;        // the data in a piece
constexpr unsigned kBulkMaxPieces = 32;      // the pieces in a transfer
constexpr unsigned kBulkInSize = 4;          // the transfers a node receives at a time
constexpr uint32_t kBulkNakAfterMs = 300;    // without a piece for this long, the missing ones are asked for
constexpr uint8_t kBulkMaxNaks = 3;          // and given up after as many asks

// What the user of this file computes: the tag of `len` bytes, with the key it holds
typedef void (*TagFunction)(const uint8_t *data, size_t len, uint8_t tag[kTagLen], void *context);
// The proof that `peer`'s answer to a nonce is its own: from the key this node shares with `peer`
typedef void (*ProofFunction)(void *context, uint8_t peer, uint32_t nonce, uint32_t epoch, uint32_t counter, uint8_t proof[8]);
// The number of the node with this address, or 0 when it is not known
typedef uint8_t (*NodeOfFunction)(void *context, const uint8_t mac[6]);
// Seals `len` bytes of a payload: for `peer`'s eyes alone, with the key this node shares with it, and a tag of kPairTagLen
// bytes at the end, or, when `peer` is 0, for the whole network, enciphered with the network's key and no tag. `header` is the
// frame's, with the hops, the next hop and the attempt left out: its associated data and the source of the nonce. Returns the
// length written to `out`, or 0 when there is no key
typedef size_t (*SealFunction)(void *context, uint8_t peer, const uint8_t header[kHeaderLen], const uint8_t *in, size_t len, uint8_t *out);
// The opposite: the length of the payload written to `out`, or -1 when the tag does not match or there is no key
typedef int (*OpenFunction)(void *context, uint8_t peer, const uint8_t header[kHeaderLen], const uint8_t *in, size_t len, uint8_t *out);

inline uint8_t PackKind(Type type, bool ack, uint8_t part, uint8_t attempt) {
  return (uint8_t)(((uint8_t)type & 7) << 5 | (ack ? 0x10 : 0) | (part & 3) << 2 | (attempt & 3));
}

struct Frame {
  uint8_t kind;
  uint8_t origin;
  uint8_t dest;
  uint8_t next;
  uint8_t hops;
  uint32_t epoch;
  uint32_t counter;
  const uint8_t *payload;
  size_t len;

  Type type() const { return (Type)(kind >> 5); }
  bool ackRequested() const { return (kind & 0x10) != 0; }
  uint8_t part() const { return (kind >> 2) & 3; }
  uint8_t attempt() const { return kind & 3; }
  bool routed() const { return next != 0; }
};

inline void Put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
inline uint32_t Get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

// The frame as bytes, with its tag zeroed; 0 when the payload does not fit
inline size_t Encode(const Frame &f, uint8_t *out) {
  if (f.len > kMaxPayload) return 0;
  out[0] = kVersion;
  out[1] = f.kind;
  out[2] = f.origin;
  out[3] = f.dest;
  out[4] = f.next;
  out[5] = f.hops;
  Put32(out + 6, f.epoch);
  Put32(out + 10, f.counter);
  if (f.len > 0) memcpy(out + kHeaderLen, f.payload, f.len);
  memset(out + kHeaderLen + f.len, 0, kTagLen);
  return kHeaderLen + f.len + kTagLen;
}

// The bytes as a frame, whose payload points into them; false for what is not one of ours
inline bool Decode(const uint8_t *in, size_t n, Frame *f) {
  if (n < kHeaderLen + kTagLen || n > kMaxFrame || in[0] != kVersion) return false;
  f->kind = in[1];
  f->origin = in[2];
  f->dest = in[3];
  f->next = in[4];
  f->hops = in[5];
  f->epoch = Get32(in + 6);
  f->counter = Get32(in + 10);
  f->payload = in + kHeaderLen;
  f->len = n - kHeaderLen - kTagLen;
  return true;
}

// The tag a frame of `n` bytes should carry, with `next` and `hops` as 0
inline void TagOf(TagFunction fn, void *context, const uint8_t *frame, size_t n, uint8_t tag[kTagLen]) {
  uint8_t scratch[kMaxFrame];
  size_t covered = n - kTagLen;
  memcpy(scratch, frame, covered);
  scratch[4] = 0;
  scratch[5] = 0;
  fn(scratch, covered, tag, context);
}

// Stamps the tag of a frame in place
inline void Seal(TagFunction fn, void *context, uint8_t *frame, size_t n) {
  TagOf(fn, context, frame, n, frame + n - kTagLen);
}

inline bool TagMatches(TagFunction fn, void *context, const uint8_t *frame, size_t n) {
  uint8_t tag[kTagLen];
  TagOf(fn, context, frame, n, tag);
  uint8_t diff = 0;
  for (size_t i = 0; i < kTagLen; i++) diff |= tag[i] ^ frame[n - kTagLen + i];
  return diff == 0;
}

// How the queue orders what waits to be sent: the lower goes first
inline uint8_t PriorityOf(Type type) {
  switch (type) {
    case kEvent: return 1;
    case kCommand: case kAck: case kMembership: case kSync: return 2;
    default: return 3;                         // state, bulk, heartbeats
  }
}

// The same for a frame as bytes: of the supervision's, only the heartbeat is the lowest; a probe or a verdict is as urgent as a command
inline uint8_t FramePriority(const uint8_t *frame) {
  Type type = (Type)(frame[1] >> 5);
  if (type == kBeat && frame[kHeaderLen] != kSubBeat) return 2;
  return PriorityOf(type);
}

// What a node does with a frame it hears
enum Verdict : uint8_t { kAccepted, kRetry, kRepeated, kReplayed, kStale, kNeedsSync, kIgnored, kBad };

struct Delivery {
  uint8_t origin;
  Type type;
  bool ackRequested;
  bool retry;                                  // a number already delivered, heard again with a higher attempt
  uint8_t part;                                // 0 a whole message, 1 the first part of two, 2 the second
  uint8_t attempt;
  uint8_t dest;
  uint32_t joins;                              // of a second part, the number of the first, which is not in the payload
  uint32_t epoch;
  uint32_t counter;
  int8_t rssi;
  uint8_t from[6];                             // the neighbour the frame was heard from
  uint8_t len;
  uint8_t payload[kMaxPayload];
};

// What became of a frame that asked for an answer: it came, or it did not after the last attempt
struct Outcome {
  uint32_t counter;
  uint8_t dest;
  bool ok;
  uint8_t attempts;
};

struct Stats {
  uint32_t heard, bad, repeated, replayed, stale, unsynced, delivered, inboxFull;
  uint32_t sentOwn, sentRelay, suppressed, queueFull;
  uint32_t acksSent, acksHeard, resent, gaveUp, noRoute, hopFailed, syncAsked, syncDone, syncBad;
  uint32_t beatsSent, beatsHeard, pings, probes, rescued, verdictsSent, verdictsHeard, noiseSent, keptAsOnlyWay;
  uint32_t partsSent, piecesSent, piecesNew, piecesRepeated, naksSent, bulkDone, bulkLost;
  uint32_t noKey, cipherBad;
};

// How a neighbour stands: heard lately, not heard and being tried, or declared silent by this node
enum Liveness : uint8_t { kAlive = 0, kSuspect = 1, kMute = 2 };

// A node heard directly, and what its last heartbeat said
struct Neighbor {
  bool used;
  uint8_t id;
  uint8_t state;                               // a Liveness
  uint8_t listsMe;                             // 0 not known, 1 its heartbeat lists this node among the ones it hears, 2 it does not
  uint8_t mac[6];
  int8_t rssi;                                 // the signal it is heard at, smoothed; 0 before the first
  int8_t theirRssi;                            // the signal it says it hears this node at
  uint8_t hearsCount;
  uint8_t hears[kMaxNeighbors];                // the nodes it listed, the ones it hears
  uint8_t infoLen;
  uint8_t info[kMaxInfo];                      // the application's bytes of its last heartbeat
  uint16_t jitter;                             // how much longer than the others this node waits before it suspects this neighbour, ms
  uint32_t lastHeard;                          // the last time something of it got through, or an unicast of ours was acknowledged by it
  uint32_t beatAt;                             // the last heartbeat; 0 before the first
  uint32_t suspectAt;
};

// What the supervision has to tell the application
enum NoticeKind : uint8_t { kNoticeSilent = 1, kNoticeBack = 2, kNoticeNoisy = 3, kNoticeCalm = 4, kNoticeBulkDone = 5, kNoticeBulkLost = 6 };
struct Notice {
  uint8_t node;                                // the node it is about; for the noise, the node whose channel it is
  uint8_t kind;                                // a NoticeKind
  uint8_t by;                                  // the node that said so, this node's own number when it found out itself
  uint32_t value;                              // of a bulk transfer, its id; the node it is about is the one that sent it
};

struct Config {
  uint8_t id;                                  // this node's number
  uint32_t epoch;                              // this node's epoch, already raised for this start
  uint32_t (*random)(void *);                  // a random number
  void *context;
  TagFunction tag;                             // nullptr: tags are not computed and not checked
  void *tagContext;
  ProofFunction proof;                         // nullptr: the sync answers carry no proof and none is checked
  void *proofContext;
  NodeOfFunction nodeOf;                       // needed to route: the number of a neighbour, from its address
  void *nodeContext;
  int8_t weakDbm;                              // a frame heard below this was heard from far away
  uint8_t suppressAt;                          // copies heard, the first included, that make this node drop its own
  SealFunction seal;                           // nullptr: payloads are not enciphered and not opened
  OpenFunction open;
  void *cipherContext;
  uint32_t beatEveryMs;                        // the time between heartbeats; 0: no heartbeats, and no supervision
  uint8_t noiseLimit;                          // the percent lost that makes a minute a noisy one; 0 for the default
};

class Node {
 public:
  void Begin(const Config &config) {
    memset(this, 0, sizeof(*this));
    cfg_ = config;
    if (cfg_.weakDbm == 0) cfg_.weakDbm = -70;
    if (cfg_.suppressAt == 0) cfg_.suppressAt = 2;
    if (cfg_.noiseLimit == 0) cfg_.noiseLimit = kNoiseLimit;
  }

  // The application hands over a frame for `dest` (kToAll for everyone), to be flooded. Returns its counter, or 0.
  // A frame that asks for an answer and is for one node is kept, sent again if none comes, and reported either way.
  // The heartbeat type is the supervision's own, and is not the application's to send
  uint32_t Send(Type type, uint8_t dest, const uint8_t *payload, size_t len, bool ackRequested, uint32_t now) {
    if (type == kBeat) return 0;
    return Queue(type, dest, payload, len, ackRequested, kMaxHops, now);
  }

  // The same, along the way back to `dest` instead of by flooding: for an answer to a frame that was flooded. Returns the
  // counter, or 0 when this node has no way to `dest`
  uint32_t SendRouted(Type type, uint8_t dest, const uint8_t *payload, size_t len, uint32_t now, uint32_t delayMs = 0) {
    if (len > PayloadCap(dest)) return 0;
    Origin *d = FindOrigin(dest, false);
    uint8_t next = d != nullptr && d->routed ? NodeOf(d->via) : 0;
    if (next == 0) { stats_.noRoute++; return 0; }
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return 0; }
    Frame f = Header(type, dest, next, kMaxHops, false);
    f.payload = payload;
    f.len = len;
    if (!BuildOwn(slot, f, now)) return 0;
    memcpy(slot->to, d->via, 6);
    slot->unicast = true;
    slot->due = now + delayMs;
    return f.counter;
  }

  // A message longer than a frame, in two: the first part full, the second with the number of the first ahead of the rest,
  // each part its own frame with its own number, and each confirmed on its own when an answer is asked for. Nothing is sent
  // and false comes back when the message does not fit in two, or the queue has no room for both. `counters` get the numbers
  bool SendParts(Type type, uint8_t dest, const uint8_t *payload, size_t len, bool ackRequested, uint32_t now, uint32_t counters[2]) {
    size_t cap = PayloadCap(dest);
    if (type == kBeat || len <= cap || len > 2 * cap - 4) return false;
    unsigned room = 0, waiting = 0;
    for (unsigned i = 0; i < kTxQueue; i++) room += !txq_[i].used;
    for (unsigned i = 0; i < kPendingSize; i++) waiting += !pending_[i].used;
    if (room < 2 || (ackRequested && dest != kToAll && waiting < 2)) { stats_.queueFull++; return false; }
    uint8_t second[kMaxPayload];
    size_t rest = len - cap;
    counters[0] = Queue(type, dest, payload, cap, ackRequested, kMaxHops, now, 1);
    Put32(second, counters[0]);
    memcpy(second + 4, payload + cap, rest);
    counters[1] = Queue(type, dest, second, rest + 4, ackRequested, kMaxHops, now, 2);
    stats_.partsSent += 2;
    return counters[0] != 0 && counters[1] != 0;
  }

  // The most a payload can be in a frame for `dest`
  size_t MaxPayloadFor(uint8_t dest) const { return PayloadCap(dest); }

  // The pieces a transfer of `len` bytes comes to
  static unsigned BulkPieces(size_t len) { return (unsigned)((len + kBulkPieceMax - 1) / kBulkPieceMax); }

  // One piece of a bulk transfer, `index` of `total`, of the transfer `id`, along the way back to `dest` when this node has
  // one and flooded when it has not. Returns the counter, or 0 when there was no room or the piece does not fit
  uint32_t SendBulkPiece(uint8_t dest, uint16_t id, uint8_t index, uint8_t total, const uint8_t *data, size_t len, uint32_t now) {
    if (total == 0 || total > kBulkMaxPieces || index >= total || len > kBulkPieceMax) return 0;
    uint8_t p[kBulkPieceMax + 5];
    p[0] = kBulkSubPiece;
    p[1] = (uint8_t)id;
    p[2] = (uint8_t)(id >> 8);
    p[3] = index;
    p[4] = total;
    if (len > 0) memcpy(p + 5, data, len);
    uint32_t counter = SendAlong(kBulk, dest, p, len + 5, now);
    if (counter != 0) stats_.piecesSent++;
    return counter;
  }

  // The radio heard `n` bytes from the neighbour `src`, with the signal `rssi`
  Verdict OnReceive(const uint8_t *data, size_t n, const uint8_t src[6], int8_t rssi, uint32_t now) {
    Frame f;
    if (!Decode(data, n, &f)) { stats_.bad++; return kBad; }
    if (cfg_.tag != nullptr && !TagMatches(cfg_.tag, cfg_.tagContext, data, n)) { stats_.bad++; return kBad; }
    if (f.origin == cfg_.id || f.origin == 0 || f.origin == kToAll) return kIgnored;
    // how near its origin a frame was heard: the hops it has left, which a heartbeat, sent with none, does not say, being heard from the origin itself
    uint8_t reach = f.type() == kBeat ? kMaxHops : f.hops;
    // a routed frame is for the neighbour it names, and the others, if they heard it, leave it alone
    if (f.routed() && f.next != cfg_.id) return kIgnored;
    stats_.heard++;
    // a copy of what is in hand, or of what was handled: counted for the suppression and no more
    if (SeenBefore(f.origin, f.epoch, f.counter, f.attempt())) {
      stats_.repeated++;
      CountCopy(f.origin, f.epoch, f.counter, f.attempt(), NodeOf(src), now);
      // a copy from a neighbour that hears this node is a way back to the origin when the one kept is none
      Origin *known_origin = FindOrigin(f.origin, false);
      if (known_origin != nullptr && known_origin->synced && (!known_origin->routed || OneWay(known_origin->via))) Learn(known_origin, src, reach);
      return kRepeated;
    }
    Origin *o = FindOrigin(f.origin, true);
    if (o == nullptr) { stats_.unsynced++; return kNeedsSync; }
    bool forMe = f.dest == cfg_.id || f.dest == kToAll;
    // what the frame carries, as this node reads it: a frame for this node alone is opened with the key it shares with the origin, one
    // for everyone with the network's. A frame that does not open is refused before it counts for anything: a window, a way back, a copy
    Frame g = f;
    uint8_t plain[kMaxPayload];
    if (forMe && cfg_.open != nullptr && f.len > 0) {
      uint8_t aad[kHeaderLen];
      CipherHeader(f, aad);
      int pn = cfg_.open(cfg_.cipherContext, f.dest == kToAll ? 0 : f.origin, aad, f.payload, f.len, plain);
      if (pn < 0) { stats_.cipherBad++; return kBad; }
      g.payload = plain;
      g.len = (size_t)pn;
    }
    if (f.type() == kSync) {
      Learn(o, src, reach);
      Remember(f.origin, f.epoch, f.counter, f.attempt(), src);
      // an origin that asks from an epoch above the one kept has started again: it is asked in its turn, before its first data frame
      if (f.epoch > o->epoch && o->synced) o->synced = false;
      return OnSync(g, data, n, rssi, now, forMe, NodeOf(src));
    }
    bool known = false;                        // this number has been delivered before
    // a frame refused for want of a sync, or for its epoch, is not remembered: it is not one this node has handled, and the
    // sender's next attempt, or this very frame heard again, is taken once the origin is known. The way back is learned
    // from it when this node has none, because the sync exchange goes that way
    if (!o->synced) { if (!o->routed) Learn(o, src, reach); stats_.unsynced++; return kNeedsSync; }
    if (f.epoch < o->epoch) { stats_.stale++; return kStale; }
    if (f.epoch > o->epoch) { o->synced = false; if (!o->routed) Learn(o, src, reach); stats_.unsynced++; return kNeedsSync; }
    if (f.counter > o->highest) {
      uint32_t shift = f.counter - o->highest;
      o->seen = shift >= kReplayWindow ? 0 : o->seen << shift;
      o->seen |= 1;
      o->highest = f.counter;
    } else {
      uint32_t back = o->highest - f.counter;
      if (back >= kReplayWindow) { stats_.stale++; return kStale; }
      if ((o->seen >> back) & 1) known = true; else o->seen |= (uint32_t)1 << back;
    }
    if (known && !(f.attempt() > 0)) { stats_.replayed++; return kReplayed; }
    // the first copy of a number came by the best way: it is the way back to its origin
    Learn(o, src, reach);
    Remember(f.origin, f.epoch, f.counter, f.attempt(), src);
    // a frame that got through the gate is proof of its origin, and of the neighbour that sent it, just now
    uint8_t sender = NodeOf(src);
    if (sender == 0 && f.type() == kBeat) sender = f.origin;
    Touch(sender, src, rssi, now);
    if (f.origin != sender) NodeIsAlive(f.origin, now);
    if (f.type() == kBeat) {
      OnSupervision(g, sender, now);
    } else if (forMe && f.type() == kAck) {
      HandleAck(g);
    } else if (forMe) {
      // a piece of a bulk transfer is the application's once, whatever the number of times it comes
      if (f.type() != kBulk || TrackPiece(g, now)) Deliver(g, src, rssi, known);
      // answered at once, before the application has done anything with it, and every attempt
      if (f.ackRequested() && f.dest == cfg_.id) SendAck(f, now);
    }
    Pass(f, data, n, rssi, now, sender);
    return known ? kRetry : kAccepted;
  }

  // The origin is known to be at this epoch and counter: its frames are accepted from the next one on
  void SetSynced(uint8_t origin, uint32_t epoch, uint32_t counter) {
    Origin *o = FindOrigin(origin, true);
    if (o == nullptr) return;
    o->synced = true;
    o->epoch = epoch;
    o->highest = counter;
    o->seen = 1;
  }

  // Asks `target` (or everyone, kToAll) where it is: its epoch and counter, with a proof, which is the
  // way an origin becomes known. Returns false if there was no room for another exchange
  bool RequestSync(uint8_t target, uint32_t now) {
    SyncAsk *a = nullptr;
    for (unsigned i = 0; i < kSyncSize; i++) if (asks_[i].used && asks_[i].target == target) a = &asks_[i];
    for (unsigned i = 0; a == nullptr && i < kSyncSize; i++) if (!asks_[i].used) a = &asks_[i];
    if (a == nullptr) return false;
    a->used = true;
    a->target = target;
    a->nonce = cfg_.random != nullptr ? cfg_.random(cfg_.context) : 1;
    a->until = now + kSyncWaitMs;
    uint8_t p[5];
    p[0] = kSyncAsk;
    Put32(p + 1, a->nonce);
    Origin *t = target != kToAll ? FindOrigin(target, false) : nullptr;
    uint32_t sent = t != nullptr && t->routed ? SendRouted(kSync, target, p, sizeof(p), now) : Send(kSync, target, p, sizeof(p), false, now);
    if (sent == 0) { a->used = false; return false; }
    stats_.syncAsked++;
    return true;
  }

  // Whether this node accepts the frames of `origin`: it has been through the sync exchange with it
  bool Knows(uint8_t origin) const {
    for (unsigned i = 0; i < kMaxOrigins; i++) if (origins_[i].used && origins_[i].id == origin) return origins_[i].synced;
    return false;
  }

  // An origin whose frames this node had to refuse for want of a sync, or 0
  uint8_t WantsSync() const {
    for (unsigned i = 0; i < kMaxOrigins; i++) if (origins_[i].used && !origins_[i].synced) return origins_[i].id;
    return 0;
  }

  // The timers: the frames that have waited for an answer long enough, the exchanges that have waited too long,
  // and the origins that need a sync. Called often, at least every few milliseconds
  void Tick(uint32_t now) {
    for (unsigned i = 0; i < kPendingSize; i++) {
      Pending &p = pending_[i];
      if (!p.used || (int32_t)(now - p.due) < 0) continue;
      if (p.attempt >= kMaxAttempt) {
        Report(p.counter, p.dest, false, p.attempt + 1);
        stats_.gaveUp++;
        noiseTried_++;
        noiseFailed_++;
        p.used = false;
        continue;
      }
      TxItem *slot = FreeSlot();
      if (slot == nullptr) { p.due = now + 1; continue; }
      p.attempt++;
      memset(slot, 0, sizeof(*slot));
      memcpy(slot->data, p.frame, p.len);
      slot->len = p.len;
      slot->data[1] = (uint8_t)((slot->data[1] & ~3) | p.attempt);
      if (cfg_.tag != nullptr) Seal(cfg_.tag, cfg_.tagContext, slot->data, slot->len);
      slot->used = true;
      slot->own = true;
      memset(slot->to, 0xff, 6);
      slot->prio = FramePriority(slot->data);
      slot->heard = 1;
      slot->due = now;
      Remember(cfg_.id, cfg_.epoch, p.counter, p.attempt, nullptr);
      p.due = now + kAnswerWaitMs;
      stats_.resent++;
    }
    for (unsigned i = 0; i < kSyncSize; i++) if (asks_[i].used && (int32_t)(now - asks_[i].until) >= 0) asks_[i].used = false;
    bool everyone = false;
    for (unsigned i = 0; i < kSyncSize; i++) if (asks_[i].used && asks_[i].target == kToAll) everyone = true;
    for (unsigned i = 0; i < kMaxOrigins && !everyone; i++) {
      Origin &o = origins_[i];
      if (!o.used || o.synced || !o.routed) continue;
      if (o.asked && (int32_t)(now - o.askedAt) < (int32_t)kSyncAskEveryMs) continue;
      if (RequestSync(o.id, now)) { o.asked = true; o.askedAt = now; }
    }
    if (cfg_.beatEveryMs != 0) Supervise(now);
    for (unsigned i = 0; i < kBulkInSize; i++) {
      BulkIn &b = bulkIn_[i];
      if (!b.used || b.done || (int32_t)(now - b.lastAt) < (int32_t)kBulkNakAfterMs) continue;
      if (b.naks >= kBulkMaxNaks) {
        Post(kNoticeBulkLost, b.origin, cfg_.id, b.id);
        stats_.bulkLost++;
        b.used = false;
        continue;
      }
      uint8_t p[7];
      p[0] = kBulkSubNak;
      p[1] = (uint8_t)b.id;
      p[2] = (uint8_t)(b.id >> 8);
      Put32(p + 3, Missing(b));
      if (SendAlong(kBulk, b.origin, p, sizeof(p), now) != 0) stats_.naksSent++;
      b.naks++;
      b.lastAt = now;
    }
  }

  // The radio is free: the frame to send next, to whom (broadcast, all ones, for a flooded frame), and whether there
  // is one. Serialised: nothing more comes until the radio says what became of the last
  bool NextTx(uint32_t now, uint8_t *out, size_t *len, uint8_t to[6]) {
    if (busy_) return false;
    TxItem *best = nullptr;
    for (unsigned i = 0; i < kTxQueue; i++) {
      TxItem &t = txq_[i];
      if (!t.used || (int32_t)(now - t.due) < 0) continue;
      if (best == nullptr || t.prio < best->prio || (t.prio == best->prio && (int32_t)(t.due - best->due) < 0)) best = &t;
    }
    if (best == nullptr) return false;
    memcpy(out, best->data, best->len);
    memcpy(to, best->to, 6);
    *len = best->len;
    if (best->own) stats_.sentOwn++; else stats_.sentRelay++;
    inflight_ = *best;
    inflightValid_ = true;
    best->used = false;
    busy_ = true;
    return true;
  }

  // When something will be ready to send, in the clock of `now`; false if nothing waits
  bool NextDue(uint32_t *due) const {
    bool any = false;
    for (unsigned i = 0; i < kTxQueue; i++) {
      if (!txq_[i].used) continue;
      if (!any || (int32_t)(txq_[i].due - *due) < 0) *due = txq_[i].due;
      any = true;
    }
    return any;
  }

  // The radio is sending the frame NextTx gave, and has not said what became of it
  bool Busy() const { return busy_; }

  // The radio says what became of the last frame: a unicast that the neighbour did not acknowledge is handed over again.
  // A unicast that was a ping tells, by the neighbour's acknowledgement of it, whether the neighbour is there
  void TxDone(bool ok, uint32_t now) {
    bool unicast = inflightValid_ && inflight_.unicast;
    uint8_t pingTarget = inflight_.pingTarget, pingAsker = inflight_.pingAsker;
    bool again = false;
    // a ping to a node that is gone fails for want of the node, and says nothing of the channel
    if (unicast && pingTarget == 0) { noiseTried_++; if (!ok) noiseFailed_++; }
    if (unicast && !ok) {
      if (++inflight_.tries < kHopTries) {
        TxItem *slot = FreeSlot();
        if (slot != nullptr) { *slot = inflight_; slot->due = now + 1; again = true; }
      }
      if (!again) {
        stats_.hopFailed++;
        if (pingTarget == 0) DemoteRoute(inflight_.data[3], inflight_.to);
      }
    }
    inflightValid_ = false;
    busy_ = false;
    if (unicast && pingTarget != 0 && (ok || !again)) OnPingResult(pingTarget, pingAsker, ok, now);
  }

  bool PopDelivery(Delivery *d) {
    if (inboxCount_ == 0) return false;
    *d = inbox_[inboxHead_];
    inboxHead_ = (inboxHead_ + 1) % kInboxSize;
    inboxCount_--;
    return true;
  }

  bool PopOutcome(Outcome *o) {
    if (outcomeCount_ == 0) return false;
    *o = outcomes_[outcomeHead_];
    outcomeHead_ = (outcomeHead_ + 1) % kOutcomeSize;
    outcomeCount_--;
    return true;
  }

  // The neighbour a frame for `origin` would be sent to, and whether this node knows one
  bool RouteTo(uint8_t origin, uint8_t via[6]) const {
    for (unsigned i = 0; i < kMaxOrigins; i++) {
      if (origins_[i].used && origins_[i].id == origin && origins_[i].routed) {
        memcpy(via, origins_[i].via, 6);
        return true;
      }
    }
    return false;
  }

  // The bytes of the application's own that every heartbeat of this node carries, up to kMaxInfo
  void SetBeatInfo(const uint8_t *info, size_t len) {
    infoLen_ = (uint8_t)(len > kMaxInfo ? kMaxInfo : len);
    if (infoLen_ > 0) memcpy(info_, info, infoLen_);
  }

  // The neighbours, by slot: a slot that is not in use is null
  const Neighbor *NeighborAt(unsigned i) const { return i < kMaxNeighbors && nbrs_[i].used ? &nbrs_[i] : nullptr; }

  const Neighbor *NeighborOf(uint8_t id) const {
    for (unsigned i = 0; i < kMaxNeighbors; i++) if (nbrs_[i].used && nbrs_[i].id == id) return &nbrs_[i];
    return nullptr;
  }

  // Whether the network has been told that `node` is silent, by this node or by another
  bool IsSilent(uint8_t node) const {
    for (unsigned i = 0; i < kMaxOrigins; i++) if (mutes_[i].used && mutes_[i].node == node) return true;
    return false;
  }

  bool PopNotice(Notice *out) {
    if (noticeCount_ == 0) return false;
    *out = notices_[noticeHead_];
    noticeHead_ = (noticeHead_ + 1) % kNoticeSize;
    noticeCount_--;
    return true;
  }

  // Whether this node has been calling its own channel noisy
  bool Noisy() const { return noisy_; }

  // How much of what should have got through did not, in the last minute judged: the greater of the percent of strong
  // neighbours' heartbeats missed and of unicasts and answers not acknowledged
  uint8_t LossPercent() const { return lossPercent_; }

  const Stats &stats() const { return stats_; }
  uint8_t id() const { return cfg_.id; }
  uint32_t epoch() const { return cfg_.epoch; }
  unsigned queued() const { unsigned n = 0; for (unsigned i = 0; i < kTxQueue; i++) n += txq_[i].used; return n + (inflightValid_ ? 1 : 0); }
  unsigned waiting() const { unsigned n = 0; for (unsigned i = 0; i < kPendingSize; i++) n += pending_[i].used; return n; }

 private:
  struct Origin { bool used; bool synced; bool routed; bool asked; uint8_t id; uint8_t routeHops; uint8_t via[6]; uint32_t epoch; uint32_t highest; uint32_t seen; uint32_t askedAt; };
  struct Seen { bool used; bool hasFrom; uint8_t origin; uint8_t attempt; uint32_t epoch; uint32_t counter; uint8_t from[6]; };
  // `from` are the neighbours a flooded frame waiting to be repeated was heard from, for the first two copies;
  // `pingTarget` and `pingAsker` mark a ping: whom it tries, and for whom (0: for this node)
  struct TxItem { bool used; bool own; bool unicast; uint8_t len; uint8_t prio; uint8_t heard; uint8_t tries; uint8_t to[6]; uint8_t from[2]; uint8_t fromCount; uint8_t pingTarget; uint8_t pingAsker; uint32_t due; uint8_t data[kMaxFrame]; };
  struct Pending { bool used; uint8_t dest; uint8_t attempt; uint8_t len; uint32_t counter; uint32_t due; uint8_t frame[kMaxFrame]; };
  struct SyncAsk { bool used; uint8_t target; uint32_t nonce; uint32_t until; };
  struct Mute { bool used; bool mine; uint8_t node; };

  Config cfg_;
  uint32_t counter_;
  bool busy_;
  bool inflightValid_;
  TxItem inflight_;
  Origin origins_[kMaxOrigins];
  Seen seen_[kSeenSize];
  unsigned seenNext_;
  TxItem txq_[kTxQueue];
  Pending pending_[kPendingSize];
  SyncAsk asks_[kSyncSize];
  Delivery inbox_[kInboxSize];
  unsigned inboxHead_, inboxCount_;
  Outcome outcomes_[kOutcomeSize];
  unsigned outcomeHead_, outcomeCount_;
  Stats stats_;
  struct BulkIn { bool used; bool done; uint8_t origin; uint8_t total; uint8_t naks; uint16_t id; uint32_t have; uint32_t lastAt; };
  BulkIn bulkIn_[kBulkInSize];
  Neighbor nbrs_[kMaxNeighbors];
  Mute mutes_[kMaxOrigins];
  Notice notices_[kNoticeSize];
  unsigned noticeHead_, noticeCount_;
  uint8_t info_[kMaxInfo];
  uint8_t infoLen_;
  bool beatArmed_;
  uint32_t nextBeat_;
  bool noiseArmed_;
  uint32_t noiseAt_;
  uint32_t noiseHeard_, noiseMissed_;          // in this window: the heartbeats of strong neighbours that came, and that did not
  uint32_t noiseTried_, noiseFailed_;          // and the unicasts and the answers waited for, and the ones that were not acknowledged
  uint8_t loud_;                               // the windows in a row at or above the limit
  bool noisy_;
  uint8_t lossPercent_;

  uint8_t NodeOf(const uint8_t mac[6]) const { return cfg_.nodeOf != nullptr ? cfg_.nodeOf(cfg_.nodeContext, mac) : 0; }

  // Whether the neighbour at this address has said it does not hear this node: nothing sent to it would get there, so it is no way
  bool OneWay(const uint8_t mac[6]) const {
    for (unsigned i = 0; i < kMaxNeighbors; i++) if (nbrs_[i].used && memcmp(nbrs_[i].mac, mac, 6) == 0) return nbrs_[i].listsMe == 2;
    return false;
  }

  // The neighbour a frame of this origin was heard from is the way back to it, unless that neighbour does not hear this node. A way is
  // replaced only by one as near, by the hops the frame had left when it was heard: the ways kept lead nearer the origin at every hop,
  // so that a frame sent along them cannot go round or run out. A way that fails is demoted, and the next frame heard gives another
  void Learn(Origin *o, const uint8_t src[6], uint8_t hops) {
    if (OneWay(src)) return;
    if (o->routed && hops < o->routeHops) return;
    o->routed = true;
    o->routeHops = hops;
    memcpy(o->via, src, 6);
  }

  // A hop to `mac` for a frame to `dest` failed for good: the way to `dest` through it is kept, for there may be no other yet, but it
  // counts as the farthest, and the next frame heard from `dest`, by whatever neighbour, takes its place
  void DemoteRoute(uint8_t dest, const uint8_t mac[6]) {
    Origin *d = FindOrigin(dest, false);
    if (d != nullptr && d->routed && memcmp(d->via, mac, 6) == 0) d->routeHops = 0;
  }

  Origin *FindOrigin(uint8_t id, bool create) {
    Origin *free_slot = nullptr;
    for (unsigned i = 0; i < kMaxOrigins; i++) {
      if (origins_[i].used && origins_[i].id == id) return &origins_[i];
      if (!origins_[i].used && free_slot == nullptr) free_slot = &origins_[i];
    }
    if (!create || free_slot == nullptr) return nullptr;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = true;
    free_slot->id = id;
    return free_slot;
  }

  TxItem *FreeSlot() {
    for (unsigned i = 0; i < kTxQueue; i++) if (!txq_[i].used) return &txq_[i];
    return nullptr;
  }

  Pending *FreePending() {
    for (unsigned i = 0; i < kPendingSize; i++) if (!pending_[i].used) return &pending_[i];
    return nullptr;
  }

  // The header of a frame of this node's, with the next number
  Frame Header(Type type, uint8_t dest, uint8_t next, uint8_t hops, bool ackRequested, uint8_t part = 0) {
    Frame f;
    f.kind = PackKind(type, ackRequested, part, 0);
    f.origin = cfg_.id;
    f.dest = dest;
    f.next = next;
    f.hops = hops;
    f.epoch = cfg_.epoch;
    f.counter = ++counter_;
    f.payload = nullptr;
    f.len = 0;
    return f;
  }

  // What fits in a frame for `dest`: a frame for one node alone loses the tag of its seal
  size_t PayloadCap(uint8_t dest) const { return cfg_.seal != nullptr && dest != kToAll ? kMaxPayload - kPairTagLen : kMaxPayload; }

  // The header as the seal sees it: with the hops and the next hop, which change at every hop, and the attempt, which changes
  // when a frame is sent again, taken as 0
  static void CipherHeader(const Frame &f, uint8_t aad[kHeaderLen]) {
    aad[0] = kVersion;
    aad[1] = (uint8_t)(f.kind & ~3);
    aad[2] = f.origin;
    aad[3] = f.dest;
    aad[4] = 0;
    aad[5] = 0;
    Put32(aad + 6, f.epoch);
    Put32(aad + 10, f.counter);
  }

  // Puts an own frame in a slot of the queue, enciphered if there is a cipher, sealed, remembered as heard so that a neighbour's
  // repetition is a copy. False, and nothing in the slot, when the cipher has no key for the destination
  bool BuildOwn(TxItem *slot, const Frame &f, uint32_t now) {
    memset(slot, 0, sizeof(*slot));
    Frame c = f;
    uint8_t sealed[kMaxPayload];
    if (cfg_.seal != nullptr && f.len > 0) {
      uint8_t aad[kHeaderLen];
      CipherHeader(f, aad);
      size_t sn = cfg_.seal(cfg_.cipherContext, f.dest == kToAll ? 0 : f.dest, aad, f.payload, f.len, sealed);
      if (sn == 0 || sn > kMaxPayload) { stats_.noKey++; return false; }
      c.payload = sealed;
      c.len = sn;
    }
    slot->len = (uint8_t)Encode(c, slot->data);
    if (cfg_.tag != nullptr) Seal(cfg_.tag, cfg_.tagContext, slot->data, slot->len);
    slot->used = true;
    slot->own = true;
    slot->prio = FramePriority(slot->data);
    slot->heard = 1;
    slot->due = now;
    memset(slot->to, 0xff, 6);
    Remember(f.origin, f.epoch, f.counter, f.attempt(), nullptr);
    return true;
  }

  // A frame of this node's, to be flooded with `hops` repetitions left. A frame that asks for an answer and is for
  // one node is kept, sent again if none comes, and reported either way
  uint32_t Queue(Type type, uint8_t dest, const uint8_t *payload, size_t len, bool ackRequested, uint8_t hops, uint32_t now, uint8_t part = 0) {
    if (len > PayloadCap(dest)) return 0;
    bool wait = ackRequested && dest != kToAll;
    Pending *keep = nullptr;
    if (wait) {
      keep = FreePending();
      if (keep == nullptr) { stats_.queueFull++; return 0; }
    }
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return 0; }
    Frame f = Header(type, dest, 0, hops, ackRequested, part);
    f.payload = payload;
    f.len = len;
    if (!BuildOwn(slot, f, now)) return 0;
    if (wait) {
      memset(keep, 0, sizeof(*keep));
      keep->used = true;
      keep->counter = f.counter;
      keep->dest = dest;
      keep->attempt = 0;
      keep->due = now + kAnswerWaitMs;
      keep->len = slot->len;
      memcpy(keep->frame, slot->data, slot->len);
    }
    return f.counter;
  }

  bool SeenBefore(uint8_t origin, uint32_t epoch, uint32_t counter, uint8_t attempt) const {
    for (unsigned i = 0; i < kSeenSize; i++) {
      const Seen &s = seen_[i];
      if (s.used && s.origin == origin && s.epoch == epoch && s.counter == counter && s.attempt == attempt) return true;
    }
    return false;
  }

  void Remember(uint8_t origin, uint32_t epoch, uint32_t counter, uint8_t attempt, const uint8_t *from) {
    Seen &s = seen_[seenNext_];
    seenNext_ = (seenNext_ + 1) % kSeenSize;
    s.used = true;
    s.origin = origin;
    s.epoch = epoch;
    s.counter = counter;
    s.attempt = attempt;
    s.hasFrom = from != nullptr;
    if (from != nullptr) memcpy(s.from, from, 6);
  }

  // A copy of a frame this node is waiting to repeat was heard again, from the neighbour `from`. Two copies make this
  // node drop its own, the neighbours having covered what it would, unless it is the only way to one of its own
  void CountCopy(uint8_t origin, uint32_t epoch, uint32_t counter, uint8_t attempt, uint8_t from, uint32_t now) {
    for (unsigned i = 0; i < kTxQueue; i++) {
      TxItem &t = txq_[i];
      if (!t.used || t.own || t.unicast) continue;
      if (t.data[2] != origin || Get32(t.data + 6) != epoch || Get32(t.data + 10) != counter || (t.data[1] & 3) != attempt) continue;
      if (t.heard < 255) t.heard++;
      if (t.fromCount < 2) t.from[t.fromCount++] = from;
      if (t.heard >= cfg_.suppressAt) {
        if (SolePath(t, now)) stats_.keptAsOnlyWay++;
        else { t.used = false; stats_.suppressed++; }
      }
      return;
    }
  }

  // Whether the frame waiting in `t` is the only way it has to one of this node's neighbours: one that the senders it was heard
  // from, and its origin, do not hear, by the lists in their heartbeats. A sender whose list is not known covers only itself
  bool SolePath(const TxItem &t, uint32_t now) const {
    if (cfg_.beatEveryMs == 0) return false;
    uint8_t origin = t.data[2];
    for (unsigned i = 0; i < kMaxNeighbors; i++) {
      const Neighbor &m = nbrs_[i];
      if (!m.used || m.state != kAlive || m.listsMe == 2 || m.id == origin) continue;
      if ((int32_t)(now - m.lastHeard) >= (int32_t)kHeardWindowMs) continue;
      bool covered = false;
      for (unsigned k = 0; k < t.fromCount && !covered; k++) {
        if (t.from[k] == m.id) { covered = true; break; }
        const Neighbor *s = NeighborOf(t.from[k]);
        covered = s != nullptr && Lists(*s, m.id);
      }
      const Neighbor *o = NeighborOf(origin);
      if (!covered && o != nullptr && Lists(*o, m.id)) covered = true;
      if (!covered) return true;
    }
    return false;
  }

  // Whether the last heartbeat of `n` listed `id` among the ones it hears
  static bool Lists(const Neighbor &n, uint8_t id) {
    if (n.beatAt == 0) return false;
    for (unsigned i = 0; i < n.hearsCount; i++) if (n.hears[i] == id) return true;
    return false;
  }

  // What happens to a frame that is not for this node alone: a flooded one is repeated, a routed one goes on
  void Pass(const Frame &f, const uint8_t *data, size_t n, int8_t rssi, uint32_t now, uint8_t from = 0) {
    if (f.hops == 0 || f.dest == cfg_.id) return;
    if (f.routed()) Forward(data, n, f, now); else Schedule(data, n, rssi, now, from);
  }

  void Schedule(const uint8_t *data, size_t n, int8_t rssi, uint32_t now, uint8_t from) {
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return; }
    memset(slot, 0, sizeof(*slot));
    memcpy(slot->data, data, n);
    slot->len = (uint8_t)n;
    slot->data[4] = 0;
    slot->data[5] = data[5] - 1;
    slot->used = true;
    memset(slot->to, 0xff, 6);
    slot->prio = FramePriority(data);
    slot->heard = 1;
    slot->from[0] = from;
    slot->fromCount = 1;
    uint32_t r = cfg_.random != nullptr ? cfg_.random(cfg_.context) : 0;
    slot->due = now + (rssi < cfg_.weakDbm ? r % 4 : 3 + r % 6);
  }

  // A routed frame for someone else: to the neighbour this node keeps for its destination, with no wait
  void Forward(const uint8_t *data, size_t n, const Frame &f, uint32_t now) {
    Origin *d = FindOrigin(f.dest, false);
    uint8_t next = d != nullptr && d->routed ? NodeOf(d->via) : 0;
    if (next == 0) { stats_.noRoute++; return; }
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return; }
    memset(slot, 0, sizeof(*slot));
    memcpy(slot->data, data, n);
    slot->len = (uint8_t)n;
    slot->data[4] = next;
    slot->data[5] = data[5] - 1;
    slot->used = true;
    slot->unicast = true;
    memcpy(slot->to, d->via, 6);
    slot->prio = FramePriority(data);
    slot->heard = 1;
    slot->due = now;
  }

  void Deliver(const Frame &f, const uint8_t src[6], int8_t rssi, bool retry) {
    if (inboxCount_ >= kInboxSize) { stats_.inboxFull++; return; }
    Delivery &d = inbox_[(inboxHead_ + inboxCount_) % kInboxSize];
    inboxCount_++;
    d.origin = f.origin;
    d.type = f.type();
    d.ackRequested = f.ackRequested();
    d.retry = retry;
    d.part = f.part();
    d.attempt = f.attempt();
    d.dest = f.dest;
    d.epoch = f.epoch;
    d.counter = f.counter;
    d.rssi = rssi;
    memcpy(d.from, src, 6);
    // the second part of a message leads with the number of the first, which is not the application's data
    bool second = f.part() == 2 && f.len >= 4;
    d.joins = second ? Get32(f.payload) : 0;
    d.len = (uint8_t)(f.len - (second ? 4 : 0));
    memcpy(d.payload, f.payload + (second ? 4 : 0), d.len);
    stats_.delivered++;
  }

  void Report(uint32_t counter, uint8_t dest, bool ok, uint8_t attempts) {
    if (outcomeCount_ >= kOutcomeSize) return;
    Outcome &o = outcomes_[(outcomeHead_ + outcomeCount_) % kOutcomeSize];
    outcomeCount_++;
    o.counter = counter;
    o.dest = dest;
    o.ok = ok;
    o.attempts = attempts;
  }

  // "Received", for a frame of `f.origin`, along the way back: the number and the attempt it answers
  void SendAck(const Frame &f, uint32_t now) {
    uint8_t p[5];
    Put32(p, f.counter);
    p[4] = f.attempt();
    if (SendRouted(kAck, f.origin, p, sizeof(p), now) != 0) stats_.acksSent++;
  }

  void HandleAck(const Frame &f) {
    if (f.len < 5) return;
    uint32_t counter = Get32(f.payload);
    for (unsigned i = 0; i < kPendingSize; i++) {
      Pending &p = pending_[i];
      if (!p.used || p.counter != counter || p.dest != f.origin) continue;
      Report(p.counter, p.dest, true, p.attempt + 1);
      stats_.acksHeard++;
      noiseTried_++;
      p.used = false;
      return;
    }
  }

  // The sync exchange. It has no replay window of its own: a frame of it is a copy or it is handled, and an answer
  // counts only for the exchange this node started, with its nonce
  Verdict OnSync(const Frame &f, const uint8_t *data, size_t n, int8_t rssi, uint32_t now, bool forMe, uint8_t from) {
    if (forMe && f.len >= 5 && f.payload[0] == kSyncAsk && f.origin != cfg_.id) {
      uint8_t a[21];
      a[0] = kSyncAnswer;
      memcpy(a + 1, f.payload + 1, 4);
      Put32(a + 5, cfg_.epoch);
      Put32(a + 9, counter_);
      memset(a + 13, 0, 8);
      if (cfg_.proof != nullptr) cfg_.proof(cfg_.proofContext, f.origin, Get32(f.payload + 1), cfg_.epoch, counter_, a + 13);
      // every node that hears a flooded ask answers it: a few milliseconds apart, so that the answers do not meet on the way back
      SendRouted(kSync, f.origin, a, cfg_.proof != nullptr ? 21 : 13, now, cfg_.random != nullptr ? cfg_.random(cfg_.context) % 16 : 0);
    } else if (forMe && f.dest == cfg_.id && f.len >= 13 && f.payload[0] == kSyncAnswer) {
      uint32_t nonce = Get32(f.payload + 1);
      for (unsigned i = 0; i < kSyncSize; i++) {
        SyncAsk &a = asks_[i];
        if (!a.used || a.nonce != nonce || (a.target != kToAll && a.target != f.origin)) continue;
        uint32_t epoch = Get32(f.payload + 5), counter = Get32(f.payload + 9);
        bool ok = true;
        if (cfg_.proof != nullptr) {
          uint8_t want[8];
          cfg_.proof(cfg_.proofContext, f.origin, nonce, epoch, counter, want);
          ok = f.len >= 21 && memcmp(want, f.payload + 13, 8) == 0;
        }
        if (ok) {
          SetSynced(f.origin, epoch, counter);
          stats_.syncDone++;
          if (a.target != kToAll) a.used = false;
        } else {
          stats_.syncBad++;
        }
        break;
      }
    }
    Pass(f, data, n, rssi, now, from);
    return kAccepted;
  }

  // --- the bulk transfer -------------------------------------------------------------------------

  bool HasRoute(uint8_t dest) {
    Origin *d = FindOrigin(dest, false);
    return d != nullptr && d->routed && NodeOf(d->via) != 0;
  }

  // A frame for `dest` along the way back when there is one, and flooded when there is not
  uint32_t SendAlong(Type type, uint8_t dest, const uint8_t *payload, size_t len, uint32_t now) {
    if (HasRoute(dest)) return SendRouted(type, dest, payload, len, now);
    return Queue(type, dest, payload, len, false, kMaxHops, now);
  }

  // The pieces of a transfer not had yet, a bit each
  static uint32_t Missing(const BulkIn &b) {
    uint32_t all = b.total >= 32 ? 0xffffffffu : ((uint32_t)1 << b.total) - 1;
    return all & ~b.have;
  }

  void SendDone(const BulkIn &b, uint32_t now) {
    uint8_t p[3] = {kBulkSubDone, (uint8_t)b.id, (uint8_t)(b.id >> 8)};
    SendAlong(kBulk, b.origin, p, sizeof(p), now);
  }

  // The slot a new transfer takes: a free one, else the oldest that is complete, else the oldest of all
  BulkIn *SpareBulk() {
    BulkIn *best = nullptr;
    int bestRank = 3;
    for (unsigned i = 0; i < kBulkInSize; i++) {
      BulkIn &c = bulkIn_[i];
      int rank = !c.used ? 0 : c.done ? 1 : 2;
      if (rank < bestRank || (rank == bestRank && (int32_t)(c.lastAt - best->lastAt) < 0)) { best = &c; bestRank = rank; }
    }
    return best;
  }

  // A frame of a bulk transfer addressed to this node: a piece is remembered, and when it is the last one the sender is told;
  // returns whether the application is to have it (a piece it has had is not given again; what is not a piece is its own)
  bool TrackPiece(const Frame &f, uint32_t now) {
    if (f.len < 5 || f.payload[0] != kBulkSubPiece) return true;
    uint16_t id = (uint16_t)(f.payload[1] | f.payload[2] << 8);
    uint8_t index = f.payload[3], total = f.payload[4];
    if (total == 0 || total > kBulkMaxPieces || index >= total) return false;
    BulkIn *b = nullptr;
    for (unsigned i = 0; i < kBulkInSize; i++) if (bulkIn_[i].used && bulkIn_[i].origin == f.origin && bulkIn_[i].id == id) b = &bulkIn_[i];
    if (b == nullptr) {
      b = SpareBulk();
      memset(b, 0, sizeof(*b));
      b->used = true;
      b->origin = f.origin;
      b->id = id;
      b->total = total;
    } else if (b->total != total) {
      // the same id, a transfer of another size: a new one
      b->total = total;
      b->have = 0;
      b->done = false;
      b->naks = 0;
    }
    bool fresh = (b->have & ((uint32_t)1 << index)) == 0;
    b->have |= (uint32_t)1 << index;
    b->lastAt = now;
    stats_.piecesNew += fresh;
    if (!fresh) {
      stats_.piecesRepeated++;
      // a piece of a transfer that is complete: the sender did not hear that it is
      if (b->done) SendDone(*b, now);
      return false;
    }
    if (Missing(*b) == 0 && !b->done) {
      b->done = true;
      SendDone(*b, now);
      Post(kNoticeBulkDone, b->origin, cfg_.id, b->id);
      stats_.bulkDone++;
    }
    return true;
  }

  // --- the supervision ---------------------------------------------------------------------------

  void Post(NoticeKind kind, uint8_t node, uint8_t by, uint32_t value = 0) {
    if (noticeCount_ >= kNoticeSize) return;
    Notice &n = notices_[(noticeHead_ + noticeCount_) % kNoticeSize];
    noticeCount_++;
    n.node = node;
    n.kind = kind;
    n.by = by;
    n.value = value;
  }

  Neighbor *FindNeighbor(uint8_t id, bool create) {
    Neighbor *free_slot = nullptr, *oldest = nullptr;
    for (unsigned i = 0; i < kMaxNeighbors; i++) {
      Neighbor &n = nbrs_[i];
      if (n.used && n.id == id) return &n;
      if (!n.used) { if (free_slot == nullptr) free_slot = &n; }
      else if (oldest == nullptr || (int32_t)(n.lastHeard - oldest->lastHeard) < 0) oldest = &n;
    }
    if (!create) return nullptr;
    Neighbor *n = free_slot != nullptr ? free_slot : oldest;
    memset(n, 0, sizeof(*n));
    n->used = true;
    n->id = id;
    // a heartbeat is heard by all the neighbours of its sender at once, so their timers would run out together: each waits
    // a different while, and the first to give up a neighbour says so for the others, that are by then trying it
    n->jitter = (uint16_t)(cfg_.random != nullptr ? cfg_.random(cfg_.context) % kSuspectJitterMs : 0);
    return n;
  }

  Mute *FindMute(uint8_t node) {
    for (unsigned i = 0; i < kMaxOrigins; i++) if (mutes_[i].used && mutes_[i].node == node) return &mutes_[i];
    return nullptr;
  }

  // A frame that got through the gate was sent by the neighbour `id` just now, heard at `rssi`
  void Touch(uint8_t id, const uint8_t mac[6], int8_t rssi, uint32_t now) {
    if (id == 0 || id == cfg_.id || id == kToAll) return;
    Neighbor *n = FindNeighbor(id, true);
    memcpy(n->mac, mac, 6);
    n->rssi = n->rssi == 0 ? rssi : (int8_t)((3 * n->rssi + rssi) / 4);
    n->lastHeard = now;
    if (n->state == kMute) n->beatAt = 0;
    n->state = kAlive;
    NodeIsAlive(id, now);
  }

  // `id` is known to be alive: if the network was told it is silent, it is back, and the node that said so says it
  void NodeIsAlive(uint8_t id, uint32_t now) {
    Mute *m = FindMute(id);
    if (m == nullptr) return;
    bool mine = m->mine;
    m->used = false;
    Post(kNoticeBack, id, cfg_.id);
    if (mine) FloodVerdict(id, false, now);
  }

  void SetMute(uint8_t node, bool silent, bool mine, uint8_t by) {
    Mute *m = FindMute(node);
    if (!silent) {
      if (m != nullptr) { m->used = false; Post(kNoticeBack, node, by); }
      return;
    }
    if (m != nullptr) return;
    for (unsigned i = 0; i < kMaxOrigins; i++) {
      if (mutes_[i].used) continue;
      mutes_[i].used = true;
      mutes_[i].node = node;
      mutes_[i].mine = mine;
      Post(kNoticeSilent, node, by);
      // a neighbour this node was itself trying is given up with the others, without a verdict of this node's own
      Neighbor *suspect = FindNeighbor(node, false);
      if (suspect != nullptr && suspect->state == kSuspect) suspect->state = kMute;
      return;
    }
  }

  void FloodVerdict(uint8_t node, bool silent, uint32_t now) {
    uint8_t p[3] = {kSubVerdict, node, (uint8_t)(silent ? 1 : 0)};
    if (Queue(kBeat, kToAll, p, sizeof(p), false, kMaxHops, now) != 0) stats_.verdictsSent++;
  }

  // The heartbeat: what the application keeps in it, and who this node has heard lately, with the signal
  void QueueBeat(uint32_t now) {
    uint8_t p[kMaxPayload];
    size_t at = 0;
    p[at++] = kSubBeat;
    p[at++] = infoLen_;
    if (infoLen_ > 0) memcpy(p + at, info_, infoLen_);
    at += infoLen_;
    size_t countAt = at++;
    uint8_t count = 0;
    for (unsigned i = 0; i < kMaxNeighbors; i++) {
      const Neighbor &n = nbrs_[i];
      if (!n.used || n.rssi == 0 || (int32_t)(now - n.lastHeard) >= (int32_t)kHeardWindowMs) continue;
      p[at++] = n.id;
      p[at++] = (uint8_t)n.rssi;
      count++;
    }
    p[countAt] = count;
    if (Queue(kBeat, kToAll, p, at, false, 0, now) != 0) stats_.beatsSent++;
  }

  // A unicast to a neighbour's own address, which the radio hands over and the neighbour's radio acknowledges
  uint32_t SendDirect(const Neighbor &to, const uint8_t *payload, size_t len, uint32_t now, uint8_t pingTarget, uint8_t pingAsker) {
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return 0; }
    Frame f = Header(kBeat, to.id, to.id, 0, false);
    f.payload = payload;
    f.len = len;
    if (!BuildOwn(slot, f, now)) return 0;
    memcpy(slot->to, to.mac, 6);
    slot->unicast = true;
    slot->pingTarget = pingTarget;
    slot->pingAsker = pingAsker;
    return f.counter;
  }

  void StartPing(const Neighbor &target, uint8_t asker, uint32_t now) {
    uint8_t p[1] = {kSubPing};
    if (SendDirect(target, p, sizeof(p), now, target.id, asker) != 0) stats_.pings++;
  }

  // The neighbours asked to try a suspect: of those that hear it and are heard back, the two of the best signal
  void SendProbes(const Neighbor &suspect, uint32_t now) {
    bool taken[kMaxNeighbors] = {};
    for (unsigned sent = 0; sent < kProbeHelpers; sent++) {
      int best = -1;
      for (unsigned i = 0; i < kMaxNeighbors; i++) {
        const Neighbor &n = nbrs_[i];
        if (!n.used || taken[i] || n.id == suspect.id || n.state != kAlive || n.listsMe == 2 || !Lists(n, suspect.id)) continue;
        if (best < 0 || n.rssi > nbrs_[best].rssi) best = (int)i;
      }
      if (best < 0) return;
      taken[best] = true;
      uint8_t p[2] = {kSubProbe, suspect.id};
      if (SendDirect(nbrs_[best], p, sizeof(p), now, 0, 0) != 0) stats_.probes++;
    }
  }

  // What became of a ping: for this node's own, a neighbour that answers is alive and one that does not is tried through
  // the others; for another's, an answer is passed on to the one that asked
  void OnPingResult(uint8_t target, uint8_t asker, bool ok, uint32_t now) {
    if (asker == 0) {
      Neighbor *n = FindNeighbor(target, false);
      if (n == nullptr || n->state != kSuspect) return;
      if (ok) { n->state = kAlive; n->lastHeard = now; stats_.rescued++; }
      else SendProbes(*n, now);
    } else if (ok) {
      const Neighbor *a = NeighborOf(asker);
      uint8_t p[2] = {kSubAlive, target};
      if (a != nullptr) SendDirect(*a, p, sizeof(p), now, 0, 0);
    }
  }

  void OnBeat(const Frame &f, uint8_t from, uint32_t now) {
    Neighbor *n = FindNeighbor(from, false);
    if (n == nullptr || f.len < 3) return;
    size_t il = f.payload[1];
    if (2 + il + 1 > f.len) return;
    n->infoLen = (uint8_t)(il > kMaxInfo ? kMaxInfo : il);
    memcpy(n->info, f.payload + 2, n->infoLen);
    size_t at = 2 + il;
    size_t count = f.payload[at++];
    if (at + 2 * count > f.len) count = (f.len - at) / 2;
    n->hearsCount = 0;
    n->listsMe = 2;
    n->theirRssi = 0;
    for (size_t i = 0; i < count; i++) {
      uint8_t id = f.payload[at + 2 * i];
      if (id == cfg_.id) { n->listsMe = 1; n->theirRssi = (int8_t)f.payload[at + 2 * i + 1]; }
      if (n->hearsCount < kMaxNeighbors) n->hears[n->hearsCount++] = id;
    }
    // a neighbour that does not hear this node is no way back to anyone, whatever came by it before the first heartbeat told
    if (n->listsMe == 2) {
      for (unsigned i = 0; i < kMaxOrigins; i++) if (origins_[i].used && origins_[i].routed && memcmp(origins_[i].via, n->mac, 6) == 0) origins_[i].routed = false;
    }
    // heartbeats that should have come from a strong neighbour and did not are the channel's; a gap longer than a window
    // is the neighbour's, and a neighbour that was given up starts its count again
    if (n->beatAt != 0 && n->rssi >= cfg_.weakDbm) {
      uint32_t gap = now - n->beatAt, every = cfg_.beatEveryMs;
      noiseHeard_++;
      if (gap > every + every / 2 && gap < kNoiseWindowMs) noiseMissed_ += gap / every - 1;
    }
    n->beatAt = now;
    stats_.beatsHeard++;
  }

  void OnSupervision(const Frame &f, uint8_t from, uint32_t now) {
    if (f.len < 1) return;
    switch (f.payload[0]) {
      case kSubBeat:
        OnBeat(f, from, now);
        break;
      case kSubProbe:
        if (f.dest == cfg_.id && f.len >= 2) {
          const Neighbor *t = NeighborOf(f.payload[1]);
          if (t != nullptr && t->state != kMute) StartPing(*t, f.origin, now);
        }
        break;
      case kSubAlive:
        if (f.dest == cfg_.id && f.len >= 2) {
          Neighbor *t = FindNeighbor(f.payload[1], false);
          if (t != nullptr && t->state == kSuspect) { t->state = kAlive; t->lastHeard = now; stats_.rescued++; }
        }
        break;
      case kSubVerdict:
        if (f.dest == kToAll && f.len >= 3) {
          stats_.verdictsHeard++;
          uint8_t node = f.payload[1];
          bool silent = f.payload[2] != 0;
          // a node told it is silent says it is not
          if (node == cfg_.id) { if (silent) FloodVerdict(cfg_.id, false, now); }
          else SetMute(node, silent, false, f.origin);
        }
        break;
      case kSubNoise:
        if (f.dest == kToAll && f.len >= 2) Post(f.payload[1] != 0 ? kNoticeNoisy : kNoticeCalm, f.origin, f.origin);
        break;
      default:
        break;
    }
  }

  // The heartbeat is due, the neighbours that have gone quiet are suspected and, in the end, declared silent, and
  // the noise of the last minute is judged
  void Supervise(uint32_t now) {
    if (!beatArmed_) {
      beatArmed_ = true;
      nextBeat_ = now + (cfg_.random != nullptr ? cfg_.random(cfg_.context) % cfg_.beatEveryMs : 0);
    } else if ((int32_t)(now - nextBeat_) >= 0) {
      QueueBeat(now);
      nextBeat_ = now + cfg_.beatEveryMs + (cfg_.random != nullptr ? cfg_.random(cfg_.context) % kBeatJitterMs : 0);
    }
    for (unsigned i = 0; i < kMaxNeighbors; i++) {
      Neighbor &n = nbrs_[i];
      if (!n.used) continue;
      if (n.state == kAlive && (int32_t)(now - n.lastHeard) >= (int32_t)(kSuspectAfterMs + n.jitter)) {
        n.state = kSuspect;
        n.suspectAt = now;
        StartPing(n, 0, now);
      } else if (n.state == kSuspect && (int32_t)(now - n.suspectAt) >= (int32_t)kSilentAfterMs) {
        n.state = kMute;
        if (!IsSilent(n.id)) {
          SetMute(n.id, true, true, cfg_.id);
          FloodVerdict(n.id, true, now);
        }
      }
    }
    if (!noiseArmed_) {
      noiseArmed_ = true;
      noiseAt_ = now + kNoiseWindowMs;
    } else if ((int32_t)(now - noiseAt_) >= 0) {
      noiseAt_ = now + kNoiseWindowMs;
      // a minute is loud when enough of what should have got through did not: of the heartbeats of strong neighbours, or of the
      // unicasts and the answers; and quiet when less than half that did not. Too few to judge is quiet
      uint32_t beats = noiseHeard_ + noiseMissed_, limit = cfg_.noiseLimit;
      uint32_t byBeats = beats != 0 ? noiseMissed_ * 100 / beats : 0, byHops = noiseTried_ != 0 ? noiseFailed_ * 100 / noiseTried_ : 0;
      lossPercent_ = (uint8_t)(byBeats > byHops ? byBeats : byHops);
      bool loud = (beats >= 12 && noiseMissed_ * 100 >= limit * beats) || (noiseTried_ >= 6 && noiseFailed_ * 100 >= limit * noiseTried_);
      bool quiet = (beats == 0 || noiseMissed_ * 200 < limit * beats) && (noiseTried_ == 0 || noiseFailed_ * 200 < limit * noiseTried_);
      if (loud) {
        if (++loud_ >= 2 && !noisy_) {
          noisy_ = true;
          Post(kNoticeNoisy, cfg_.id, cfg_.id);
          uint8_t p[2] = {kSubNoise, 1};
          if (Queue(kBeat, kToAll, p, sizeof(p), false, kMaxHops, now) != 0) stats_.noiseSent++;
        }
      } else {
        loud_ = 0;
        if (quiet && noisy_) {
          noisy_ = false;
          Post(kNoticeCalm, cfg_.id, cfg_.id);
          uint8_t p[2] = {kSubNoise, 0};
          if (Queue(kBeat, kToAll, p, sizeof(p), false, kMaxHops, now) != 0) stats_.noiseSent++;
        }
      }
      noiseHeard_ = noiseMissed_ = noiseTried_ = noiseFailed_ = 0;
    }
  }
};

}  // namespace EspNowMesh

#endif  // _ESPNOW_MESH_CORE_H_
