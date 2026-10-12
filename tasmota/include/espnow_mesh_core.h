/*
  espnow_mesh_core.h - ESP-NOW mesh: frame format, duplicate suppression, replay window, flooding,
                       routing back along the way a frame came, acknowledgement with resend, and the sync exchange

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

constexpr uint32_t kAnswerWaitMs = 100;      // between an attempt and the next, and after the last
constexpr uint8_t kMaxAttempt = 2;           // the attempt that is the last: 0, 1 and 2
constexpr unsigned kHopTries = 3;            // times a routed hop is handed to the radio
constexpr uint32_t kSyncWaitMs = 2000;       // an exchange that has had no answer by then is given up
constexpr uint32_t kSyncAskEveryMs = 1000;   // the least between two asks to the same origin

enum Type : uint8_t { kCommand = 0, kAck = 1, kState = 2, kEvent = 3, kBeat = 4, kBulk = 5, kMembership = 6, kSync = 7 };

// The sync exchange's two frames, the first byte of their payload
constexpr uint8_t kSyncAsk = 1;              // nonce(4)
constexpr uint8_t kSyncAnswer = 2;           // nonce(4) epoch(4) counter(4) proof(8)

// What the user of this file computes: the tag of `len` bytes, with the key it holds
typedef void (*TagFunction)(const uint8_t *data, size_t len, uint8_t tag[kTagLen], void *context);
// The proof that `peer`'s answer to a nonce is its own: from the key this node shares with `peer`
typedef void (*ProofFunction)(void *context, uint8_t peer, uint32_t nonce, uint32_t epoch, uint32_t counter, uint8_t proof[8]);
// The number of the node with this address, or 0 when it is not known
typedef uint8_t (*NodeOfFunction)(void *context, const uint8_t mac[6]);

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

// What a node does with a frame it hears
enum Verdict : uint8_t { kAccepted, kRetry, kRepeated, kReplayed, kStale, kNeedsSync, kIgnored, kBad };

struct Delivery {
  uint8_t origin;
  Type type;
  bool ackRequested;
  bool retry;                                  // a number already delivered, heard again with a higher attempt
  uint8_t part;
  uint8_t attempt;
  uint8_t dest;
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
};

class Node {
 public:
  void Begin(const Config &config) {
    memset(this, 0, sizeof(*this));
    cfg_ = config;
    if (cfg_.weakDbm == 0) cfg_.weakDbm = -70;
    if (cfg_.suppressAt == 0) cfg_.suppressAt = 2;
  }

  // The application hands over a frame for `dest` (kToAll for everyone), to be flooded. Returns its counter, or 0.
  // A frame that asks for an answer and is for one node is kept, sent again if none comes, and reported either way
  uint32_t Send(Type type, uint8_t dest, const uint8_t *payload, size_t len, bool ackRequested, uint32_t now) {
    if (len > kMaxPayload) return 0;
    bool wait = ackRequested && dest != kToAll;
    Pending *keep = nullptr;
    if (wait) {
      keep = FreePending();
      if (keep == nullptr) { stats_.queueFull++; return 0; }
    }
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return 0; }
    Frame f = Header(type, dest, 0, type == kBeat ? 0 : kMaxHops, ackRequested);
    f.payload = payload;
    f.len = len;
    BuildOwn(slot, f, now);
    memset(slot->to, 0xff, 6);
    slot->unicast = false;
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

  // The same, along the way back to `dest` instead of by flooding: for an answer to a frame that was flooded. Returns the
  // counter, or 0 when this node has no way to `dest`
  uint32_t SendRouted(Type type, uint8_t dest, const uint8_t *payload, size_t len, uint32_t now, uint32_t delayMs = 0) {
    if (len > kMaxPayload) return 0;
    Origin *d = FindOrigin(dest, false);
    uint8_t next = d != nullptr && d->routed ? NodeOf(d->via) : 0;
    if (next == 0) { stats_.noRoute++; return 0; }
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return 0; }
    Frame f = Header(type, dest, next, kMaxHops, false);
    f.payload = payload;
    f.len = len;
    BuildOwn(slot, f, now);
    memcpy(slot->to, d->via, 6);
    slot->unicast = true;
    slot->due = now + delayMs;
    return f.counter;
  }

  // The radio heard `n` bytes from the neighbour `src`, with the signal `rssi`
  Verdict OnReceive(const uint8_t *data, size_t n, const uint8_t src[6], int8_t rssi, uint32_t now) {
    Frame f;
    if (!Decode(data, n, &f)) { stats_.bad++; return kBad; }
    if (cfg_.tag != nullptr && !TagMatches(cfg_.tag, cfg_.tagContext, data, n)) { stats_.bad++; return kBad; }
    if (f.origin == cfg_.id || f.origin == 0 || f.origin == kToAll) return kIgnored;
    // a routed frame is for the neighbour it names, and the others, if they heard it, leave it alone
    if (f.routed() && f.next != cfg_.id) return kIgnored;
    stats_.heard++;
    // a copy of what is in hand, or of what was handled: counted for the suppression and no more
    if (SeenBefore(f.origin, f.epoch, f.counter, f.attempt())) {
      stats_.repeated++;
      CountCopy(f.origin, f.epoch, f.counter, f.attempt());
      return kRepeated;
    }
    Origin *o = FindOrigin(f.origin, true);
    if (o == nullptr) { stats_.unsynced++; return kNeedsSync; }
    bool forMe = f.dest == cfg_.id || f.dest == kToAll;
    if (f.type() == kSync) {
      Learn(o, src);
      Remember(f.origin, f.epoch, f.counter, f.attempt(), src);
      // an origin that asks from an epoch above the one kept has started again: it is asked in its turn, before its first data frame
      if (f.epoch > o->epoch && o->synced) o->synced = false;
      return OnSync(f, data, n, rssi, now, forMe);
    }
    bool known = false;                        // this number has been delivered before
    // a frame refused for want of a sync, or for its epoch, is not remembered: it is not one this node has handled, and the
    // sender's next attempt, or this very frame heard again, is taken once the origin is known. The way back is learned
    // from it when this node has none, because the sync exchange goes that way
    if (!o->synced) { if (!o->routed) Learn(o, src); stats_.unsynced++; return kNeedsSync; }
    if (f.epoch < o->epoch) { stats_.stale++; return kStale; }
    if (f.epoch > o->epoch) { o->synced = false; if (!o->routed) Learn(o, src); stats_.unsynced++; return kNeedsSync; }
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
    Learn(o, src);
    Remember(f.origin, f.epoch, f.counter, f.attempt(), src);
    if (forMe && f.type() == kAck) {
      HandleAck(f);
    } else if (forMe) {
      Deliver(f, src, rssi, known);
      // answered at once, before the application has done anything with it, and every attempt
      if (f.ackRequested() && f.dest == cfg_.id) SendAck(f, now);
    }
    Pass(f, data, n, rssi, now);
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
        p.used = false;
        continue;
      }
      TxItem *slot = FreeSlot();
      if (slot == nullptr) { p.due = now + 1; continue; }
      p.attempt++;
      memcpy(slot->data, p.frame, p.len);
      slot->len = p.len;
      slot->data[1] = (uint8_t)((slot->data[1] & ~3) | p.attempt);
      if (cfg_.tag != nullptr) Seal(cfg_.tag, cfg_.tagContext, slot->data, slot->len);
      slot->used = true;
      slot->own = true;
      slot->unicast = false;
      memset(slot->to, 0xff, 6);
      slot->prio = PriorityOf((Type)(slot->data[1] >> 5));
      slot->heard = 1;
      slot->due = now;
      slot->tries = 0;
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

  // The radio says what became of the last frame: a unicast that the neighbour did not acknowledge is handed over again
  void TxDone(bool ok, uint32_t now) {
    if (inflightValid_ && inflight_.unicast && !ok) {
      if (++inflight_.tries < kHopTries) {
        TxItem *slot = FreeSlot();
        if (slot != nullptr) { *slot = inflight_; slot->due = now + 1; }
      } else {
        stats_.hopFailed++;
      }
    }
    inflightValid_ = false;
    busy_ = false;
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

  const Stats &stats() const { return stats_; }
  uint8_t id() const { return cfg_.id; }
  uint32_t epoch() const { return cfg_.epoch; }
  unsigned queued() const { unsigned n = 0; for (unsigned i = 0; i < kTxQueue; i++) n += txq_[i].used; return n + (inflightValid_ ? 1 : 0); }
  unsigned waiting() const { unsigned n = 0; for (unsigned i = 0; i < kPendingSize; i++) n += pending_[i].used; return n; }

 private:
  struct Origin { bool used; bool synced; bool routed; bool asked; uint8_t id; uint8_t via[6]; uint32_t epoch; uint32_t highest; uint32_t seen; uint32_t askedAt; };
  struct Seen { bool used; bool hasFrom; uint8_t origin; uint8_t attempt; uint32_t epoch; uint32_t counter; uint8_t from[6]; };
  struct TxItem { bool used; bool own; bool unicast; uint8_t len; uint8_t prio; uint8_t heard; uint8_t tries; uint8_t to[6]; uint32_t due; uint8_t data[kMaxFrame]; };
  struct Pending { bool used; uint8_t dest; uint8_t attempt; uint8_t len; uint32_t counter; uint32_t due; uint8_t frame[kMaxFrame]; };
  struct SyncAsk { bool used; uint8_t target; uint32_t nonce; uint32_t until; };

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

  uint8_t NodeOf(const uint8_t mac[6]) const { return cfg_.nodeOf != nullptr ? cfg_.nodeOf(cfg_.nodeContext, mac) : 0; }

  // The neighbour a frame of this origin was first heard from is the way back to it
  static void Learn(Origin *o, const uint8_t src[6]) {
    o->routed = true;
    memcpy(o->via, src, 6);
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
  Frame Header(Type type, uint8_t dest, uint8_t next, uint8_t hops, bool ackRequested) {
    Frame f;
    f.kind = PackKind(type, ackRequested, 0, 0);
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

  // Puts an own frame in a slot of the queue, sealed, remembered as heard so that a neighbour's repetition is a copy
  void BuildOwn(TxItem *slot, const Frame &f, uint32_t now) {
    slot->len = (uint8_t)Encode(f, slot->data);
    if (cfg_.tag != nullptr) Seal(cfg_.tag, cfg_.tagContext, slot->data, slot->len);
    slot->used = true;
    slot->own = true;
    slot->prio = PriorityOf(f.type());
    slot->heard = 1;
    slot->tries = 0;
    slot->due = now;
    Remember(f.origin, f.epoch, f.counter, f.attempt(), nullptr);
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

  // A copy of a frame this node is waiting to repeat was heard again
  void CountCopy(uint8_t origin, uint32_t epoch, uint32_t counter, uint8_t attempt) {
    for (unsigned i = 0; i < kTxQueue; i++) {
      TxItem &t = txq_[i];
      if (!t.used || t.own || t.unicast) continue;
      if (t.data[2] != origin || Get32(t.data + 6) != epoch || Get32(t.data + 10) != counter || (t.data[1] & 3) != attempt) continue;
      if (t.heard < 255) t.heard++;
      if (t.heard >= cfg_.suppressAt) { t.used = false; stats_.suppressed++; }
      return;
    }
  }

  // What happens to a frame that is not for this node alone: a flooded one is repeated, a routed one goes on
  void Pass(const Frame &f, const uint8_t *data, size_t n, int8_t rssi, uint32_t now) {
    if (f.hops == 0 || f.dest == cfg_.id) return;
    if (f.routed()) Forward(data, n, f, now); else Schedule(data, n, rssi, now);
  }

  void Schedule(const uint8_t *data, size_t n, int8_t rssi, uint32_t now) {
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; return; }
    memcpy(slot->data, data, n);
    slot->len = (uint8_t)n;
    slot->data[4] = 0;
    slot->data[5] = data[5] - 1;
    slot->used = true;
    slot->own = false;
    slot->unicast = false;
    slot->tries = 0;
    memset(slot->to, 0xff, 6);
    slot->prio = PriorityOf((Type)(data[1] >> 5));
    slot->heard = 1;
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
    memcpy(slot->data, data, n);
    slot->len = (uint8_t)n;
    slot->data[4] = next;
    slot->data[5] = data[5] - 1;
    slot->used = true;
    slot->own = false;
    slot->unicast = true;
    slot->tries = 0;
    memcpy(slot->to, d->via, 6);
    slot->prio = PriorityOf((Type)(data[1] >> 5));
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
    d.len = (uint8_t)f.len;
    memcpy(d.payload, f.payload, f.len);
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
      p.used = false;
      return;
    }
  }

  // The sync exchange. It has no replay window of its own: a frame of it is a copy or it is handled, and an answer
  // counts only for the exchange this node started, with its nonce
  Verdict OnSync(const Frame &f, const uint8_t *data, size_t n, int8_t rssi, uint32_t now, bool forMe) {
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
    Pass(f, data, n, rssi, now);
    return kAccepted;
  }
};

}  // namespace EspNowMesh

#endif  // _ESPNOW_MESH_CORE_H_
