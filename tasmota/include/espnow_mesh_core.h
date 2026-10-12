/*
  espnow_mesh_core.h - ESP-NOW mesh: frame format, duplicate suppression, replay window and flooding

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
 * frames a node has already seen or must refuse, and which of the ones it hears it repeats
 * and when. It needs no operating system and no radio library, and keeps all its state in
 * fixed arrays, so the same code runs in the firmware's radio task and in a host test with
 * many nodes over a simulated air.
 *
 * A frame, 14 bytes of header, the payload, and a tag of 8 bytes (ESP-NOW allows 250):
 *
 *   version(1) kind(1) origin(1) dest(1) next(1) hops(1) epoch(4) counter(4) payload tag(8)
 *
 *   kind     type(3 bits) | ack requested(1) | part(2: whole, first, second) | attempt(2)
 *   origin   the number of the node that created the frame
 *   dest     the number of the node it is for, or 255 for all of them
 *   next     the next hop of a routed frame; 0 in a flooded one
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
 * Replay: a node keeps, for each origin, the highest epoch and counter accepted and a window
 * of 32 counters behind it, one bit each. A counter already seen, one behind the window and
 * an epoch below the kept one are refused. An origin starts unsynchronised: nothing it sends
 * is accepted until the user of this file says it knows where the origin is (`SetSynced`),
 * which it learns from an exchange of its own, and an epoch above the kept one makes the
 * origin unsynchronised again, because a start of the origin is the moment a recorded frame
 * of one of its earlier epochs could be played back. A frame that repeats a number with a
 * higher attempt is a retransmission: it is repeated, and delivered as one, so that the
 * destination can answer it again, and the application executes it once.
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

constexpr unsigned kMaxOrigins = 16;         // the origins a node keeps a window for
constexpr unsigned kSeenSize = 64;           // the numbers a node remembers hearing
constexpr unsigned kTxQueue = 16;            // the frames waiting to be sent
constexpr unsigned kInboxSize = 8;           // the frames waiting for the application

// What a frame is for: a command and its acknowledgement, a state report, an event, a heartbeat for the neighbours,
// a payload too big for one frame, the management of the mesh's membership and keys, and the exchange that tells a
// node where another one is in its epoch and counter
enum Type : uint8_t { kCommand = 0, kAck = 1, kState = 2, kEvent = 3, kBeat = 4, kBulk = 5, kMembership = 6, kSync = 7 };

// What the user of this file computes: the tag of `len` bytes, with the key it holds
typedef void (*TagFunction)(const uint8_t *data, size_t len, uint8_t tag[kTagLen], void *context);

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

struct Stats {
  uint32_t heard, bad, repeated, replayed, stale, unsynced, delivered, inboxFull;
  uint32_t sentOwn, sentRelay, suppressed, queueFull;
};

struct Config {
  uint8_t id;                                  // this node's number
  uint32_t epoch;                              // this node's epoch, already raised for this start
  uint32_t (*random)(void *);                  // a random number
  void *context;
  TagFunction tag;                             // nullptr: tags are not computed and not checked
  void *tagContext;
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
    counter_ = 0;
  }

  // The application hands over a frame for `dest` (kToAll for everyone). Returns its counter, or 0
  uint32_t Send(Type type, uint8_t dest, const uint8_t *payload, size_t len, bool ackRequested, uint32_t now) {
    if (len > kMaxPayload) return 0;
    Frame f;
    f.kind = PackKind(type, ackRequested, 0, 0);
    f.origin = cfg_.id;
    f.dest = dest;
    f.next = 0;
    f.hops = type == kBeat ? 0 : kMaxHops;     // a heartbeat is for the neighbours that hear it: it is not repeated
    f.epoch = cfg_.epoch;
    f.counter = ++counter_;
    f.payload = payload;
    f.len = len;
    TxItem *slot = FreeSlot();
    if (slot == nullptr) { stats_.queueFull++; counter_--; return 0; }
    slot->len = (uint8_t)Encode(f, slot->data);
    if (cfg_.tag != nullptr) Seal(cfg_.tag, cfg_.tagContext, slot->data, slot->len);
    slot->used = true;
    slot->own = true;
    slot->prio = PriorityOf(type);
    slot->heard = 1;
    slot->due = now;
    // own frames are remembered as heard, so that a neighbour's repetition of one is a duplicate
    Remember(f.origin, f.epoch, f.counter, f.attempt(), nullptr, 0, now);
    return f.counter;
  }

  // The radio heard `n` bytes from the neighbour `src`, with the signal `rssi`
  Verdict OnReceive(const uint8_t *data, size_t n, const uint8_t src[6], int8_t rssi, uint32_t now) {
    Frame f;
    if (!Decode(data, n, &f)) { stats_.bad++; return kBad; }
    if (cfg_.tag != nullptr && !TagMatches(cfg_.tag, cfg_.tagContext, data, n)) { stats_.bad++; return kBad; }
    if (f.origin == cfg_.id || f.origin == 0 || f.origin == kToAll) return kIgnored;
    stats_.heard++;
    bool forMe = f.dest == cfg_.id || f.dest == kToAll;
    bool known = false;                        // this number has been delivered before
    Origin *o = FindOrigin(f.origin, true);
    if (o == nullptr) { stats_.unsynced++; return kNeedsSync; }
    if (!o->synced) { stats_.unsynced++; wantSync_ = f.origin; return kNeedsSync; }
    if (f.epoch < o->epoch) { stats_.stale++; return kStale; }
    if (f.epoch > o->epoch) { o->synced = false; stats_.unsynced++; wantSync_ = f.origin; return kNeedsSync; }
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
    // heard already, this very frame, attempt included: a copy of what is in hand
    if (SeenBefore(f.origin, f.epoch, f.counter, f.attempt())) {
      stats_.repeated++;
      CountCopy(f.origin, f.epoch, f.counter, f.attempt());
      return kRepeated;
    }
    Remember(f.origin, f.epoch, f.counter, f.attempt(), src, rssi, now);
    if (known && !(f.attempt() > 0)) { stats_.replayed++; return kReplayed; }
    if (forMe) Deliver(f, src, rssi, known);
    // flooded and with hops left: repeat it, unless it was for this node alone
    if (f.hops > 0 && !f.routed() && f.dest != cfg_.id) Schedule(data, n, rssi, now);
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
    if (wantSync_ == origin) wantSync_ = 0;
  }

  // An origin that sent something this node could not accept for want of a sync, or 0
  uint8_t WantsSync() const { return wantSync_; }

  // The radio is free: the frame to send next, and whether there is one. Serialised: nothing
  // more comes until the radio says what became of the last
  bool NextTx(uint32_t now, uint8_t *out, size_t *len) {
    if (busy_) return false;
    TxItem *best = nullptr;
    for (unsigned i = 0; i < kTxQueue; i++) {
      TxItem &t = txq_[i];
      if (!t.used || (int32_t)(now - t.due) < 0) continue;
      if (best == nullptr || t.prio < best->prio || (t.prio == best->prio && (int32_t)(t.due - best->due) < 0)) best = &t;
    }
    if (best == nullptr) return false;
    memcpy(out, best->data, best->len);
    *len = best->len;
    if (best->own) stats_.sentOwn++; else stats_.sentRelay++;
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

  bool Busy() const { return busy_; }
  void TxDone() { busy_ = false; }

  bool PopDelivery(Delivery *d) {
    if (inboxCount_ == 0) return false;
    *d = inbox_[inboxHead_];
    inboxHead_ = (inboxHead_ + 1) % kInboxSize;
    inboxCount_--;
    return true;
  }

  const Stats &stats() const { return stats_; }
  uint8_t id() const { return cfg_.id; }
  uint32_t epoch() const { return cfg_.epoch; }
  unsigned queued() const { unsigned n = 0; for (unsigned i = 0; i < kTxQueue; i++) n += txq_[i].used; return n; }

  // Where the first copy of a number came from, which is the way back to its origin
  bool ReturnPath(uint8_t origin, uint32_t epoch, uint32_t counter, uint8_t from[6]) const {
    for (unsigned i = 0; i < kSeenSize; i++) {
      const Seen &s = seen_[i];
      if (s.used && s.origin == origin && s.epoch == epoch && s.counter == counter && s.hasFrom) {
        memcpy(from, s.from, 6);
        return true;
      }
    }
    return false;
  }

 private:
  struct Origin { bool used; bool synced; uint8_t id; uint32_t epoch; uint32_t highest; uint32_t seen; };
  struct Seen { bool used; bool hasFrom; uint8_t origin; uint8_t attempt; uint32_t epoch; uint32_t counter; uint8_t from[6]; };
  struct TxItem { bool used; bool own; uint8_t len; uint8_t prio; uint8_t heard; uint32_t due; uint8_t data[kMaxFrame]; };

  Config cfg_;
  uint32_t counter_;
  uint8_t wantSync_;
  bool busy_;
  Origin origins_[kMaxOrigins];
  Seen seen_[kSeenSize];
  unsigned seenNext_;
  TxItem txq_[kTxQueue];
  Delivery inbox_[kInboxSize];
  unsigned inboxHead_, inboxCount_;
  Stats stats_;

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

  bool SeenBefore(uint8_t origin, uint32_t epoch, uint32_t counter, uint8_t attempt) const {
    for (unsigned i = 0; i < kSeenSize; i++) {
      const Seen &s = seen_[i];
      if (s.used && s.origin == origin && s.epoch == epoch && s.counter == counter && s.attempt == attempt) return true;
    }
    return false;
  }

  void Remember(uint8_t origin, uint32_t epoch, uint32_t counter, uint8_t attempt, const uint8_t *from, int8_t rssi, uint32_t now) {
    (void)rssi; (void)now;
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
      if (!t.used || t.own) continue;
      if (t.data[2] != origin || Get32(t.data + 6) != epoch || Get32(t.data + 10) != counter || (t.data[1] & 3) != attempt) continue;
      if (t.heard < 255) t.heard++;
      if (t.heard >= cfg_.suppressAt) { t.used = false; stats_.suppressed++; }
      return;
    }
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
    slot->prio = PriorityOf((Type)(data[1] >> 5));
    slot->heard = 1;
    uint32_t r = cfg_.random != nullptr ? cfg_.random(cfg_.context) : 0;
    slot->due = now + (rssi < cfg_.weakDbm ? r % 4 : 3 + r % 6);
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
};

}  // namespace EspNowMesh

#endif  // _ESPNOW_MESH_CORE_H_
