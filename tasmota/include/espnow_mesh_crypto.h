/*
  espnow_mesh_crypto.h - ESP-NOW mesh: the keys and the cipher the mesh core asks for, on BearSSL

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

#ifndef _ESPNOW_MESH_CRYPTO_H_
#define _ESPNOW_MESH_CRYPTO_H_

/*********************************************************************************************\
 * The functions espnow_mesh_core.h takes from its user, on the BearSSL that Tasmota carries and
 * that a host can compile on its own:
 *
 *   identity   a node has an X25519 key pair of its own, made once
 *   pair key   between two nodes: X25519 of the one's secret and the other's public key, through
 *              HKDF-SHA256 with the two public keys, the lower first, as its salt; an AES-128 key
 *              for the payload and a 32-byte key for the proofs. Cached, at most one per node
 *   group key  of the whole network, 32 bytes with a version number, through HKDF into an AES-128
 *              key for the payload and an HMAC key for the tag of a frame
 *   Tag        HMAC-SHA256 under the network's key, the first 8 bytes: what every node that
 *              repeats a frame checks, and that nobody outside the network can make
 *   Seal       a frame for one node alone: AES-128-CCM, a nonce of 9 bytes (the origin, the epoch
 *              and the counter of the frame), the header as the associated data, 8 bytes of tag;
 *              a frame for everyone: AES-128-CTR under the network's key and the same nonce, and
 *              no tag, for the tag of the frame covers it
 *   Proof      HMAC-SHA256 under the key of the pair, of the nonce, the epoch and the counter
 *
 * It keeps nothing of the radio, and writes nothing to flash: where the secret and the group key
 * are kept is the business of the code that owns the node.
\*********************************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "espnow_mesh_core.h"
#include <t_bearssl.h>

namespace EspNowMesh {

constexpr unsigned kCryptoPeers = 16;        // the nodes a node keeps a pair key for

class Crypto {
 public:
  // Wipes key material in a way the compiler does not drop as a dead store
  static void Wipe(void *buffer, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (len--) *p++ = 0;
  }

  // The identity, from a 32-byte secret (X25519, clamped by the curve function itself). False if no public key comes of it
  bool Begin(const uint8_t secret[32]) {
    memset(this, 0, sizeof(*this));
    memcpy(secret_, secret, 32);
    static const uint8_t base[32] = {9};
    return X25519(pub_, secret_, base);
  }

  const uint8_t *PublicKey() const { return pub_; }

  // The key of the whole network, 32 bytes, and its version
  void SetGroupKey(const uint8_t key[32], uint8_t version) {
    static const char salt[] = "mesh group";
    uint8_t mac[32];
    Hkdf((const uint8_t *)salt, sizeof(salt) - 1, key, 32, (const uint8_t *)"enc", 3, groupEnc_, sizeof(groupEnc_));
    Hkdf((const uint8_t *)salt, sizeof(salt) - 1, key, 32, (const uint8_t *)"mac", 3, mac, sizeof(mac));
    br_hmac_key_init(&groupMac_, &br_sha256_vtable, mac, sizeof(mac));
    Wipe(mac, sizeof(mac));
    groupVersion_ = version;
    hasGroup_ = true;
  }

  uint8_t GroupVersion() const { return hasGroup_ ? groupVersion_ : 0; }
  bool HasGroupKey() const { return hasGroup_; }

  // The node `node`, whose public key is `pub`: the keys of the pair are derived and kept. False for a key of small order, or
  // when there is no room for another node
  bool SetPeer(uint8_t node, const uint8_t pub[32]) {
    Peer *p = nullptr, *free_slot = nullptr;
    for (unsigned i = 0; i < kCryptoPeers; i++) {
      if (peers_[i].used && peers_[i].node == node) p = &peers_[i];
      if (!peers_[i].used && free_slot == nullptr) free_slot = &peers_[i];
    }
    if (p == nullptr) p = free_slot;
    if (p == nullptr) return false;
    uint8_t shared[32], salt[64];
    if (!X25519(shared, secret_, pub)) return false;
    bool lower = memcmp(pub_, pub, 32) < 0;
    memcpy(salt, lower ? pub_ : pub, 32);
    memcpy(salt + 32, lower ? pub : pub_, 32);
    Peer fresh;
    memset(&fresh, 0, sizeof(fresh));
    Hkdf(salt, sizeof(salt), shared, sizeof(shared), (const uint8_t *)"pair enc", 8, fresh.enc, sizeof(fresh.enc));
    Hkdf(salt, sizeof(salt), shared, sizeof(shared), (const uint8_t *)"pair proof", 10, fresh.proof, sizeof(fresh.proof));
    Wipe(shared, sizeof(shared));
    fresh.used = true;
    fresh.node = node;
    *p = fresh;
    Wipe(&fresh, sizeof(fresh));
    return true;
  }

  void ForgetPeer(uint8_t node) {
    for (unsigned i = 0; i < kCryptoPeers; i++) if (peers_[i].used && peers_[i].node == node) memset(&peers_[i], 0, sizeof(peers_[i]));
  }

  bool HasPeer(uint8_t node) const { return FindPeer(node) != nullptr; }

  // --- the hooks of the core: `context` is the Crypto -------------------------------------------

  static void Tag(const uint8_t *data, size_t len, uint8_t tag[kTagLen], void *context) {
    Crypto *c = (Crypto *)context;
    if (!c->hasGroup_) { memset(tag, 0, kTagLen); return; }
    br_hmac_context hc;
    br_hmac_init(&hc, &c->groupMac_, kTagLen);
    br_hmac_update(&hc, data, len);
    br_hmac_out(&hc, tag);
  }

  static void Proof(void *context, uint8_t peer, uint32_t nonce, uint32_t epoch, uint32_t counter, uint8_t proof[8]) {
    Crypto *c = (Crypto *)context;
    const Peer *p = c->FindPeer(peer);
    if (p == nullptr) { memset(proof, 0, 8); return; }
    uint8_t words[12];
    Put32(words, nonce);
    Put32(words + 4, epoch);
    Put32(words + 8, counter);
    uint8_t mac[32];
    Hmac(p->proof, sizeof(p->proof), words, sizeof(words), mac);
    memcpy(proof, mac, 8);
  }

  static size_t Seal(void *context, uint8_t peer, const uint8_t header[kHeaderLen], const uint8_t *in, size_t len, uint8_t *out) {
    Crypto *c = (Crypto *)context;
    uint8_t nonce[9];
    NonceOf(header, nonce);
    if (peer == 0) {
      if (!c->hasGroup_) return 0;
      memcpy(out, in, len);
      Ctr(c->groupEnc_, nonce, out, len);
      return len;
    }
    const Peer *p = c->FindPeer(peer);
    if (p == nullptr) return 0;
    memcpy(out, in, len);
    if (!CcmSeal(p->enc, nonce, sizeof(nonce), header, kHeaderLen, out, len, out + len, kPairTagLen)) return 0;
    return len + kPairTagLen;
  }

  static int Open(void *context, uint8_t peer, const uint8_t header[kHeaderLen], const uint8_t *in, size_t len, uint8_t *out) {
    Crypto *c = (Crypto *)context;
    uint8_t nonce[9];
    NonceOf(header, nonce);
    if (peer == 0) {
      if (!c->hasGroup_) return -1;
      memcpy(out, in, len);
      Ctr(c->groupEnc_, nonce, out, len);
      return (int)len;
    }
    const Peer *p = c->FindPeer(peer);
    if (p == nullptr || len < kPairTagLen) return -1;
    size_t n = len - kPairTagLen;
    memcpy(out, in, n);
    if (!CcmOpen(p->enc, nonce, sizeof(nonce), header, kHeaderLen, out, n, in + n, kPairTagLen)) return -1;
    return (int)n;
  }

  // --- the primitives, on BearSSL --------------------------------------------------------------

  // X25519 (RFC 7748). BearSSL reads the scalar big-endian, where the RFC's is little-endian, so the secret goes in reversed; points
  // are little-endian in both. An all-zero result comes from a point of small order and gives no key
  static bool X25519(uint8_t out[32], const uint8_t secret[32], const uint8_t point[32]) {
    uint8_t scalar[32];
    for (unsigned i = 0; i < 32; i++) scalar[i] = secret[31 - i];
    memcpy(out, point, 32);
    uint32_t ok = br_ec_c25519_m15.mul(out, 32, scalar, 32, BR_EC_curve25519);
    Wipe(scalar, sizeof(scalar));
    uint8_t any = 0;
    for (unsigned i = 0; i < 32; i++) any |= out[i];
    return ok && any;
  }

  static void Hmac(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t out[32]) {
    br_hmac_key_context kc;
    br_hmac_context hc;
    br_hmac_key_init(&kc, &br_sha256_vtable, key, keyLen);
    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, data, len);
    br_hmac_out(&hc, out);
  }

  // HKDF-SHA256 (RFC 5869): the `outLen` bytes of output for `info`, from the input key material and the salt
  static void Hkdf(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen, const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen) {
    br_hkdf_context hc;
    br_hkdf_init(&hc, &br_sha256_vtable, salt, saltLen);
    br_hkdf_inject(&hc, ikm, ikmLen);
    br_hkdf_flip(&hc);
    br_hkdf_produce(&hc, info, infoLen, out, outLen);
  }

  // AES-128-CCM (RFC 3610), in place: `data` becomes the ciphertext, and the tag of `tagLen` bytes is written to `tag`
  static bool CcmSeal(const uint8_t key[16], const uint8_t *nonce, size_t nonceLen, const uint8_t *aad, size_t aadLen, uint8_t *data, size_t len, uint8_t *tag, size_t tagLen) {
    br_aes_ct_ctrcbc_keys bc;
    br_ccm_context ctx;
    br_aes_ct_ctrcbc_init(&bc, key, 16);
    br_ccm_init(&ctx, &bc.vtable);
    if (!br_ccm_reset(&ctx, nonce, nonceLen, aadLen, len, tagLen)) return false;
    br_ccm_aad_inject(&ctx, aad, aadLen);
    br_ccm_flip(&ctx);
    br_ccm_run(&ctx, 1, data, len);
    br_ccm_get_tag(&ctx, tag);
    Wipe(&bc, sizeof(bc));
    return true;
  }

  // The opposite, in place: false, and the data not to be used, when the tag does not match
  static bool CcmOpen(const uint8_t key[16], const uint8_t *nonce, size_t nonceLen, const uint8_t *aad, size_t aadLen, uint8_t *data, size_t len, const uint8_t *tag, size_t tagLen) {
    br_aes_ct_ctrcbc_keys bc;
    br_ccm_context ctx;
    br_aes_ct_ctrcbc_init(&bc, key, 16);
    br_ccm_init(&ctx, &bc.vtable);
    if (!br_ccm_reset(&ctx, nonce, nonceLen, aadLen, len, tagLen)) return false;
    br_ccm_aad_inject(&ctx, aad, aadLen);
    br_ccm_flip(&ctx);
    br_ccm_run(&ctx, 0, data, len);
    bool ok = br_ccm_check_tag(&ctx, tag) != 0;
    Wipe(&bc, sizeof(bc));
    return ok;
  }

  // AES-128-CTR, in place, with a 9-byte nonce: the block counter starts at 0
  static void Ctr(const uint8_t key[16], const uint8_t nonce[9], uint8_t *data, size_t len) {
    br_aes_ct_ctr_keys k;
    uint8_t iv[12];
    br_aes_ct_ctr_init(&k, key, 16);
    memcpy(iv, nonce, 9);
    memset(iv + 9, 0, 3);
    br_aes_ct_ctr_run(&k, iv, 0, data, len);
    Wipe(&k, sizeof(k));
  }

 private:
  struct Peer { bool used; uint8_t node; uint8_t enc[16]; uint8_t proof[32]; };

  uint8_t secret_[32];
  uint8_t pub_[32];
  bool hasGroup_;
  uint8_t groupVersion_;
  uint8_t groupEnc_[16];
  br_hmac_key_context groupMac_;
  Peer peers_[kCryptoPeers];

  const Peer *FindPeer(uint8_t node) const {
    for (unsigned i = 0; i < kCryptoPeers; i++) if (peers_[i].used && peers_[i].node == node) return &peers_[i];
    return nullptr;
  }

  // The nonce of a frame: its origin, epoch and counter, which is a number that no frame of the network shares
  static void NonceOf(const uint8_t header[kHeaderLen], uint8_t nonce[9]) {
    nonce[0] = header[2];
    memcpy(nonce + 1, header + 6, 8);
  }
};

}  // namespace EspNowMesh

#endif  // _ESPNOW_MESH_CRYPTO_H_
