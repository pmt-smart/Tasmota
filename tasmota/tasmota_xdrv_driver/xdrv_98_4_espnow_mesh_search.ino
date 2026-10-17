/*
  xdrv_98_4_espnow_mesh_search.ino - ESP-NOW mesh: a node that hears none of its nodes looks for them on the other channels

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
 * A node whose mesh channel is not the one its nodes are on hears none of them: the network moved to another channel while the
 * node was off, or the node was given a wrong one. Nothing would bring it back, since the only way to tell it is the channel it
 * does not hear.
 *
 * A node that has nodes in its table and has heard none of them by the radio for ESPNOW_MESH_SEARCH_QUIET_S, with no access point
 * associated, listens on every other channel in turn, ESPNOW_MESH_SEARCH_DWELL_MS on each, which is longer than the time between
 * two heartbeats, and counts the nodes of the network heard there: only a frame under the network's key counts, since the core
 * takes no other. The mesh's own channel is listened on last, and a node heard there ends the search with nothing changed: the nodes
 * came back, and what was heard on the other channels was their echo on the next ones, weaker, from close by. Otherwise the channel
 * where the most were heard, the strongest of two with as many, becomes the mesh's channel, saved as EspNowMeshChannel, and the radio
 * goes there. With none heard anywhere, the radio goes back to the mesh's channel, and the search comes again
 * ESPNOW_MESH_SEARCH_AGAIN_S later.
 *
 * Nothing happens on a device with no mesh channel or no node in its table, with the station associated, or while someone else
 * has the radio: the direct link, the WiFi Manager, a join, a pairing, a hotspot, a scan, the off-channel probe, or the station
 * of xdrv_98_3, which lets the search have the radio only while it is parked.
 *
 * Command:
 *   EspNowMeshSearch [1] - {"EspNowMeshSearch":{"State":"Idle"|"Listening","Quiet":<s>,"Channel":<n>,"Searches":<n>,"Moves":<n>,
 *                          "Found":<n>}}: Quiet is how long none of the nodes has been heard by the radio, Channel the one listened
 *                          on, Moves the searches that changed the mesh's channel, Found the channel the last one moved it to (0
 *                          none); 1 starts a search now
\*********************************************************************************************/

#define XDRV_103                          103

#ifndef ESPNOW_MESH_SEARCH_QUIET_S
#define ESPNOW_MESH_SEARCH_QUIET_S        60       // none of the nodes heard this long, and the node looks for them
#endif
#ifndef ESPNOW_MESH_SEARCH_DWELL_MS
#define ESPNOW_MESH_SEARCH_DWELL_MS       6500     // on each channel: a heartbeat comes every 5 to 5.5 s, and the task's snapshot is up to 0.5 s old
#endif
#ifndef ESPNOW_MESH_SEARCH_AGAIN_S
#define ESPNOW_MESH_SEARCH_AGAIN_S        600      // after a search that heard none of them
#endif
#define ESPNOW_MESH_SEARCH_CHANNELS       13

struct {
  bool listening = false;
  uint8_t channel = 0;                     // the one listened on
  uint8_t best = 0;                        // the channel where the most nodes were heard so far, and how many, and the strongest of them
  uint32_t best_count = 0;
  int8_t best_rssi = -128;
  uint32_t dwell_since = 0;
  uint32_t watch_since = 0;                // when the node was first seen in a state to search, 0 while it is not
  uint32_t again_at = 0;                   // no search before then
  bool forced = false;                     // a search asked by the command
  uint32_t searches = 0;
  uint32_t moves = 0;
  uint8_t found = 0;
} EspNowMeshSearch;

// The channel is the search's while it listens on another one
bool EspNowMeshSearchHolds(void) {
  return EspNowMeshSearch.listening;
}

// What the search needs: the mesh on a channel, nodes in the table, the radio not associated, and nobody else on it
static bool EspNowMeshSearchApplies(void) {
  if (!EspNowMeshDriver.running || !EspNowMeshSettings.channel || EspNowMeshDriver.direct_radio) { return false; }
  if (!EspNowMeshKnowsNodes()) { return false; }
  wifi_ap_record_t ap;
  if (ESP_OK == esp_wifi_sta_get_ap_info(&ap)) { return false; }
#ifdef USE_ESPNOW_MESH_PROBE
  if (EspNowProbeHoldsChannel()) { return false; }
#endif
#ifdef USE_WIFI_STATION_CONTROL
  if (STA_RADIO_FREE != StaCtrlRadioOwner()) { return false; }
#else
  if (Wifi.scan_state || (WIFI_SCAN_RUNNING == WiFi.scanComplete())) { return false; }
#endif
  return EspNowMeshStationLetsSearch();
}

static void EspNowMeshSearchListen(uint8_t channel) {
  EspNowMeshSearch.channel = channel;
  EspNowMeshSearch.dwell_since = millis();
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

// The channel to listen on after `channel` (0 to start): every channel but the mesh's, in order, and the mesh's last, which has the last
// word; 0 when the search is over
static uint8_t EspNowMeshSearchNext(uint8_t channel) {
  uint8_t mesh = EspNowMeshSettings.channel;
  if (channel == mesh) { return 0; }
  for (uint8_t c = channel + 1; c <= ESPNOW_MESH_SEARCH_CHANNELS; c++) {
    if (c != mesh) { return c; }
  }
  return mesh;
}

static void EspNowMeshSearchStart(uint32_t quiet_s) {
  EspNowMeshSearch.searches++;
  EspNowMeshSearch.listening = true;
  EspNowMeshSearch.forced = false;
  EspNowMeshSearch.best = 0;
  EspNowMeshSearch.best_count = 0;
  EspNowMeshSearch.best_rssi = -128;
  AddLog(LOG_LEVEL_INFO, PSTR("EMH: None of the nodes heard on channel %d for %u s: they are looked for on the others"),
    EspNowMeshSettings.channel, quiet_s);
  EspNowMeshSearchListen(EspNowMeshSearchNext(0));
}

// The search ends: the mesh's channel stays as it was when a node was heard on it in the end (the others heard elsewhere were the
// next channels' echo of them, or they came back), and is otherwise the one where the most nodes were heard; the radio goes to it
static void EspNowMeshSearchEnd(uint32_t home) {
  EspNowMeshSearch.listening = false;
  EspNowMeshSearch.watch_since = millis() ? millis() : 1;
  uint8_t was = EspNowMeshSettings.channel;
  if (home) {
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: %u nodes heard on the mesh's channel %d: it stays"), home, was);
  } else if (EspNowMeshSearch.best_count) {
    EspNowMeshSettings.channel = EspNowMeshSearch.best;
    EspNowMeshSearch.moves++;
    EspNowMeshSearch.found = EspNowMeshSearch.best;
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: %u nodes heard on channel %d and none on %d: the mesh's channel is %d now"),
      EspNowMeshSearch.best_count, EspNowMeshSearch.best, was, EspNowMeshSearch.best);
    if (!EspNowMeshSettingsCommit()) { AddLog(LOG_LEVEL_INFO, PSTR("EMH: The mesh's channel was not saved: flash write failed")); }
  } else {
    EspNowMeshSearch.again_at = millis() + ESPNOW_MESH_SEARCH_AGAIN_S * 1000;
    AddLog(LOG_LEVEL_INFO, PSTR("EMH: None of the nodes heard on any channel: the radio goes back to %d"), was);
  }
  esp_wifi_set_channel(EspNowMeshSettings.channel, WIFI_SECOND_CHAN_NONE);
}

static void EspNowMeshSearchEverySecond(void) {
  if (!EspNowMeshSearchApplies()) {
    if (EspNowMeshSearch.listening) {
      // someone else took the radio, or the node is no longer one to search: the search ends where it is, with what it heard
      EspNowMeshSearch.listening = false;
      AddLog(LOG_LEVEL_DEBUG, PSTR("EMH: The search for the nodes stops on channel %d"), EspNowMeshSearch.channel);
    }
    EspNowMeshSearch.watch_since = 0;
    return;
  }
  uint32_t count;
  int8_t rssi;
  uint32_t last;
  if (EspNowMeshSearch.listening) {
    if ((int32_t)(millis() - EspNowMeshSearch.dwell_since) < ESPNOW_MESH_SEARCH_DWELL_MS) { return; }
    EspNowMeshRadioHeard(EspNowMeshSearch.dwell_since, &count, &rssi, &last);
    if (EspNowMeshSearch.channel == EspNowMeshSettings.channel) {
      EspNowMeshSearchEnd(count);
      return;
    }
    if (count && ((count > EspNowMeshSearch.best_count) || ((count == EspNowMeshSearch.best_count) && (rssi > EspNowMeshSearch.best_rssi)))) {
      EspNowMeshSearch.best = EspNowMeshSearch.channel;
      EspNowMeshSearch.best_count = count;
      EspNowMeshSearch.best_rssi = rssi;
    }
    if (count) {
      AddLog(LOG_LEVEL_DEBUG, PSTR("EMH: %u nodes heard on channel %d, the strongest at %d dBm"), count, EspNowMeshSearch.channel, rssi);
    }
    EspNowMeshSearchListen(EspNowMeshSearchNext(EspNowMeshSearch.channel));
    return;
  }
  if (!EspNowMeshSearch.watch_since) { EspNowMeshSearch.watch_since = millis() ? millis() : 1; }
  if (!EspNowMeshRadioHeard(millis(), &count, &rssi, &last)) { return; }
  // quiet since the later of the last frame the radio heard and the moment the node could search
  uint32_t mark = EspNowMeshSearch.watch_since;
  if (last && ((int32_t)(last - mark) > 0)) { mark = last; }
  uint32_t quiet_ms = (uint32_t)(millis() - mark);
  bool quiet = (int32_t)quiet_ms >= (int32_t)(ESPNOW_MESH_SEARCH_QUIET_S * 1000);
  bool due = !EspNowMeshSearch.again_at || ((int32_t)(millis() - EspNowMeshSearch.again_at) >= 0);
  if (EspNowMeshSearch.forced || (quiet && due)) { EspNowMeshSearchStart(quiet_ms / 1000); }
}

void CmndEspNowMeshSearch(void) {
  if ((XdrvMailbox.data_len > 0) && (1 == XdrvMailbox.payload)) { EspNowMeshSearch.forced = true; }
  uint32_t count;
  int8_t rssi;
  uint32_t last = 0;
  EspNowMeshRadioHeard(millis(), &count, &rssi, &last);
  uint32_t mark = last ? last : EspNowMeshSearch.watch_since;
  uint32_t quiet = (mark && ((int32_t)(millis() - mark) > 0)) ? (millis() - mark) / 1000 : 0;
  Response_P(PSTR("{\"EspNowMeshSearch\":{\"State\":\"%s\",\"Quiet\":%u,\"Channel\":%u,\"Searches\":%u,\"Moves\":%u,\"Found\":%u}}"),
    EspNowMeshSearch.listening ? PSTR("Listening") : PSTR("Idle"), quiet,
    EspNowMeshSearch.listening ? EspNowMeshSearch.channel : EspNowMeshSettings.channel,
    EspNowMeshSearch.searches, EspNowMeshSearch.moves, EspNowMeshSearch.found);
}

const char kEspNowMeshSearchCommands[] PROGMEM = "|EspNowMeshSearch";
void (* const kEspNowMeshSearchCommand[])(void) PROGMEM = { &CmndEspNowMeshSearch };

bool Xdrv103(uint32_t function) {
  bool result = false;
  switch (function) {
    case FUNC_EVERY_SECOND:
      EspNowMeshSearchEverySecond();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowMeshSearchCommands, kEspNowMeshSearchCommand);
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_MESH
