/*
  xdrv_98_3_espnow_mesh_station.ino - ESP-NOW mesh: a node's WiFi station keeps to the mesh's channel, and looks for its network there

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
 * A station whose saved network is out of reach looks for it all the time: the WiFi stack connects again at every
 * failure, and Tasmota starts the connection over every 20 to 35 seconds (WifiCheckIp), with the radio stopped and
 * started on the way (WifiBegin), and restarts the device after its hundredth round. Each attempt scans every channel,
 * and an ESP-NOW mesh that lives on one channel loses the node: a ZBBridge Pro with a network that does not exist spent
 * 95% of ten minutes off the mesh's channel.
 *
 * With the mesh running on a channel of its own setting, this driver takes the retries of such a node over:
 * - after ESPNOW_MESH_STATION_GRACE_S with no connection, or as soon as the stack says it did not find the network, the
 *   station stops trying (the stack's retries off, Tasmota's held through EspNowMeshStationQuiet, and no restart) and the
 *   radio goes to the mesh's channel;
 * - it looks for the network with a scan of the mesh's channel, active, of ESPNOW_MESH_STATION_PROBE_MS, which does not take
 *   the radio off it. The scans come 10, 30 and then every 60 s after the park, plus a delay of the node's own, from its MAC,
 *   of up to ESPNOW_MESH_STATION_SPREAD_S;
 * - a scan that finds one of the saved networks joins it on that channel and that access point, and a join that connects
 *   hands the station to Tasmota, connected;
 * - every ESPNOW_MESH_STATION_WIDE_S the scan is of every channel, for an access point that moved to another channel. The
 *   first one comes at a time of the node's own after the park, from its MAC, between 60 s and ESPNOW_MESH_STATION_WIDE_S:
 *   the nodes that lost the network together do not leave the mesh's channel together.
 * A join ends after ESPNOW_MESH_STATION_TRY_S with the station not associated, at the ESPNOW_MESH_STATION_TRY_FAILS-th
 * failure the stack reports, or after ESPNOW_MESH_STATION_ASSOC_S associated with no address.
 *
 * The mesh's channel is the one the station may be on, once the node has other nodes of the mesh in its table: a station
 * associated with an access point on another channel takes the radio, and the node, off the mesh, which is worse than no
 * network. Such a station leaves the access point and parks, whoever joined it (Tasmota at boot, the stack's own retries,
 * a join), and a scan joins only an access point on the mesh's channel. The strongest access point of a saved network seen
 * on another channel is kept (OffChannel, OffBssid) for the application to report, until the station connects or a scan of
 * every channel no longer sees one. A node alone, with no other node in its table, joins its network on any channel: there
 * is no mesh to keep to.
 *
 * Nothing changes for a device without the mesh running, without a mesh channel, with no network saved, or with Tasmota's
 * WiFi off. Nor while someone else has the radio: the WiFi Manager, a join, a pairing, a hotspot, a scan, the direct link,
 * the mesh's off-channel probe, the mesh's search for its nodes on the other channels (xdrv_98_4). When one of them takes
 * it, or the mesh stops, Tasmota gets its retries back at once. Tasmota's WiFi setting is never changed, so a power cut in
 * the middle leaves nothing behind.
 *
 * Command:
 *   EspNowMeshStation - {"EspNowMeshStation":{"State":"Watch"|"Parked"|"Probing"|"Joining"|"Wide","Down":<s>,"Next":<s>,
 *                        "Channel":<n>,"Ap":<n>,"Probes":<n>,"Seen":<n>,"Wides":<n>,"Found":<n>,"Parks":<n>,"Reason":<n>,
 *                        "OffChannel":<n>,"OffBssid":"<mac>","Offs":<n>}}: Down is how long the station has been down (0 while
 *                        up), Next the seconds to the next scan, Channel the mesh's, which the station keeps to, Ap the channel
 *                        of the access point the station is associated with (0 none), Seen the scans that saw the network,
 *                        Wides the scans of every channel, Found the joins that connected, Reason the last failure the stack
 *                        reported, OffChannel and OffBssid the access point of a saved network seen off the mesh's channel (0
 *                        and "" none), and Offs how many times the station left one
\*********************************************************************************************/

#define XDRV_102                          102

#ifndef ESPNOW_MESH_STATION_GRACE_S
#define ESPNOW_MESH_STATION_GRACE_S       10       // a station down this long stops trying on its own
#endif
#ifndef ESPNOW_MESH_STATION_PROBE_MS
#define ESPNOW_MESH_STATION_PROBE_MS      120      // a scan's time on each channel
#endif
#ifndef ESPNOW_MESH_STATION_SPREAD_S
#define ESPNOW_MESH_STATION_SPREAD_S      5        // a node's own delay, 0 to this, from its MAC
#endif
#ifndef ESPNOW_MESH_STATION_WIDE_S
#define ESPNOW_MESH_STATION_WIDE_S        600      // a scan of every channel this often while parked
#endif
#define ESPNOW_MESH_STATION_WIDE_MIN_S    60       // and the first one no sooner than this after the park
#define ESPNOW_MESH_STATION_TRY_S         15       // a join with the station not associated by then ends
#define ESPNOW_MESH_STATION_ASSOC_S       30       // and associated with no address by then
#define ESPNOW_MESH_STATION_TRY_FAILS     2        // a join ends at this failure the stack reports
#define ESPNOW_MESH_STATION_SCAN_MAX_MS   3000     // a scan of one channel with no result by then failed
#define ESPNOW_MESH_STATION_WIDE_MAX_MS   6000     // and of every channel

static const uint8_t EspNowMeshStationWaits[] = { 10, 30, 60 };   // seconds between the scans; the last one repeats

enum EspNowMeshStationStates {
  ESPNOW_MESH_STATION_WATCH, ESPNOW_MESH_STATION_PARKED, ESPNOW_MESH_STATION_PROBING, ESPNOW_MESH_STATION_JOINING, ESPNOW_MESH_STATION_WIDE
};

struct {
  uint8_t state = ESPNOW_MESH_STATION_WATCH;
  uint8_t step = 0;                        // into EspNowMeshStationWaits
  uint8_t off_channel = 0;                 // the channel of a saved network's access point seen off the mesh's channel, 0 none
  uint8_t off_bssid[6] = { 0 };            // and that access point
  uint32_t down_since = 0;                 // when the station was first seen down, 0 while it is up
  uint32_t next_try = 0;
  uint32_t try_since = 0;
  uint32_t wide_at = 0;                    // when the next scan of every channel is due
  uint32_t probes = 0;
  uint32_t seen = 0;                       // the scans that saw a saved network the station may join
  uint32_t wides = 0;
  uint32_t found = 0;                      // the joins that connected
  uint32_t parks = 0;
  uint32_t offs = 0;                       // the access points left for being off the mesh's channel
  volatile uint32_t fails = 0;             // the failures the stack reported during a join
  volatile uint8_t reason = 0;             // the last one
  volatile bool not_found = false;         // the stack did not find the network since the station was last up
} EspNowMeshStation;

// The milliseconds since a mark of millis(), 0 for a mark not reached yet
static uint32_t EspNowMeshStationSince(uint32_t mark) {
  int32_t since = (int32_t)(millis() - mark);
  return (since > 0) ? (uint32_t)since : 0;
}

// Run on the network event task: it only counts
void EspNowMeshStationEvent(arduino_event_t *event);
void EspNowMeshStationEvent(arduino_event_t *event) {
  if (ARDUINO_EVENT_WIFI_STA_DISCONNECTED != event->event_id) { return; }
  uint8_t reason = event->event_info.wifi_sta_disconnected.reason;
  if (WIFI_REASON_ASSOC_LEAVE == reason) { return; }       // this side left: a park, or the stack starting over
  EspNowMeshStation.reason = reason;
  EspNowMeshStation.fails = EspNowMeshStation.fails + 1;
  if (WIFI_REASON_NO_AP_FOUND == reason) { EspNowMeshStation.not_found = true; }
}

// Tasmota's own retries are held while this driver has them (WifiCheckIp)
bool EspNowMeshStationQuiet(void) {
  return (ESPNOW_MESH_STATION_WATCH != EspNowMeshStation.state);
}

// What this driver needs: the mesh on a channel, Tasmota's WiFi on with a network saved, and no one else on the radio's channel
static bool EspNowMeshStationApplies(void) {
  if (!EspNowMeshDriver.running || !EspNowMeshSettings.channel || EspNowMeshDriver.direct_radio) { return false; }
  if (!Settings->flag4.network_wifi || Wifi.config_type) { return false; }
  if (!strlen(SettingsText(SET_STASSID1)) && !strlen(SettingsText(SET_STASSID2))) { return false; }
#ifdef USE_ESPNOW_MESH_PROBE
  if (EspNowProbeHoldsChannel()) { return false; }
#endif
  return true;
}

// The mesh's search for its nodes may take the radio: the station is not in the way, parked or with nothing to do
bool EspNowMeshStationLetsSearch(void) {
  return !EspNowMeshStationApplies() || (ESPNOW_MESH_STATION_PARKED == EspNowMeshStation.state);
}

// Whether the station may be on an access point on this channel: the mesh's, or any for a node alone
static bool EspNowMeshStationJoinable(uint8_t channel) {
  return (channel == EspNowMeshSettings.channel) || !EspNowMeshKnowsNodes();
}

// A join, a pairing, a hotspot or a scan has the radio: a parked station leaves the radio alone and waits
static bool EspNowMeshStationRadioFree(void) {
#ifdef USE_WIFI_STATION_CONTROL
  return (STA_RADIO_FREE == StaCtrlRadioOwner());
#else
  return !Wifi.scan_state && (WIFI_SCAN_RUNNING != WiFi.scanComplete());
#endif
}

static void EspNowMeshStationChannel(void) {
  if (EspNowMeshSearchHolds()) { return; }
  uint8_t channel = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  esp_wifi_get_channel(&channel, &second);
  if (channel == EspNowMeshSettings.channel) { return; }
  wifi_ap_record_t ap;
  if (ESP_OK == esp_wifi_sta_get_ap_info(&ap)) { return; }
  if (ESP_OK == esp_wifi_set_channel(EspNowMeshSettings.channel, WIFI_SECOND_CHAN_NONE)) {
    AddLog(LOG_LEVEL_DEBUG, PSTR("EMS: Radio from channel %d to the mesh's, %d"), channel, EspNowMeshSettings.channel);
  }
}

// The seconds from a park to the first scan of every channel: the node's own, from its MAC
static uint32_t EspNowMeshStationWideFirst(void) {
  if (ESPNOW_MESH_STATION_WIDE_S <= ESPNOW_MESH_STATION_WIDE_MIN_S) { return ESPNOW_MESH_STATION_WIDE_S; }
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  return ESPNOW_MESH_STATION_WIDE_MIN_S + ((mac[4] << 8) | mac[5]) % (ESPNOW_MESH_STATION_WIDE_S - ESPNOW_MESH_STATION_WIDE_MIN_S + 1);
}

// The station stops trying, the radio goes to the mesh's channel, and the next scan is set
static void EspNowMeshStationPark(void) {
  WiFi.setAutoReconnect(false);
  // A connection under way, Tasmota's or a join, is ended; the radio stays on. A scan leaves nothing to end
  uint8_t state = EspNowMeshStation.state;
  if ((ESPNOW_MESH_STATION_PROBING != state) && (ESPNOW_MESH_STATION_PARKED != state) && (ESPNOW_MESH_STATION_WIDE != state)) {
    WiFi.disconnect();
  }
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  uint32_t wait_s = EspNowMeshStationWaits[EspNowMeshStation.step] + mac[5] % (ESPNOW_MESH_STATION_SPREAD_S + 1);
  if (EspNowMeshStation.step < sizeof(EspNowMeshStationWaits) - 1) { EspNowMeshStation.step++; }
  EspNowMeshStation.next_try = millis() + wait_s * 1000;
  if (ESPNOW_MESH_STATION_WATCH == state) {
    EspNowMeshStation.parks++;
    EspNowMeshStation.wide_at = millis() + EspNowMeshStationWideFirst() * 1000;
  }
  EspNowMeshStation.state = ESPNOW_MESH_STATION_PARKED;
  EspNowMeshStation.not_found = false;
  EspNowMeshStationChannel();
}

// The station is on an access point off the mesh's channel and leaves it, which is kept as the one off the channel. Declared before
// its definition, as its signature names a type of the ESP-IDF (see xdrv_98_1)
static void EspNowMeshStationLeaveAp(const wifi_ap_record_t* ap);
static void EspNowMeshStationLeaveAp(const wifi_ap_record_t* ap) {
  EspNowMeshStation.off_channel = ap->primary;
  memcpy(EspNowMeshStation.off_bssid, ap->bssid, 6);
  EspNowMeshStation.offs++;
  if (!EspNowMeshStation.down_since) { EspNowMeshStation.down_since = millis() ? millis() : 1; }
  AddLog(LOG_LEVEL_INFO, PSTR("EMS: The access point %02X:%02X:%02X:%02X:%02X:%02X is on channel %d, not the mesh's %d: the station leaves it"),
    ap->bssid[0], ap->bssid[1], ap->bssid[2], ap->bssid[3], ap->bssid[4], ap->bssid[5], ap->primary, EspNowMeshSettings.channel);
  EspNowMeshStationPark();
}

// A scan of the mesh's channel, or of every channel
static void EspNowMeshStationScan(bool wide) {
  int16_t started = WiFi.scanNetworks(true, false, false, ESPNOW_MESH_STATION_PROBE_MS, wide ? 0 : EspNowMeshSettings.channel);
  if (WIFI_SCAN_RUNNING != started) {
    EspNowMeshStationPark();               // the stack refused it: the next one, later
    return;
  }
  if (wide) {
    EspNowMeshStation.wides++;
    EspNowMeshStation.wide_at = millis() + ESPNOW_MESH_STATION_WIDE_S * 1000;
  } else {
    EspNowMeshStation.probes++;
  }
  EspNowMeshStation.try_since = millis();
  EspNowMeshStation.state = wide ? ESPNOW_MESH_STATION_WIDE : ESPNOW_MESH_STATION_PROBING;
}

// Which saved network an entry of the scan is: 0 or 1, or -1 for none
static int32_t EspNowMeshStationSaved(int16_t entry) {
  String ssid = WiFi.SSID(entry);
  for (uint32_t i = 0; i < 2; i++) {
    const char* saved = SettingsText(SET_STASSID1 + i);
    if (strlen(saved) && ssid.equals(saved)) { return i; }
  }
  return -1;
}

// The scan's result: the strongest access point of a saved network on a channel the station may be on is joined, on its channel; none,
// and the station parks again. The strongest one on another channel is kept as the one off the channel
static void EspNowMeshStationScanned(void) {
  bool wide = (ESPNOW_MESH_STATION_WIDE == EspNowMeshStation.state);
  int16_t count = WiFi.scanComplete();
  if (WIFI_SCAN_RUNNING == count) {
    if (EspNowMeshStationSince(EspNowMeshStation.try_since) < (wide ? ESPNOW_MESH_STATION_WIDE_MAX_MS : ESPNOW_MESH_STATION_SCAN_MAX_MS)) { return; }
    count = 0;
  }
  int16_t best = -1;
  int16_t off = -1;
  int32_t network = -1;
  for (int16_t i = 0; i < count; i++) {
    int32_t saved = EspNowMeshStationSaved(i);
    if (saved < 0) { continue; }
    if (EspNowMeshStationJoinable(WiFi.channel(i))) {
      if ((best < 0) || (WiFi.RSSI(i) > WiFi.RSSI(best))) {
        best = i;
        network = saved;
      }
    } else if ((off < 0) || (WiFi.RSSI(i) > WiFi.RSSI(off))) {
      off = i;
    }
  }
  if (off >= 0) {
    uint8_t channel = WiFi.channel(off);
    if (channel != EspNowMeshStation.off_channel) {
      AddLog(LOG_LEVEL_INFO, PSTR("EMS: %s seen on channel %d, off the mesh's %d"), WiFi.SSID(off).c_str(), channel, EspNowMeshSettings.channel);
    }
    EspNowMeshStation.off_channel = channel;
    memcpy(EspNowMeshStation.off_bssid, WiFi.BSSID(off), 6);
  } else if (wide) {
    EspNowMeshStation.off_channel = 0;     // every channel was seen, and no access point off the mesh's
    memset(EspNowMeshStation.off_bssid, 0, 6);
  }
  if (best < 0) {
    WiFi.scanDelete();
    EspNowMeshStationPark();
    return;
  }
  EspNowMeshStation.seen++;
  uint8_t bssid[6];
  memcpy(bssid, WiFi.BSSID(best), 6);
  int32_t channel = WiFi.channel(best);
  WiFi.scanDelete();
  Settings->sta_active = network;
  EspNowMeshStation.fails = 0;
  EspNowMeshStation.try_since = millis();
  EspNowMeshStation.state = ESPNOW_MESH_STATION_JOINING;
  WiFi.setAutoReconnect(true);
  WiFiHelper::begin(SettingsText(SET_STASSID1 + network), SettingsText(SET_STAPWD1 + network), channel, bssid);
  AddLog(LOG_LEVEL_INFO, PSTR("EMS: %s seen on channel %d, joining"), SettingsText(SET_STASSID1 + network), channel);
}

// Tasmota's retries back, starting over at once when its WiFi is still meant to be on
static void EspNowMeshStationLeave(void) {
  if ((ESPNOW_MESH_STATION_PROBING == EspNowMeshStation.state) || (ESPNOW_MESH_STATION_WIDE == EspNowMeshStation.state)) { WiFi.scanDelete(); }
  WiFi.setAutoReconnect(true);
  EspNowMeshStation.state = ESPNOW_MESH_STATION_WATCH;
  EspNowMeshStation.step = 0;
  EspNowMeshStation.not_found = false;
  if (Settings->flag4.network_wifi && !Wifi.config_type) { Wifi.retry = Wifi.retry_init; }
  AddLog(LOG_LEVEL_DEBUG, PSTR("EMS: Retries handed back to Tasmota"));
}

static void EspNowMeshStationEverySecond(void) {
  if (!EspNowMeshStationApplies()) {
    if (ESPNOW_MESH_STATION_WATCH != EspNowMeshStation.state) { EspNowMeshStationLeave(); }
    EspNowMeshStation.down_since = 0;
    return;
  }
  wifi_ap_record_t ap;
  if ((ESP_OK == esp_wifi_sta_get_ap_info(&ap)) && !EspNowMeshStationJoinable(ap.primary) && EspNowMeshStationRadioFree()) {
    EspNowMeshStationLeaveAp(&ap);
    return;
  }
  if (WL_CONNECTED == WiFi.status()) {
    if (ESPNOW_MESH_STATION_WATCH != EspNowMeshStation.state) {
      EspNowMeshStation.found++;
      AddLog(LOG_LEVEL_INFO, PSTR("EMS: WiFi back after %u s"), EspNowMeshStationSince(EspNowMeshStation.down_since) / 1000);
    }
    EspNowMeshStation.state = ESPNOW_MESH_STATION_WATCH;
    EspNowMeshStation.step = 0;
    EspNowMeshStation.down_since = 0;
    EspNowMeshStation.not_found = false;
    EspNowMeshStation.off_channel = 0;
    memset(EspNowMeshStation.off_bssid, 0, 6);
    return;
  }
  if (!EspNowMeshStation.down_since) { EspNowMeshStation.down_since = millis() ? millis() : 1; }
  switch (EspNowMeshStation.state) {
    case ESPNOW_MESH_STATION_WATCH:
      if (!EspNowMeshStationRadioFree()) { break; }
      if (EspNowMeshStation.not_found || (EspNowMeshStationSince(EspNowMeshStation.down_since) >= ESPNOW_MESH_STATION_GRACE_S * 1000)) {
        AddLog(LOG_LEVEL_INFO, PSTR("EMS: WiFi %s, the radio stays on the mesh's channel %d and the network is looked for there"),
          EspNowMeshStation.not_found ? PSTR("not found") : PSTR("out of reach"), EspNowMeshSettings.channel);
        EspNowMeshStationPark();
      }
      break;
    case ESPNOW_MESH_STATION_PARKED:
      if (!EspNowMeshStationRadioFree() || EspNowMeshSearchHolds()) { break; }
      if (!TimeReached(EspNowMeshStation.next_try)) {
        EspNowMeshStationChannel();        // a scan may have left it elsewhere
      } else {
        EspNowMeshStationScan(TimeReached(EspNowMeshStation.wide_at));
      }
      break;
    case ESPNOW_MESH_STATION_PROBING:
    case ESPNOW_MESH_STATION_WIDE:
      EspNowMeshStationScanned();
      break;
    case ESPNOW_MESH_STATION_JOINING: {
      uint32_t trying = EspNowMeshStationSince(EspNowMeshStation.try_since);
      bool associated = (ESP_OK == esp_wifi_sta_get_ap_info(&ap));
      bool over = associated ? (trying >= ESPNOW_MESH_STATION_ASSOC_S * 1000)
                             : ((EspNowMeshStation.fails >= ESPNOW_MESH_STATION_TRY_FAILS) || (trying >= ESPNOW_MESH_STATION_TRY_S * 1000));
      if (over) { EspNowMeshStationPark(); }
      break;
    }
  }
}

static const char* EspNowMeshStationStateText(void) {
  switch (EspNowMeshStation.state) {
    case ESPNOW_MESH_STATION_PARKED:  return PSTR("Parked");
    case ESPNOW_MESH_STATION_PROBING: return PSTR("Probing");
    case ESPNOW_MESH_STATION_JOINING: return PSTR("Joining");
    case ESPNOW_MESH_STATION_WIDE:    return PSTR("Wide");
  }
  return PSTR("Watch");
}

void CmndEspNowMeshStation(void) {
  uint32_t down = EspNowMeshStation.down_since ? EspNowMeshStationSince(EspNowMeshStation.down_since) / 1000 : 0;
  uint32_t next = 0;
  if ((ESPNOW_MESH_STATION_PARKED == EspNowMeshStation.state) && !TimeReached(EspNowMeshStation.next_try)) {
    next = (EspNowMeshStation.next_try - millis()) / 1000;
  }
  wifi_ap_record_t ap;
  uint32_t ap_channel = (ESP_OK == esp_wifi_sta_get_ap_info(&ap)) ? ap.primary : 0;
  char bssid[18] = "";
  if (EspNowMeshStation.off_channel) {
    const uint8_t* b = EspNowMeshStation.off_bssid;
    snprintf_P(bssid, sizeof(bssid), PSTR("%02X:%02X:%02X:%02X:%02X:%02X"), b[0], b[1], b[2], b[3], b[4], b[5]);
  }
  Response_P(PSTR("{\"EspNowMeshStation\":{\"State\":\"%s\",\"Down\":%u,\"Next\":%u,\"Channel\":%u,\"Ap\":%u,\"Probes\":%u,\"Seen\":%u,\"Wides\":%u,"
                  "\"Found\":%u,\"Parks\":%u,\"Reason\":%u,\"OffChannel\":%u,\"OffBssid\":\"%s\",\"Offs\":%u}}"),
    EspNowMeshStationStateText(), down, next, EspNowMeshSettings.channel, ap_channel,
    EspNowMeshStation.probes, EspNowMeshStation.seen, EspNowMeshStation.wides, EspNowMeshStation.found, EspNowMeshStation.parks,
    EspNowMeshStation.reason, EspNowMeshStation.off_channel, bssid, EspNowMeshStation.offs);
}

const char kEspNowMeshStationCommands[] PROGMEM = "|EspNowMeshStation";
void (* const kEspNowMeshStationCommand[])(void) PROGMEM = { &CmndEspNowMeshStation };

bool Xdrv102(uint32_t function) {
  bool result = false;
  switch (function) {
    case FUNC_INIT:
      WiFi.onEvent(EspNowMeshStationEvent);
      break;
    case FUNC_EVERY_SECOND:
      EspNowMeshStationEverySecond();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowMeshStationCommands, kEspNowMeshStationCommand);
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_MESH
