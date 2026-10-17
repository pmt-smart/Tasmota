/*
  xdrv_98_3_espnow_mesh_station.ino - ESP-NOW mesh: a node whose WiFi network is out of reach looks for it on one channel, and stays on the mesh's

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
 * - after ESPNOW_MESH_STATION_GRACE_S with no connection, the station stops trying (the stack's retries off, Tasmota's
 *   held through EspNowMeshStationQuiet, and no restart) and the radio goes to the mesh's channel;
 * - it looks for the network with a scan of one channel, active, of ESPNOW_MESH_STATION_PROBE_MS: the channel the
 *   network was last on, or the mesh's when that is not known. On the mesh's channel the radio does not even leave it.
 *   The scans come 10, 30 and then every 60 s after the park, plus a delay of the node's own, from its MAC, of up to
 *   ESPNOW_MESH_STATION_SPREAD_S;
 * - a scan that finds one of the saved networks joins it on that channel and that access point, and a join that
 *   connects hands the station to Tasmota, connected;
 * - every ESPNOW_MESH_STATION_WIDE_S the scan gives way to a connection of the stack's own, on every channel, for an
 *   access point that moved to another channel, or a network the node has never been on. It ends at the
 *   ESPNOW_MESH_STATION_TRY_FAILS-th failure the stack reports.
 * A join or a wide try ends after ESPNOW_MESH_STATION_TRY_S with the station not associated, or ESPNOW_MESH_STATION_ASSOC_S
 * with no address.
 *
 * Nothing changes for a device without the mesh running, without a mesh channel, with no network saved, or with
 * Tasmota's WiFi off. Nor while someone else has the radio: the WiFi Manager, a join, a pairing, a hotspot, a scan, the
 * direct link, the mesh's off-channel probe. When one of them takes it, or the mesh stops, Tasmota gets its retries
 * back at once. Tasmota's WiFi setting is never changed, so a power cut in the middle leaves nothing behind.
 *
 * Command:
 *   EspNowMeshStation - {"EspNowMeshStation":{"State":"Watch"|"Parked"|"Probing"|"Joining"|"Wide","Down":<s>,"Next":<s>,
 *                        "Channel":<n>,"Probes":<n>,"Seen":<n>,"Wides":<n>,"Found":<n>,"Parks":<n>,"Reason":<n>}}: Down is
 *                        how long the station has been down (0 while up), Next the seconds to the next scan, Channel the one
 *                        it scans, Seen the scans that saw the network, Found the joins and wide tries that connected, Reason
 *                        the last failure the stack reported
\*********************************************************************************************/

#define XDRV_102                          102

#ifndef ESPNOW_MESH_STATION_GRACE_S
#define ESPNOW_MESH_STATION_GRACE_S       10       // a station down this long stops trying on its own
#endif
#ifndef ESPNOW_MESH_STATION_PROBE_MS
#define ESPNOW_MESH_STATION_PROBE_MS      120      // the scan of the network's channel
#endif
#ifndef ESPNOW_MESH_STATION_SPREAD_S
#define ESPNOW_MESH_STATION_SPREAD_S      5        // a node's own delay, 0 to this, from its MAC
#endif
#ifndef ESPNOW_MESH_STATION_WIDE_S
#define ESPNOW_MESH_STATION_WIDE_S        600      // a connection on every channel this often while parked
#endif
#define ESPNOW_MESH_STATION_TRY_S         15       // a join or a wide try with the station not associated by then ends
#define ESPNOW_MESH_STATION_ASSOC_S       30       // and associated with no address by then
#define ESPNOW_MESH_STATION_TRY_FAILS     2        // a wide try ends at this failure the stack reports
#define ESPNOW_MESH_STATION_SCAN_MAX_MS   3000     // a scan with no result by then failed

static const uint8_t EspNowMeshStationWaits[] = { 10, 30, 60 };   // seconds between the scans; the last one repeats

enum EspNowMeshStationStates {
  ESPNOW_MESH_STATION_WATCH, ESPNOW_MESH_STATION_PARKED, ESPNOW_MESH_STATION_PROBING, ESPNOW_MESH_STATION_JOINING, ESPNOW_MESH_STATION_WIDE
};

struct {
  uint8_t state = ESPNOW_MESH_STATION_WATCH;
  uint8_t step = 0;                        // into EspNowMeshStationWaits
  uint8_t channel = 0;                     // the channel the network was last on, 0 not known
  uint32_t down_since = 0;                 // when the station was first seen down, 0 while it is up
  uint32_t next_try = 0;
  uint32_t try_since = 0;
  uint32_t wide_at = 0;                    // when the next wide try is due
  uint32_t probes = 0;
  uint32_t seen = 0;                       // the scans that saw a saved network
  uint32_t wides = 0;
  uint32_t found = 0;                      // the joins and wide tries that connected
  uint32_t parks = 0;
  volatile uint32_t fails = 0;             // the failures the stack reported during a join or a wide try
  volatile uint8_t reason = 0;             // the last one
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

// A join, a pairing, a hotspot or a scan has the radio: a parked station leaves the radio alone and waits
static bool EspNowMeshStationRadioFree(void) {
#ifdef USE_WIFI_STATION_CONTROL
  return (STA_RADIO_FREE == StaCtrlRadioOwner());
#else
  return !Wifi.scan_state && (WIFI_SCAN_RUNNING != WiFi.scanComplete());
#endif
}

static void EspNowMeshStationChannel(void) {
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

// The station stops trying, the radio goes to the mesh's channel, and the next scan is set
static void EspNowMeshStationPark(void) {
  WiFi.setAutoReconnect(false);
  // A connection under way, Tasmota's or a join, is ended; the radio stays on. A scan leaves nothing to end
  if ((ESPNOW_MESH_STATION_PROBING != EspNowMeshStation.state) && (ESPNOW_MESH_STATION_PARKED != EspNowMeshStation.state)) {
    WiFi.disconnect();
  }
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  uint32_t wait_s = EspNowMeshStationWaits[EspNowMeshStation.step] + mac[5] % (ESPNOW_MESH_STATION_SPREAD_S + 1);
  if (EspNowMeshStation.step < sizeof(EspNowMeshStationWaits) - 1) { EspNowMeshStation.step++; }
  EspNowMeshStation.next_try = millis() + wait_s * 1000;
  if (ESPNOW_MESH_STATION_WATCH == EspNowMeshStation.state) {
    EspNowMeshStation.parks++;
    EspNowMeshStation.wide_at = millis() + ESPNOW_MESH_STATION_WIDE_S * 1000;
    AddLog(LOG_LEVEL_INFO, PSTR("EMS: WiFi out of reach, the radio stays on the mesh's channel %d, the network looked for on channel %d"),
      EspNowMeshSettings.channel, EspNowMeshStation.channel ? EspNowMeshStation.channel : EspNowMeshSettings.channel);
  }
  EspNowMeshStation.state = ESPNOW_MESH_STATION_PARKED;
  EspNowMeshStationChannel();
}

// A scan of the one channel the network should be on
static void EspNowMeshStationProbe(void) {
  uint8_t channel = EspNowMeshStation.channel ? EspNowMeshStation.channel : EspNowMeshSettings.channel;
  int16_t started = WiFi.scanNetworks(true, false, false, ESPNOW_MESH_STATION_PROBE_MS, channel);
  if (WIFI_SCAN_RUNNING != started) {
    EspNowMeshStationPark();               // the stack refused it: the next one, later
    return;
  }
  EspNowMeshStation.probes++;
  EspNowMeshStation.try_since = millis();
  EspNowMeshStation.state = ESPNOW_MESH_STATION_PROBING;
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

// The scan's result: the strongest access point of a saved network is joined, on its channel; none, and the station parks again
static void EspNowMeshStationProbed(void) {
  int16_t count = WiFi.scanComplete();
  if (WIFI_SCAN_RUNNING == count) {
    if (EspNowMeshStationSince(EspNowMeshStation.try_since) < ESPNOW_MESH_STATION_SCAN_MAX_MS) { return; }
    count = 0;
  }
  int16_t best = -1;
  int32_t network = -1;
  for (int16_t i = 0; i < count; i++) {
    int32_t saved = EspNowMeshStationSaved(i);
    if ((saved >= 0) && ((best < 0) || (WiFi.RSSI(i) > WiFi.RSSI(best)))) {
      best = i;
      network = saved;
    }
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

// A connection of the stack's own, on every channel, with its retries, and the radio left on: the other saved network every
// other time, when there are two
static void EspNowMeshStationWide(void) {
  EspNowMeshStation.wides++;
  EspNowMeshStation.wide_at = millis() + ESPNOW_MESH_STATION_WIDE_S * 1000;
  uint32_t other = Settings->sta_active ^ 1;
  if (strlen(SettingsText(SET_STASSID1 + other)) && !(EspNowMeshStation.wides & 1)) { Settings->sta_active = other; }
  if (!strlen(SettingsText(SET_STASSID1 + Settings->sta_active))) { Settings->sta_active ^= 1; }
  EspNowMeshStation.fails = 0;
  EspNowMeshStation.try_since = millis();
  EspNowMeshStation.state = ESPNOW_MESH_STATION_WIDE;
  WiFi.setAutoReconnect(true);
  WiFiHelper::begin(SettingsText(SET_STASSID1 + Settings->sta_active), SettingsText(SET_STAPWD1 + Settings->sta_active));
  AddLog(LOG_LEVEL_INFO, PSTR("EMS: Trying %s on every channel"), SettingsText(SET_STASSID1 + Settings->sta_active));
}

// Tasmota's retries back, starting over at once when its WiFi is still meant to be on
static void EspNowMeshStationLeave(void) {
  if (ESPNOW_MESH_STATION_PROBING == EspNowMeshStation.state) { WiFi.scanDelete(); }
  WiFi.setAutoReconnect(true);
  EspNowMeshStation.state = ESPNOW_MESH_STATION_WATCH;
  EspNowMeshStation.step = 0;
  if (Settings->flag4.network_wifi && !Wifi.config_type) { Wifi.retry = Wifi.retry_init; }
  AddLog(LOG_LEVEL_DEBUG, PSTR("EMS: Retries handed back to Tasmota"));
}

static void EspNowMeshStationEverySecond(void) {
  if (!EspNowMeshStationApplies()) {
    if (ESPNOW_MESH_STATION_WATCH != EspNowMeshStation.state) { EspNowMeshStationLeave(); }
    EspNowMeshStation.down_since = 0;
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
    uint8_t channel = WiFi.channel();
    if (channel) { EspNowMeshStation.channel = channel; }
    return;
  }
  if (!EspNowMeshStation.down_since) { EspNowMeshStation.down_since = millis() ? millis() : 1; }
  switch (EspNowMeshStation.state) {
    case ESPNOW_MESH_STATION_WATCH:
      if ((EspNowMeshStationSince(EspNowMeshStation.down_since) >= ESPNOW_MESH_STATION_GRACE_S * 1000) && EspNowMeshStationRadioFree()) {
        EspNowMeshStationPark();
      }
      break;
    case ESPNOW_MESH_STATION_PARKED:
      if (!EspNowMeshStationRadioFree()) { break; }
      if (!TimeReached(EspNowMeshStation.next_try)) {
        EspNowMeshStationChannel();        // a scan may have left it elsewhere
      } else if (TimeReached(EspNowMeshStation.wide_at)) {
        EspNowMeshStationWide();
      } else {
        EspNowMeshStationProbe();
      }
      break;
    case ESPNOW_MESH_STATION_PROBING:
      EspNowMeshStationProbed();
      break;
    case ESPNOW_MESH_STATION_JOINING:
    case ESPNOW_MESH_STATION_WIDE: {
      uint32_t trying = EspNowMeshStationSince(EspNowMeshStation.try_since);
      wifi_ap_record_t ap;
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
  Response_P(PSTR("{\"EspNowMeshStation\":{\"State\":\"%s\",\"Down\":%u,\"Next\":%u,\"Channel\":%u,\"Probes\":%u,\"Seen\":%u,\"Wides\":%u,"
                  "\"Found\":%u,\"Parks\":%u,\"Reason\":%u}}"),
    EspNowMeshStationStateText(), down, next, EspNowMeshStation.channel ? EspNowMeshStation.channel : EspNowMeshSettings.channel,
    EspNowMeshStation.probes, EspNowMeshStation.seen, EspNowMeshStation.wides, EspNowMeshStation.found, EspNowMeshStation.parks,
    EspNowMeshStation.reason);
}

const char kEspNowMeshStationCommands[] PROGMEM = "|EspNowMeshStation";
void (* const kEspNowMeshStationCommand[])(void) PROGMEM = { &CmndEspNowMeshStation };

bool Xdrv102(uint32_t function) {
  bool result = false;
  switch (function) {
    case FUNC_INIT:
      WiFi.onEvent(EspNowMeshStationEvent);
      EspNowMeshStation.channel = Settings->wifi_channel;   // the network's last channel, before a failure clears it
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
