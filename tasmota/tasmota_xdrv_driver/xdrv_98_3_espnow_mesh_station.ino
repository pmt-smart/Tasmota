/*
  xdrv_98_3_espnow_mesh_station.ino - ESP-NOW mesh: a node whose WiFi network is out of reach tries it seldom, on the mesh's channel meanwhile

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
 * started on the way (WifiBegin). Each attempt scans every channel, and an ESP-NOW mesh that lives on one channel
 * loses the node: a ZBBridge Pro with a network that does not exist spent 95% of ten minutes off the mesh's channel.
 *
 * With the mesh running on a channel of its own setting, this driver takes the retries of such a node over. After
 * ESPNOW_MESH_STATION_GRACE_S with no connection, the station stops trying (the stack's retries off, Tasmota's held
 * through EspNowMeshStationQuiet) and the radio goes to the mesh's channel. A try comes ESPNOW_MESH_STATION_FIRST_S
 * later, and the time between tries doubles up to ESPNOW_MESH_STATION_MAX_S, plus a delay of the node's own, from its
 * MAC, so that the nodes of a house do not leave the channel together after an outage of their access point. A try is
 * one connection by the WiFi stack, with its own retries, and without stopping the radio. It ends at the
 * ESPNOW_MESH_STATION_TRY_FAILS-th failure the stack reports, or after ESPNOW_MESH_STATION_TRY_S with the station not
 * associated, or after ESPNOW_MESH_STATION_ASSOC_S with no address. A try that connects hands the station to Tasmota,
 * connected, and the waiting starts over at the shortest the next time.
 *
 * Nothing changes for a device without the mesh running, without a mesh channel, with no network saved, or with
 * Tasmota's WiFi off. Nor while someone else has the radio: the WiFi Manager, a join, a pairing, a hotspot, a scan, the
 * direct link, the mesh's off-channel probe. When one of them takes it, or the mesh stops, Tasmota gets its retries
 * back at once.
 *
 * Command:
 *   EspNowMeshStation - {"EspNowMeshStation":{"State":"Watch"|"Parked"|"Trying","Down":<s>,"Next":<s>,"Interval":<s>,
 *                        "Tries":<n>,"Found":<n>,"Parks":<n>,"Reason":<n>}}: Down is how long the station has been down
 *                        (0 while up), Next the seconds to the next try, Reason the last failure the stack reported
\*********************************************************************************************/

#define XDRV_102                          102

#ifndef ESPNOW_MESH_STATION_GRACE_S
#define ESPNOW_MESH_STATION_GRACE_S       30       // a station down this long stops trying on its own
#endif
#ifndef ESPNOW_MESH_STATION_FIRST_S
#define ESPNOW_MESH_STATION_FIRST_S       60       // the wait before the first try
#endif
#ifndef ESPNOW_MESH_STATION_MAX_S
#define ESPNOW_MESH_STATION_MAX_S         300      // the longest wait between tries
#endif
#ifndef ESPNOW_MESH_STATION_SPREAD_S
#define ESPNOW_MESH_STATION_SPREAD_S      30       // a node's own delay, 0 to this, from its MAC
#endif
#ifndef ESPNOW_MESH_STATION_TRY_S
#define ESPNOW_MESH_STATION_TRY_S         15       // a try with the station not associated by then ends
#endif
#define ESPNOW_MESH_STATION_ASSOC_S       30       // a try associated with no address by then ends
#define ESPNOW_MESH_STATION_TRY_FAILS     2        // a try ends at this failure the stack reports

enum EspNowMeshStationStates { ESPNOW_MESH_STATION_WATCH, ESPNOW_MESH_STATION_PARKED, ESPNOW_MESH_STATION_TRYING };

struct {
  uint8_t state = ESPNOW_MESH_STATION_WATCH;
  uint32_t down_since = 0;                 // when the station was first seen down, 0 while it is up
  uint32_t next_try = 0;
  uint32_t try_since = 0;
  uint32_t interval_s = ESPNOW_MESH_STATION_FIRST_S;
  uint32_t tries = 0;
  uint32_t found = 0;                      // the tries that connected
  uint32_t parks = 0;
  volatile uint32_t fails = 0;             // the failures the stack reported during the try
  volatile uint8_t reason = 0;             // the last one
} EspNowMeshStation;

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

// The station stops trying, and the radio goes to the mesh's channel until the next try
static void EspNowMeshStationPark(void) {
  WiFi.setAutoReconnect(false);
  WiFi.disconnect();                       // ends the attempt the stack is making; the radio stays on
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  uint32_t spread = (((uint32_t)mac[4] << 8) | mac[5]) % (ESPNOW_MESH_STATION_SPREAD_S + 1);
  EspNowMeshStation.next_try = millis() + (EspNowMeshStation.interval_s + spread) * 1000;
  EspNowMeshStation.state = ESPNOW_MESH_STATION_PARKED;
  EspNowMeshStation.parks++;
  EspNowMeshStationChannel();
  AddLog(LOG_LEVEL_INFO, PSTR("EMS: WiFi out of reach, the radio stays on the mesh's channel %d, next try in %u s"),
    EspNowMeshSettings.channel, EspNowMeshStation.interval_s + spread);
}

// One connection, with the stack's retries, and the radio left on: the other saved network every other try, when there are two
static void EspNowMeshStationTry(void) {
  EspNowMeshStation.tries++;
  uint32_t other = Settings->sta_active ^ 1;
  if (strlen(SettingsText(SET_STASSID1 + other)) && !(EspNowMeshStation.tries & 1)) { Settings->sta_active = other; }
  if (!strlen(SettingsText(SET_STASSID1 + Settings->sta_active))) { Settings->sta_active ^= 1; }
  EspNowMeshStation.fails = 0;
  EspNowMeshStation.try_since = millis();
  EspNowMeshStation.state = ESPNOW_MESH_STATION_TRYING;
  WiFi.setAutoReconnect(true);
  WiFiHelper::begin(SettingsText(SET_STASSID1 + Settings->sta_active), SettingsText(SET_STAPWD1 + Settings->sta_active));
  AddLog(LOG_LEVEL_INFO, PSTR("EMS: Trying %s"), SettingsText(SET_STASSID1 + Settings->sta_active));
}

// Tasmota's retries back, starting over at once when its WiFi is still meant to be on
static void EspNowMeshStationLeave(void) {
  WiFi.setAutoReconnect(true);
  EspNowMeshStation.state = ESPNOW_MESH_STATION_WATCH;
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
    if (ESPNOW_MESH_STATION_TRYING == EspNowMeshStation.state) {
      EspNowMeshStation.found++;
      AddLog(LOG_LEVEL_INFO, PSTR("EMS: WiFi back after %u s"), (millis() - EspNowMeshStation.down_since) / 1000);
    }
    EspNowMeshStation.state = ESPNOW_MESH_STATION_WATCH;
    EspNowMeshStation.down_since = 0;
    EspNowMeshStation.interval_s = ESPNOW_MESH_STATION_FIRST_S;
    return;
  }
  if (!EspNowMeshStation.down_since) { EspNowMeshStation.down_since = millis() | 1; }
  uint32_t now = millis();
  switch (EspNowMeshStation.state) {
    case ESPNOW_MESH_STATION_WATCH:
      if (((now - EspNowMeshStation.down_since) >= ESPNOW_MESH_STATION_GRACE_S * 1000) && EspNowMeshStationRadioFree()) {
        EspNowMeshStationPark();
      }
      break;
    case ESPNOW_MESH_STATION_PARKED:
      if (!EspNowMeshStationRadioFree()) { break; }
      if (TimeReached(EspNowMeshStation.next_try)) {
        EspNowMeshStationTry();
      } else {
        EspNowMeshStationChannel();        // a scan may have left it elsewhere
      }
      break;
    case ESPNOW_MESH_STATION_TRYING: {
      uint32_t trying = now - EspNowMeshStation.try_since;
      wifi_ap_record_t ap;
      bool associated = (ESP_OK == esp_wifi_sta_get_ap_info(&ap));
      bool over = associated ? (trying >= ESPNOW_MESH_STATION_ASSOC_S * 1000)
                             : ((EspNowMeshStation.fails >= ESPNOW_MESH_STATION_TRY_FAILS) || (trying >= ESPNOW_MESH_STATION_TRY_S * 1000));
      if (over) {
        EspNowMeshStation.interval_s = (EspNowMeshStation.interval_s * 2 > ESPNOW_MESH_STATION_MAX_S) ? ESPNOW_MESH_STATION_MAX_S : EspNowMeshStation.interval_s * 2;
        EspNowMeshStationPark();
      }
      break;
    }
  }
}

static const char* EspNowMeshStationStateText(void) {
  switch (EspNowMeshStation.state) {
    case ESPNOW_MESH_STATION_PARKED: return PSTR("Parked");
    case ESPNOW_MESH_STATION_TRYING: return PSTR("Trying");
  }
  return PSTR("Watch");
}

void CmndEspNowMeshStation(void) {
  uint32_t now = millis();
  uint32_t down = EspNowMeshStation.down_since ? (now - EspNowMeshStation.down_since) / 1000 : 0;
  uint32_t next = 0;
  if ((ESPNOW_MESH_STATION_PARKED == EspNowMeshStation.state) && !TimeReached(EspNowMeshStation.next_try)) {
    next = (EspNowMeshStation.next_try - now) / 1000;
  }
  Response_P(PSTR("{\"EspNowMeshStation\":{\"State\":\"%s\",\"Down\":%u,\"Next\":%u,\"Interval\":%u,\"Tries\":%u,\"Found\":%u,\"Parks\":%u,\"Reason\":%u}}"),
    EspNowMeshStationStateText(), down, next, EspNowMeshStation.interval_s, EspNowMeshStation.tries, EspNowMeshStation.found,
    EspNowMeshStation.parks, EspNowMeshStation.reason);
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
