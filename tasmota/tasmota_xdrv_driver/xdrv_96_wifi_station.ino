/*
  xdrv_96_wifi_station.ino - scan, join and forget a WiFi network without a restart

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

#ifdef ESP32
#ifdef USE_WIFI_STATION_CONTROL
/*********************************************************************************************\
 * WiFi station control, for a device set up from its own screen or script.
 *
 * Tasmota joins the networks saved in SSId1 and SSId2, and has no way to try one
 * before saving it: SSId and Password restart the device, and WifiTest runs only
 * inside the WiFi Manager. This driver borrows the radio while Tasmota's WiFi is
 * off. `Wifi 0` leaves the radio alone: the main loop then only calls
 * WifiDisable(), which does nothing once the WiFi is down, and nothing else in
 * Tasmota starts a connection.
 *
 * - A scan lists the networks in range, strongest first, one entry per name. It
 *   runs in place with Tasmota connected, since a scan keeps the association.
 * - A join tries a network. The credentials are saved as SSId1 and Password1 only
 *   once the station has an address, and the station is then handed to Tasmota
 *   connected: WifiConnect() finds it up at the next check and adopts it. A
 *   failure is reported with its reason, from the WiFi stack's disconnect event,
 *   and Tasmota's WiFi is left as it was before the join.
 * - Forget clears SSId1, Password1 and BSSId1, with no restart.
 * - Hold keeps the radio in station mode with no network and no AP while
 *   Tasmota's WiFi is off, for a radio user that needs the channel without an
 *   access point, as ESP-NOW does. It is not saved: whoever needs it asks again
 *   after a restart.
 * - Hotspot is an access point of the device's own, for a phone to reach its web
 *   UI directly: WPA2, with the name and password the command gives, beside the
 *   station, on the channel the radio is on, which is the station's when it is
 *   connected. The web server comes up with it when it was not running, and its
 *   pages take requests made to the hotspot's address. It closes on StaHotspot 0,
 *   a restart, the WiFi Manager opening its own, or STA_CTRL_HOTSPOT_IDLE_MS
 *   with nobody on it. An upgrade over the hotspot alone is refused: it runs from
 *   the safeboot, which has no hotspot to come back on, and the device would be
 *   left with no way to reach it.
 * - The radio has one owner at a time, which sets its channel. From the one that
 *   wins to the one that yields: the WiFi Manager, a join, a pairing session that
 *   another driver claims (StaCtrlRadioClaim), the hotspot, which holds its
 *   phones' channel, a scan. A scan passes under the WiFi Manager, the hotspot
 *   and a connected station, but waits for a join and a pairing,
 *   which need the channel to stay put. The station, and a transport that
 *   follows its channel, come below them all: they leave the channel alone
 *   while StaCtrlRadioOwner names anyone, and follow it again once it is free.
 *   A pairing does not cut a join short, and the other way round: whoever asks
 *   for the second ends the first. StaState says who has the radio.
 *
 * The station's disconnect reasons are also kept while Tasmota connects on its
 * own, so the device can say why its saved network does not come up.
 *
 * Results go to MQTT and to the rule engine, like WifiScan's:
 *   {"StaScan":{"Networks":[["<ssid>",<rssi>,<auth>,<channel>,"<bssid>"],...]}}
 *   {"StaJoin":{"State":"Connected","SSId":"<ssid>","IP":"<ip>"}}
 *   {"StaJoin":{"State":"Failed","SSId":"<ssid>","Reason":"<why>","Code":<n>}}
 *   {"StaHotspot":{"State":"Up","SSId":"<ssid>","Channel":<n>,"IP":"<ip>","Clients":<n>}},
 *     again whenever the number of phones on it changes
 *   {"StaHotspot":{"State":"Off","Reason":"Stop"|"Idle"|"WifiManager"|"Lost"}}
 * `auth` is the ESP-IDF wifi_auth_mode_t, and `why` is WrongPassword, NotFound,
 * NoAnswer or NoAddress.
 *
 * Commands:
 *   StaScan           - scan, reported when done
 *   StaJoin {"SSId":"<ssid>","Password":"<password>","Channel":<n>,"BSSId":"<bssid>"}
 *                     - join, Channel and BSSId optional; Tasmota's WiFi goes off
 *                       first when it is on
 *   StaForget         - clear SSId1, Password1 and BSSId1; Tasmota's WiFi goes off
 *   StaHold 0|1       - keep the radio in station mode while Tasmota's WiFi is off
 *   StaState          - what the driver is doing, who has the radio, and the
 *                       station's last disconnect reason
 *   StaHotspot {"SSId":"<ssid>","Password":"<password>"} - open the hotspot, with a
 *                       password of 8 to 63 characters, never echoed back; 0 closes
 *                       it; bare, its state
\*********************************************************************************************/

#define XDRV_96                         96

#define STA_CTRL_SCAN_TIMEOUT_MS        15000    // a scan that has not finished by then failed
#define STA_CTRL_JOIN_TIMEOUT_MS        25000    // a join with no address by then failed
#define STA_CTRL_ADDRESS_TIMEOUT_MS     12000    // associated, and no address by then
#define STA_CTRL_RETRY_GRACE_MS         8000     // a failure the stack did not retry within this is final
#define STA_CTRL_LINGER_MS              60000    // the radio stays up this long after a scan, for the join that follows
#define STA_CTRL_SCAN_REPORT_MAX        900      // bytes of scan report, to stay within one MQTT message
#define STA_CTRL_HOTSPOT_IDLE_MS        900000   // the hotspot closes after this long with nobody on it
#define STA_CTRL_HOTSPOT_CLIENTS        4        // phones the hotspot takes at once

enum StaCtrlStates { STA_CTRL_IDLE, STA_CTRL_SCANNING, STA_CTRL_JOINING };

struct {
  uint8_t state = STA_CTRL_IDLE;
  bool hold = false;                       // StaHold 1
  bool restore = false;                    // Tasmota's WiFi was on when this driver took the radio
  bool borrowed = false;                   // the radio is on for this driver, with Tasmota's WiFi off
  bool claimed = false;                    // a pairing session holds the radio, StaCtrlRadioClaim
  bool paused = false;                     // and has Tasmota's WiFi paused, StaCtrlRadioPause
  uint32_t started = 0;                    // when the scan or the join began
  uint32_t linger_until = 0;               // when a borrowed radio goes back off
  volatile uint32_t associated = 0;        // when the station associated during a join, 0 before
  volatile uint32_t last_disconnect = 0;   // when the last failure of a join was reported
  volatile uint8_t disconnects = 0;        // failures reported during a join
  volatile uint8_t reason = 0;             // the last failure reported, joining or not
  volatile bool got_address = false;       // the join has an address
  bool hotspot = false;                    // StaHotspot: the access point is up
  uint8_t hotspot_clients = 0;             // the phones on it, as last reported
  uint32_t hotspot_quiet = 0;              // since when nobody is on it
  char hotspot_ssid[33];
  char ssid[33];
  char password[65];
} StaCtrl;

/*********************************************************************************************\
 * Helpers
\*********************************************************************************************/

// Maps a disconnect reason to what a user can act on.
static const char* StaCtrlReasonText(uint8_t reason) {
  switch (reason) {
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_802_1X_AUTH_FAILED:
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
      return PSTR("WrongPassword");
    case WIFI_REASON_NO_AP_FOUND:
    case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
    case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
    case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
      return PSTR("NotFound");
    case 0:
      return PSTR("");
  }
  return PSTR("NoAnswer");
}

static bool StaCtrlTasmotaUp(void) {
  return Settings->flag4.network_wifi && !TasmotaGlobal.global_state.wifi_down;
}

static void StaCtrlClearSecret(void) {
  memset(StaCtrl.password, 0, sizeof(StaCtrl.password));
}

// Takes the radio from Tasmota: its WiFi off, as `Wifi 0` leaves it, and the
// radio in station mode, with no network.
static void StaCtrlTakeRadio(void) {
  if (Settings->flag4.network_wifi) {
    StaCtrl.restore = true;
    Settings->flag4.network_wifi = 0;
    WifiDisable();                         // does nothing when it was not connected
  }
  WifiSetMode(WIFI_STA);                   // does nothing when already in station mode
  WiFi.disconnect();                       // stops a connection attempt in flight
  StaCtrl.borrowed = true;
}

// Gives the radio back when the driver is done with it: to Tasmota when its
// WiFi was on, or kept up a while for what usually follows a scan.
static void StaCtrlGiveRadio(uint32_t linger) {
  if (StaCtrl.restore) {
    StaCtrl.restore = false;
    StaCtrl.borrowed = false;
    Settings->flag4.network_wifi = 1;
    WifiConnect();
    return;
  }
  if (StaCtrl.borrowed) { StaCtrl.linger_until = millis() + linger; }
}

// Runs every 250 ms while idle: a borrowed radio goes back off once nothing
// needs it, and a held or claimed one comes back after Tasmota switched it off.
static void StaCtrlKeepRadio(void) {
  if (Settings->flag4.network_wifi) {
    StaCtrl.borrowed = false;              // Tasmota's again, through `Wifi 1`
    return;
  }
  if (StaCtrl.hold || StaCtrl.claimed) {
    if (WIFI_OFF == WiFi.getMode()) {
      WifiSetMode(WIFI_STA);
      AddLog(LOG_LEVEL_DEBUG, PSTR("STA: Radio held in station mode"));
    }
    return;
  }
  if (StaCtrl.borrowed && TimeReached(StaCtrl.linger_until)) {
    StaCtrl.borrowed = false;
    WifiSetMode(WIFI_OFF);
  }
}

/*********************************************************************************************\
 * Radio owners
 *
 * For the other users of the radio. The station, and a transport that follows
 * its channel, ask StaCtrlRadioOwner before they move the channel, and leave it
 * alone while it names anyone. A driver that has to hold the channel where it
 * puts it, as a pairing session does, claims the radio for as long as it needs
 * it, pauses Tasmota's WiFi when it has to move the channel away from the
 * station's, and releases the radio at the end, with the WiFi back as it was.
\*********************************************************************************************/

// From the one that wins to the one that yields.
enum StaCtrlRadioOwners {
  STA_RADIO_FREE,                          // nobody: the station, or a transport, sets the channel
  STA_RADIO_WIFI_MANAGER,                  // Tasmota's WiFi Manager, with its AP
  STA_RADIO_JOIN,                          // StaJoin
  STA_RADIO_PAIRING,                       // a pairing session, StaCtrlRadioClaim
  STA_RADIO_HOTSPOT,                       // StaHotspot, which holds its phones' channel
  STA_RADIO_SCAN,                          // StaScan, or Tasmota's own scan
};

uint32_t StaCtrlRadioOwner(void) {
  if (Wifi.config_type) { return STA_RADIO_WIFI_MANAGER; }
  if (STA_CTRL_JOINING == StaCtrl.state) { return STA_RADIO_JOIN; }
  if (StaCtrl.claimed) { return STA_RADIO_PAIRING; }
  if (StaCtrl.hotspot) { return STA_RADIO_HOTSPOT; }
  if ((STA_CTRL_SCANNING == StaCtrl.state) || Wifi.scan_state || (WIFI_SCAN_RUNNING == WiFi.scanComplete())) {
    return STA_RADIO_SCAN;
  }
  return STA_RADIO_FREE;
}

const char* StaCtrlRadioOwnerText(uint32_t owner) {
  switch (owner) {
    case STA_RADIO_WIFI_MANAGER: return PSTR("WifiManager");
    case STA_RADIO_JOIN:         return PSTR("Join");
    case STA_RADIO_PAIRING:      return PSTR("Pairing");
    case STA_RADIO_HOTSPOT:      return PSTR("Hotspot");
    case STA_RADIO_SCAN:         return PSTR("Scan");
  }
  return PSTR("");
}

// Holds the radio for a pairing session. Refused while the WiFi Manager, a join
// or a scan has it: the scan is short, and the one who asked tries again once it
// is over. A radio that was off comes on in station mode for the session.
bool StaCtrlRadioClaim(void) {
  uint32_t owner = StaCtrlRadioOwner();
  if ((STA_RADIO_FREE != owner) && (STA_RADIO_PAIRING != owner)) { return false; }
  if (!StaCtrl.claimed && (WIFI_OFF == WiFi.getMode())) {
    WifiSetMode(WIFI_STA);
    StaCtrl.borrowed = true;
  }
  StaCtrl.claimed = true;
  return true;
}

// Takes the station out of the way of a claim that moves the channel: Tasmota's
// WiFi pauses, as it does for a join, and stops a connection attempt in flight.
// The WiFi stack stops and starts again on the way when Tasmota's WiFi was on.
void StaCtrlRadioPause(void) {
  if (!StaCtrl.claimed || StaCtrl.paused) { return; }
  StaCtrl.paused = true;
  StaCtrlTakeRadio();
  AddLog(LOG_LEVEL_DEBUG, PSTR("STA: WiFi paused for a pairing"));
}

// Gives Tasmota its WiFi back, as it was before the pause, with the claim kept.
void StaCtrlRadioResume(void) {
  if (!StaCtrl.paused) { return; }
  StaCtrl.paused = false;
  StaCtrlGiveRadio(0);
}

// Ends the claim, with the WiFi back as it was before it. A radio that came on
// for it goes off again, unless something holds it.
void StaCtrlRadioRelease(void) {
  if (!StaCtrl.claimed) { return; }
  StaCtrlRadioResume();
  StaCtrl.claimed = false;
  if (StaCtrl.borrowed) { StaCtrl.linger_until = millis(); }
}

/*********************************************************************************************\
 * Events
 *
 * Run on the network event task. They only record what happened; the main loop
 * acts on it.
\*********************************************************************************************/

void StaCtrlEvent(arduino_event_t *event);
void StaCtrlEvent(arduino_event_t *event) {
  switch (event->event_id) {
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      if (STA_CTRL_JOINING == StaCtrl.state) { StaCtrl.associated = millis() | 1; }
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      StaCtrl.reason = 0;
      if (STA_CTRL_JOINING == StaCtrl.state) { StaCtrl.got_address = true; }
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED: {
      uint8_t reason = event->event_info.wifi_sta_disconnected.reason;
      // Leaving is what this side asked for, not a failure: a scan, a join or
      // the WiFi stack's own retry all start by disconnecting.
      if (WIFI_REASON_ASSOC_LEAVE == reason) { break; }
      StaCtrl.reason = reason ? reason : WIFI_REASON_UNSPECIFIED;
      if (STA_CTRL_JOINING == StaCtrl.state) {
        StaCtrl.associated = 0;
        StaCtrl.last_disconnect = millis() | 1;
        if (StaCtrl.disconnects < 255) { StaCtrl.disconnects++; }
      }
      break;
    }
    default:
      break;
  }
}

/*********************************************************************************************\
 * Scan
\*********************************************************************************************/

static bool StaCtrlBusy(void) {
  // The WiFi Manager, Tasmota's own scan and a pairing own the radio while they run.
  return (STA_CTRL_IDLE != StaCtrl.state) || Wifi.config_type || Wifi.scan_state || StaCtrl.claimed;
}

void CmndStaScan(void) {
  if (StaCtrlBusy()) {
    ResponseCmndChar_P(PSTR("Busy"));
    return;
  }
  // Connected, the scan runs in place. Otherwise the radio is borrowed:
  // Tasmota connecting on its own would restart the station under the scan.
  if (!StaCtrlTasmotaUp()) { StaCtrlTakeRadio(); }

  if (WIFI_SCAN_FAILED == WiFi.scanNetworks(true)) {
    StaCtrlGiveRadio(0);
    ResponseCmndChar_P(PSTR("Failed"));
    return;
  }
  StaCtrl.state = STA_CTRL_SCANNING;
  StaCtrl.started = millis();
  ResponseCmndChar_P(PSTR("Started"));
}

static void StaCtrlScanReport(int16_t count) {
  Response_P(PSTR("{\"StaScan\":{\"Networks\":["));
  if (count > 0) {
    // Strongest first, and one entry per name: the strongest access point of a
    // network is the one a join should go to. Hidden networks have no name to
    // list and are joined by name.
    uint8_t order[count];
    for (uint32_t i = 0; i < count; i++) { order[i] = i; }
    for (uint32_t i = 0; i < count; i++) {
      for (uint32_t j = i + 1; j < count; j++) {
        if (WiFi.RSSI(order[j]) > WiFi.RSSI(order[i])) { std::swap(order[i], order[j]); }
      }
    }
    bool first = true;
    for (uint32_t i = 0; i < count; i++) {
      String ssid = WiFi.SSID(order[i]);
      if (!ssid.length()) { continue; }
      bool seen = false;
      for (uint32_t j = 0; j < i; j++) {
        if (ssid == WiFi.SSID(order[j])) { seen = true; break; }
      }
      if (seen) { continue; }
      if (ResponseLength() > STA_CTRL_SCAN_REPORT_MAX) { break; }
      ResponseAppend_P(PSTR("%s[\"%s\",%d,%d,%d,\"%s\"]"), first ? "" : ",",
        EscapeJSONString(ssid.c_str()).c_str(), WiFi.RSSI(order[i]), WiFi.encryptionType(order[i]),
        WiFi.channel(order[i]), WiFi.BSSIDstr(order[i]).c_str());
      first = false;
    }
  }
  ResponseAppend_P(PSTR("]%s}}"), (count < 0) ? PSTR(",\"Error\":\"Failed\"") : PSTR(""));
  MqttPublishPrefixTopicRulesProcess_P(RESULT_OR_STAT, PSTR("StaScan"));
}

static void StaCtrlScanCheck(void) {
  int16_t count = WiFi.scanComplete();
  if (WIFI_SCAN_RUNNING == count) {
    if (!TimeReached(StaCtrl.started + STA_CTRL_SCAN_TIMEOUT_MS)) { return; }
    count = WIFI_SCAN_FAILED;
  }
  StaCtrl.state = STA_CTRL_IDLE;
  StaCtrlScanReport(count);
  if (!Wifi.scan_state) { WiFi.scanDelete(); }   // Tasmota's own scan may have started on these results
  StaCtrlGiveRadio(STA_CTRL_LINGER_MS);
}

/*********************************************************************************************\
 * Join
\*********************************************************************************************/

// A join, for StaJoin and for another driver that holds credentials it never
// hands to a command line, as ESP-NOW direct does with the network its peer gave
// it. The result goes to the rules as StaJoin's.
enum StaCtrlJoinResults { STA_JOIN_STARTED, STA_JOIN_BUSY, STA_JOIN_INVALID };

uint32_t StaCtrlJoin(const char* ssid, const char* password, uint32_t channel, const uint8_t* bssid) {
  if (StaCtrlBusy()) { return STA_JOIN_BUSY; }
  size_t ssid_len = strlen(ssid);
  size_t password_len = strlen(password);
  // A WPA passphrase has 8 to 63 characters, or is 64 hexadecimal digits; an
  // open network has none.
  if (!ssid_len || (ssid_len > 32) || (password_len && (password_len < 8)) || (password_len > 64) || (channel > 14)) {
    return STA_JOIN_INVALID;
  }
  strlcpy(StaCtrl.ssid, ssid, sizeof(StaCtrl.ssid));
  strlcpy(StaCtrl.password, password, sizeof(StaCtrl.password));

  StaCtrlTakeRadio();
  // What Tasmota's own WifiBegin() sets up, so the station it adopts is the one
  // it would have made
  WiFi.persistent(false);
#ifdef USE_IPV6
  WiFi.enableIPv6(true);
#endif
  WiFiSetSleepMode();
  WifiSetOutputPower();
  WiFiHelper::setPhyMode(WiFiPhyMode_t((Wifi.phy_mode > 0) ? Wifi.phy_mode : 4));
  if (Settings->ipv4_address[0]) {
    WiFi.config(Settings->ipv4_address[0], Settings->ipv4_address[1], Settings->ipv4_address[2],
                Settings->ipv4_address[3], Settings->ipv4_address[4]);
  }
  WiFi.hostname(TasmotaGlobal.hostname);
  // One attempt, and the stack's single retry: a failure is then final, and the
  // reason it gives is the one reported
  WiFi.setAutoReconnect(false);

  StaCtrl.associated = 0;
  StaCtrl.last_disconnect = 0;
  StaCtrl.disconnects = 0;
  StaCtrl.reason = 0;
  StaCtrl.got_address = false;
  StaCtrl.started = millis();
  StaCtrl.state = STA_CTRL_JOINING;
  WiFiHelper::begin(StaCtrl.ssid, password_len ? StaCtrl.password : nullptr, bssid ? channel : 0, bssid);
  AddLog(LOG_LEVEL_INFO, PSTR("STA: Joining %s"), StaCtrl.ssid);
  return STA_JOIN_STARTED;
}

void CmndStaJoin(void) {
  if (StaCtrlBusy()) {
    ResponseCmndChar_P(PSTR("Busy"));
    return;
  }
  JsonParser parser(XdrvMailbox.data);
  JsonParserObject root = parser.getRootObject();
  if (!root) {
    ResponseCmndError();
    return;
  }
  uint8_t bssid[6];
  unsigned int octet[6] = { 0 };
  bool use_bssid = (6 == sscanf(root.getStr(PSTR("BSSId"), ""), "%x:%x:%x:%x:%x:%x",
                                &octet[0], &octet[1], &octet[2], &octet[3], &octet[4], &octet[5]));
  for (uint32_t i = 0; i < 6; i++) {
    if (octet[i] > 255) { use_bssid = false; }
    bssid[i] = octet[i];
  }
  uint32_t result = StaCtrlJoin(root.getStr(PSTR("SSId"), ""), root.getStr(PSTR("Password"), ""),
                                root.getUInt(PSTR("Channel"), 0), use_bssid ? bssid : nullptr);
  ResponseCmndChar_P((STA_JOIN_STARTED == result) ? PSTR("Joining") : (STA_JOIN_BUSY == result) ? PSTR("Busy") : PSTR("Error"));
}

static void StaCtrlJoinReport(bool connected, const char* why) {
  if (connected) {
    Response_P(PSTR("{\"StaJoin\":{\"State\":\"Connected\",\"SSId\":\"%s\",\"IP\":\"%s\"}}"),
      EscapeJSONString(StaCtrl.ssid).c_str(), WiFi.localIP().toString().c_str());
  } else {
    Response_P(PSTR("{\"StaJoin\":{\"State\":\"Failed\",\"SSId\":\"%s\",\"Reason\":\"%s\",\"Code\":%d}}"),
      EscapeJSONString(StaCtrl.ssid).c_str(), why, StaCtrl.reason);
  }
  MqttPublishPrefixTopicRulesProcess_P(RESULT_OR_STAT, PSTR("StaJoin"));
}

static void StaCtrlJoinDone(void) {
  SettingsUpdateText(SET_STASSID1, StaCtrl.ssid);
  SettingsUpdateText(SET_STAPWD1, StaCtrl.password);
  SettingsUpdateText(SET_APBSSID1, "");     // a BSSID set for the network before would pin the new one to it
  Settings->sta_active = 0;
  SettingsSave(0);
  StaCtrlClearSecret();
  WiFi.setAutoReconnect(true);             // as Tasmota's own join leaves it
  StaCtrl.state = STA_CTRL_IDLE;
  StaCtrl.restore = false;
  StaCtrl.borrowed = false;
  AddLog(LOG_LEVEL_INFO, PSTR("STA: Joined %s, saved as SSId1"), StaCtrl.ssid);
  StaCtrlJoinReport(true, nullptr);
  // Handed over connected: Tasmota's next check finds the station up and
  // adopts it, with no reconnection
  Settings->flag4.network_wifi = 1;
  WifiConnect();
}

static void StaCtrlJoinFail(const char* why) {
  WiFi.disconnect();
  StaCtrlClearSecret();
  WiFi.setAutoReconnect(true);
  StaCtrl.state = STA_CTRL_IDLE;
  AddLog(LOG_LEVEL_INFO, PSTR("STA: Joining %s failed, %s (%d)"), StaCtrl.ssid, why, StaCtrl.reason);
  StaCtrlJoinReport(false, why);
  StaCtrlGiveRadio(STA_CTRL_LINGER_MS);
}

static void StaCtrlJoinCheck(void) {
  if (StaCtrl.got_address && (WL_CONNECTED == WiFi.status())) {
    StaCtrlJoinDone();
    return;
  }
  // The stack retries once after the first failure: the second is final, and so
  // is a first one it did not follow with another attempt
  if (StaCtrl.disconnects >= 2 ||
      (StaCtrl.disconnects && !StaCtrl.associated && TimeReached(StaCtrl.last_disconnect + STA_CTRL_RETRY_GRACE_MS))) {
    StaCtrlJoinFail(StaCtrlReasonText(StaCtrl.reason));
    return;
  }
  if (StaCtrl.associated && TimeReached(StaCtrl.associated + STA_CTRL_ADDRESS_TIMEOUT_MS)) {
    StaCtrlJoinFail(PSTR("NoAddress"));
    return;
  }
  if (TimeReached(StaCtrl.started + STA_CTRL_JOIN_TIMEOUT_MS)) {
    StaCtrlJoinFail(StaCtrl.associated ? PSTR("NoAddress") : StaCtrl.reason ? StaCtrlReasonText(StaCtrl.reason) : PSTR("NoAnswer"));
  }
}

/*********************************************************************************************\
 * Hotspot
\*********************************************************************************************/

// The hotspot is up: Tasmota's reconnection keeps it (support_wifi.ino, WifiBegin),
// and its pages take requests made to its address (xdrv_01_9_webserver.ino)
bool StaCtrlHotspotUp(void) {
  return StaCtrl.hotspot;
}

// Up with no network beside it: an upgrade is refused, since it runs from the
// safeboot, which has no hotspot to come back on
bool StaCtrlHotspotAlone(void) {
  return StaCtrl.hotspot && !StaCtrlTasmotaUp();
}

static void StaCtrlHotspotReport(void) {
  if (StaCtrl.hotspot) {
    Response_P(PSTR("{\"StaHotspot\":{\"State\":\"Up\",\"SSId\":\"%s\",\"Channel\":%d,\"IP\":\"%s\",\"Clients\":%d}}"),
      EscapeJSONString(StaCtrl.hotspot_ssid).c_str(), WiFi.channel(), WiFi.softAPIP().toString().c_str(), StaCtrl.hotspot_clients);
  } else {
    Response_P(PSTR("{\"StaHotspot\":{\"State\":\"Off\"}}"));
  }
}

// WPA2, beside the station, on the channel the radio is on: the station's when it
// is connected, and where ESP-NOW or a held radio left it otherwise
static bool StaCtrlHotspotStart(const char* ssid, const char* password) {
  if (Wifi.config_type) { return false; }  // the WiFi Manager's own access point is up
  size_t ssid_len = strlen(ssid);
  size_t password_len = strlen(password);
  if (!ssid_len || (ssid_len > 32) || (password_len < 8) || (password_len > 63)) { return false; }
  WifiSetMode(WIFI_AP_STA);
  int32_t channel = WiFi.channel();
  if ((channel < 1) || (channel > 13)) { channel = 1; }
  if (!WiFi.softAP(ssid, password, channel, 0, STA_CTRL_HOTSPOT_CLIENTS)) {
    if (!StaCtrl.hotspot) { WifiSetMode(StaCtrlTasmotaUp() || StaCtrl.hold || StaCtrl.claimed || StaCtrl.borrowed ? WIFI_STA : WIFI_OFF); }
    return false;
  }
  strlcpy(StaCtrl.hotspot_ssid, ssid, sizeof(StaCtrl.hotspot_ssid));
  StaCtrl.hotspot = true;
  StaCtrl.hotspot_clients = 0;
  StaCtrl.hotspot_quiet = millis();
#ifdef USE_WEBSERVER
  // with no network, the web server never came up
  if (Settings->webserver) { StartWebserver(Settings->webserver); }
#endif  // USE_WEBSERVER
  AddLog(LOG_LEVEL_INFO, PSTR("STA: Hotspot %s up on channel %d"), StaCtrl.hotspot_ssid, channel);
  StaCtrlHotspotReport();
  MqttPublishPrefixTopicRulesProcess_P(RESULT_OR_STAT, PSTR("StaHotspot"));
  return true;
}

// The access point down, and the station as whoever needs it left it. The WiFi
// Manager's own, which takes the same interface over, is left alone
static void StaCtrlHotspotStop(const char* why) {
  if (!StaCtrl.hotspot) { return; }
  StaCtrl.hotspot = false;
  StaCtrl.hotspot_clients = 0;
  if ((WiFi.getMode() & WIFI_MODE_AP) && !Wifi.config_type) {
    WiFi.softAPdisconnect(true);
    WifiSetMode(StaCtrlTasmotaUp() || StaCtrl.hold || StaCtrl.claimed || StaCtrl.borrowed || Settings->flag4.network_wifi ? WIFI_STA : WIFI_OFF);
  }
  AddLog(LOG_LEVEL_INFO, PSTR("STA: Hotspot %s closed, %s"), StaCtrl.hotspot_ssid, why);
  Response_P(PSTR("{\"StaHotspot\":{\"State\":\"Off\",\"Reason\":\"%s\"}}"), why);
  MqttPublishPrefixTopicRulesProcess_P(RESULT_OR_STAT, PSTR("StaHotspot"));
}

// Every 250 ms while it is up: the phones on it, and its time with none
static void StaCtrlHotspotCheck(void) {
  if (!StaCtrl.hotspot) { return; }
  if (Wifi.config_type) {
    StaCtrlHotspotStop(PSTR("WifiManager"));
    return;
  }
  if (!(WiFi.getMode() & WIFI_MODE_AP)) {  // something took the radio down under it
    StaCtrlHotspotStop(PSTR("Lost"));
    return;
  }
  uint8_t clients = WiFi.softAPgetStationNum();
  if (clients != StaCtrl.hotspot_clients) {
    StaCtrl.hotspot_clients = clients;
    StaCtrlHotspotReport();
    MqttPublishPrefixTopicRulesProcess_P(RESULT_OR_STAT, PSTR("StaHotspot"));
  }
  if (clients) {
    StaCtrl.hotspot_quiet = millis();
  } else if (TimeReached(StaCtrl.hotspot_quiet + STA_CTRL_HOTSPOT_IDLE_MS)) {
    StaCtrlHotspotStop(PSTR("Idle"));
  }
}

void CmndStaHotspot(void) {
  if (XdrvMailbox.data_len && ('{' == XdrvMailbox.data[0])) {
    JsonParser parser(XdrvMailbox.data);
    JsonParserObject root = parser.getRootObject();
    bool started = false;
    if (!!root) { started = StaCtrlHotspotStart(root.getStr(PSTR("SSId"), ""), root.getStr(PSTR("Password"), "")); }
    // the command's buffer held the password: parsed in place, and wiped
    memset(XdrvMailbox.data, 0, XdrvMailbox.data_len);
    if (!started) {
      ResponseCmndChar_P(Wifi.config_type ? PSTR("Busy") : PSTR("Error"));
      return;
    }
  } else if (XdrvMailbox.data_len && (0 == XdrvMailbox.payload)) {
    StaCtrlHotspotStop(PSTR("Stop"));
  }
  StaCtrlHotspotReport();
}

/*********************************************************************************************\
 * Forget, hold and state
\*********************************************************************************************/

void CmndStaForget(void) {
  if (STA_CTRL_IDLE != StaCtrl.state) {
    ResponseCmndChar_P(PSTR("Busy"));
    return;
  }
  if (Settings->flag4.network_wifi) {
    Settings->flag4.network_wifi = 0;
    WifiDisable();
  }
  StaCtrl.restore = false;                 // a pause gives the WiFi back off: it has no network to go to
  SettingsUpdateText(SET_STASSID1, "");
  SettingsUpdateText(SET_STAPWD1, "");
  SettingsUpdateText(SET_APBSSID1, "");
  Settings->sta_active = 0;
  Settings->wifi_channel = 0;
  memset(Settings->wifi_bssid, 0, sizeof(Settings->wifi_bssid));
  SettingsSave(0);
  StaCtrl.reason = 0;
  AddLog(LOG_LEVEL_INFO, PSTR("STA: SSId1 forgotten"));
  ResponseCmndDone();
}

void CmndStaHold(void) {
  if ((XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 1)) {
    StaCtrl.hold = XdrvMailbox.payload;
    if (STA_CTRL_IDLE == StaCtrl.state && !Settings->flag4.network_wifi) {
      if (StaCtrl.hold) {
        WifiSetMode(WIFI_STA);
        WiFi.disconnect();
      } else if (!StaCtrl.borrowed) {
        WifiSetMode(WIFI_OFF);
      }
    }
  }
  ResponseCmndStateText(StaCtrl.hold);
}

void CmndStaState(void) {
  const char* state = (STA_CTRL_SCANNING == StaCtrl.state) ? PSTR("Scanning") :
                      (STA_CTRL_JOINING == StaCtrl.state) ? PSTR("Joining") : PSTR("Idle");
  Response_P(PSTR("{\"StaState\":{\"State\":\"%s\",\"Hold\":%d,\"Radio\":%d,\"Owner\":\"%s\",\"Reason\":\"%s\",\"Code\":%d}}"),
    state, StaCtrl.hold, (WIFI_OFF != WiFi.getMode()), StaCtrlRadioOwnerText(StaCtrlRadioOwner()),
    StaCtrlReasonText(StaCtrl.reason), StaCtrl.reason);
}

const char kStaCtrlCommands[] PROGMEM = "Sta|"
  "Scan|Join|Forget|Hold|State|Hotspot";
void (* const kStaCtrlCommand[])(void) PROGMEM = {
  &CmndStaScan, &CmndStaJoin, &CmndStaForget, &CmndStaHold, &CmndStaState, &CmndStaHotspot };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv96(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_INIT:
      WiFi.onEvent(StaCtrlEvent);
      break;
    case FUNC_EVERY_250_MSECOND:
      StaCtrlHotspotCheck();
      if (STA_CTRL_SCANNING == StaCtrl.state) {
        StaCtrlScanCheck();
      } else if (STA_CTRL_JOINING == StaCtrl.state) {
        StaCtrlJoinCheck();
      } else {
        StaCtrlKeepRadio();
      }
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kStaCtrlCommands, kStaCtrlCommand);
      break;
  }
  return result;
}

#endif  // USE_WIFI_STATION_CONTROL
#endif  // ESP32
