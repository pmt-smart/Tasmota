/*
  xdrv_98_6_espnow_ota_display.ino - the ESP-NOW OTA receiver's page on a Nextion display

  Copyright (C) 2026  HouseWeave

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
#ifdef USE_ESPNOW_OTA_RECEIVER
#ifdef USE_ESPNOW_OTA_DISPLAY
/*********************************************************************************************\
 * The safeboot image of a device with a Nextion display (a Sonoff NSPanel) shows on it what the ESP-NOW OTA receiver
 * (xdrv_98_5) is doing, on a page of the display's project named "safeboot" whose components are, in this order:
 *   t0 the title and t1 the device's name;
 *   t2 the percentage, t3 an empty Text in whose box and font colour the bar is drawn, t4 to t7 lines, t8 a warning;
 *   qCode9 a QR code, and t10 and t11 its two lines;
 *   bRow12 and bRow13, two Buttons, which report a tap as the frame 55 BB len(2) "ev,safeboot,<name>,tap" crc(2),
 *   with a CRC-16/MODBUS over what precedes it.
 * The page announces itself with the frame "ev,safeboot,page,show" when it loads. A display whose project has no such
 * page says nothing, and is left as it was.
 *
 * Three views:
 *   updating  while an image comes: no button shown, so no touch does anything; the percentage and its bar, the block, who
 *             sends, the time left, and a warning to keep the power on;
 *   waiting   no image under way, or none for ESPNOW_OTA_DISPLAY_STALL_S: Open hotspot, which starts the WiFi Manager's
 *             access point, and Restart, which boots the app when the app partition holds a whole image and this image
 *             again when it does not;
 *   hotspot   the WiFi Manager's access point is up: its network as a QR code and in words, and its address; Close hotspot
 *             restarts this image, and Restart is as above.
 * Only what changed is written. The bar is drawn with fill, in the colours of t3's font (the bar) and of bRow12's face
 * (its track), which the display is asked for once the page is up.
 *
 * The display is a device's only when its template is ESPNOW_OTA_DISPLAY_TEMPLATE: the same image runs on devices whose
 * serial pins belong to something else.
\*********************************************************************************************/

#define XDRV_105                       105

#ifndef ESPNOW_OTA_DISPLAY_TEMPLATE
#define ESPNOW_OTA_DISPLAY_TEMPLATE    "NSPanel"
#endif
#ifndef ESPNOW_OTA_DISPLAY_RX
#define ESPNOW_OTA_DISPLAY_RX          17
#endif
#ifndef ESPNOW_OTA_DISPLAY_TX
#define ESPNOW_OTA_DISPLAY_TX          16
#endif
#define ESPNOW_OTA_DISPLAY_BAUD        115200
#define ESPNOW_OTA_DISPLAY_STALL_S     60         // an image with no piece for this long is shown as paused, with the buttons
#define ESPNOW_OTA_DISPLAY_PAGE_TRIES  5          // a page asked for every second this many times, before the display is taken for one without it
#define ESPNOW_OTA_DISPLAY_ANSWER_MS   300
#define ESPNOW_OTA_DISPLAY_RX_MAX      96
#define ESPNOW_OTA_DISPLAY_TEXT_MAX    40         // the bytes a text of the page is given at most: the least its Texts hold
#define ESPNOW_OTA_DISPLAY_CODE_MAX    64         // and the QR code

enum EspNowOtaView : uint8_t { kOtaViewNone = 0, kOtaViewUpdating, kOtaViewWaiting, kOtaViewHotspot };
enum EspNowOtaSlot : uint8_t {
  kSlotTitle, kSlotNode, kSlotPercent, kSlotBar, kSlotLine0, kSlotLine1, kSlotLine2, kSlotLine3, kSlotWarn,
  kSlotCode, kSlotNetwork, kSlotAddress, kSlotButton0, kSlotButton1, kSlotCount
};
static const char *const EspNowOtaSlotName[kSlotCount] = {
  "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "qCode9", "t10", "t11", "bRow12", "bRow13"
};
enum EspNowOtaAsk : uint8_t { kAskBarX, kAskBarY, kAskBarW, kAskBarH, kAskBarColour, kAskTrackColour, kAskCount };
static const char *const EspNowOtaAskWhat[kAskCount] = { "t3.x", "t3.y", "t3.w", "t3.h", "t3.pco", "bRow12.bco" };

struct {
  HardwareSerial *serial = nullptr;
  uint8_t rx[ESPNOW_OTA_DISPLAY_RX_MAX];
  uint8_t rx_len = 0;
  uint8_t tries = 0;                         // the times the page was asked for
  uint8_t ask = kAskCount;                   // the attribute asked for, kAskCount when none
  uint32_t ask_ms = 0;
  int32_t answer[kAskCount];
  uint32_t text_hash[kSlotCount];            // what each slot was last given, 0 for not known
  uint16_t vis_known = 0;                    // the slots whose visibility was written since the page loaded
  uint16_t vis_on = 0;
  int32_t bar_fill = -1;                     // the bar's width last drawn, -1 for not drawn
  uint8_t view = kOtaViewNone;
  bool enabled = false;                      // this device's template has the display
  bool absent = false;                       // the display has no such page
  bool page = false;                         // the page is up
  bool has_bar = false;                      // the bar's box and colours are known
} EspNowOtaDisplay;

/*********************************************************************************************/

static uint16_t EspNowOtaDisplayCrc(const uint8_t *data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (uint32_t bit = 0; bit < 8; bit++) { crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : crc >> 1; }
  }
  return crc;
}

static uint32_t EspNowOtaDisplayHash(const char *text) {
  uint32_t hash = 2166136261u;               // FNV-1a, and never 0, which means not known
  while (*text) { hash = (hash ^ (uint8_t)*text++) * 16777619u; }
  return hash ? hash : 1;
}

static void EspNowOtaDisplaySend(const char *command) {
  EspNowOtaDisplay.serial->write((const uint8_t *)command, strlen(command));
  static const uint8_t end[3] = { 0xFF, 0xFF, 0xFF };
  EspNowOtaDisplay.serial->write(end, sizeof(end));
}

static void EspNowOtaDisplayText(uint32_t slot, const char *text) {
  uint32_t hash = EspNowOtaDisplayHash(text);
  if (EspNowOtaDisplay.text_hash[slot] == hash) { return; }
  EspNowOtaDisplay.text_hash[slot] = hash;
  char command[96];
  int n = snprintf_P(command, sizeof(command), PSTR("%s.txt=\""), EspNowOtaSlotName[slot]);
  int room = n + ((kSlotCode == slot) ? ESPNOW_OTA_DISPLAY_CODE_MAX : ESPNOW_OTA_DISPLAY_TEXT_MAX);
  for (const char *p = text; *p && (n < room) && (n < (int)sizeof(command) - 2); p++) {
    command[n++] = ('"' == *p) ? '\'' : *p;  // a quote would end the string
  }
  command[n++] = '"';
  command[n] = '\0';
  EspNowOtaDisplaySend(command);
}

static void EspNowOtaDisplayVis(uint32_t slot, bool on) {
  uint16_t bit = 1 << slot;
  if ((EspNowOtaDisplay.vis_known & bit) && (((EspNowOtaDisplay.vis_on & bit) != 0) == on)) { return; }
  EspNowOtaDisplay.vis_known |= bit;
  if (on) { EspNowOtaDisplay.vis_on |= bit; } else { EspNowOtaDisplay.vis_on &= ~bit; }
  char command[24];
  snprintf_P(command, sizeof(command), PSTR("vis %s,%d"), EspNowOtaSlotName[slot], on);
  EspNowOtaDisplaySend(command);
  if (kSlotBar == slot) { EspNowOtaDisplay.bar_fill = -1; }  // shown again, the Text paints its box over the bar
}

static void EspNowOtaDisplayForget(void) {
  memset(EspNowOtaDisplay.text_hash, 0, sizeof(EspNowOtaDisplay.text_hash));
  EspNowOtaDisplay.vis_known = 0;
  EspNowOtaDisplay.bar_fill = -1;
  EspNowOtaDisplay.view = kOtaViewNone;
}

/*********************************************************************************************/

// The bar, in the percent of the image taken
static void EspNowOtaDisplayBar(uint32_t percent) {
  if (!EspNowOtaDisplay.has_bar) { return; }
  const int32_t *a = EspNowOtaDisplay.answer;
  int32_t fill = a[kAskBarW] * (int32_t)percent / 100;
  if (fill == EspNowOtaDisplay.bar_fill) { return; }
  char command[48];
  if ((EspNowOtaDisplay.bar_fill < 0) || (fill < EspNowOtaDisplay.bar_fill)) {
    snprintf_P(command, sizeof(command), PSTR("fill %d,%d,%d,%d,%d"), a[kAskBarX], a[kAskBarY], a[kAskBarW], a[kAskBarH], a[kAskTrackColour]);
    EspNowOtaDisplaySend(command);
  }
  if (fill > 0) {
    snprintf_P(command, sizeof(command), PSTR("fill %d,%d,%d,%d,%d"), a[kAskBarX], a[kAskBarY], fill, a[kAskBarH], a[kAskBarColour]);
    EspNowOtaDisplaySend(command);
  }
  EspNowOtaDisplay.bar_fill = fill;
}

static void EspNowOtaDisplayShow(const uint8_t *slots, size_t count, uint16_t on) {
  for (uint32_t i = 0; i < count; i++) { if (!(on & (1 << slots[i]))) { EspNowOtaDisplayVis(slots[i], false); } }
  for (uint32_t i = 0; i < count; i++) { if (on & (1 << slots[i])) { EspNowOtaDisplayVis(slots[i], true); } }
}

static uint8_t EspNowOtaDisplayViewNow(void) {
  if (WIFI_MANAGER == Wifi.config_type) { return kOtaViewHotspot; }
  uint8_t state = EspNowOta.state;
  if ((kOtaChecking == state) || (kOtaDone == state)) { return kOtaViewUpdating; }
  if ((kOtaReceiving == state) && ((millis() - EspNowOta.last_piece_ms) < ESPNOW_OTA_DISPLAY_STALL_S * 1000)) { return kOtaViewUpdating; }
  return kOtaViewWaiting;
}

// The percent of the image taken: the blocks written, and the part of the next one received
static uint32_t EspNowOtaDisplayPercent(void) {
  uint32_t blocks = EspNowOtaBlocks();
  if (!EspNowOta.has_manifest || !blocks) { return 0; }
  if (EspNowOta.block >= blocks) { return 100; }
  uint32_t part = EspNowOta.length ? (EspNowOta.got * 100 / EspNowOta.length) : 0;
  return (EspNowOta.block * 100 + part) / blocks;
}

static void EspNowOtaDisplayRender(void) {
  static const uint8_t all[] = { kSlotPercent, kSlotBar, kSlotLine0, kSlotLine1, kSlotLine2, kSlotLine3, kSlotWarn,
                                 kSlotCode, kSlotNetwork, kSlotAddress, kSlotButton0, kSlotButton1 };
  uint8_t view = EspNowOtaDisplayViewNow();
  char text[64];
  const char *name = SettingsText(SET_FRIENDLYNAME1);
  if (EspNowOta.node) {
    snprintf_P(text, sizeof(text), PSTR("%s, node %u"), name, EspNowOta.node);
  } else {
    snprintf_P(text, sizeof(text), PSTR("%s"), name);
  }
  EspNowOtaDisplayText(kSlotNode, text);
  uint32_t percent = EspNowOtaDisplayPercent();

  if (kOtaViewUpdating == view) {
    EspNowOtaDisplayShow(all, sizeof(all), (1 << kSlotPercent) | (1 << kSlotBar) | (1 << kSlotLine0) | (1 << kSlotLine1) |
                                           (1 << kSlotLine2) | (1 << kSlotLine3) | (1 << kSlotWarn));
    uint8_t state = EspNowOta.state;
    EspNowOtaDisplayText(kSlotTitle, (kOtaDone == state) ? "Firmware written" : (kOtaChecking == state) ? "Checking firmware" : "Updating firmware");
    snprintf_P(text, sizeof(text), PSTR("%u%%"), percent);
    EspNowOtaDisplayText(kSlotPercent, text);
    if (kOtaDone == state) {
      EspNowOtaDisplayText(kSlotLine0, "Restarting");
      EspNowOtaDisplayText(kSlotLine1, "");
      EspNowOtaDisplayText(kSlotLine2, "");
    } else if (kOtaChecking == state) {
      EspNowOtaDisplayText(kSlotLine0, "Reading it back");
      EspNowOtaDisplayText(kSlotLine1, "");
      EspNowOtaDisplayText(kSlotLine2, "");
    } else {
      uint32_t blocks = EspNowOtaBlocks();
      snprintf_P(text, sizeof(text), PSTR("Block %u of %u"), (EspNowOta.block < blocks) ? EspNowOta.block + 1 : blocks, blocks);
      EspNowOtaDisplayText(kSlotLine0, text);
      if (EspNowOta.sender_name[0]) {
        snprintf_P(text, sizeof(text), PSTR("From %s"), EspNowOta.sender_name);
      } else {
        snprintf_P(text, sizeof(text), PSTR("From node %u"), EspNowOta.sender_node);
      }
      EspNowOtaDisplayText(kSlotLine1, text);
      // the time left, from the pace since the sender offered: none until a block has come
      text[0] = '\0';
      uint32_t elapsed = millis() - EspNowOta.since_ms;
      uint32_t done = (EspNowOta.block - EspNowOta.since_block) * 100 + (EspNowOta.length ? EspNowOta.got * 100 / EspNowOta.length : 0);
      if ((EspNowOta.block > EspNowOta.since_block) && done) {
        uint32_t left = blocks * 100 - (EspNowOta.block * 100 + (EspNowOta.length ? EspNowOta.got * 100 / EspNowOta.length : 0));
        uint32_t minutes = (uint32_t)(((uint64_t)elapsed * left / done + 59999) / 60000);
        if (minutes <= 1) {
          snprintf_P(text, sizeof(text), PSTR("About a minute left"));
        } else {
          snprintf_P(text, sizeof(text), PSTR("About %u min left"), minutes);
        }
      }
      EspNowOtaDisplayText(kSlotLine2, text);
    }
    EspNowOtaDisplayText(kSlotLine3, "");
    EspNowOtaDisplayText(kSlotWarn, "Keep the power on");
    EspNowOtaDisplayBar(percent);

  } else if (kOtaViewWaiting == view) {
    EspNowOtaDisplayShow(all, sizeof(all), (1 << kSlotLine0) | (1 << kSlotLine1) | (1 << kSlotLine2) | (1 << kSlotButton0) | (1 << kSlotButton1));
    EspNowOtaDisplayText(kSlotTitle, "Safeboot");
    if (kOtaFailed == EspNowOta.state) {
      EspNowOtaDisplayText(kSlotLine0, "The update failed.");
      EspNowOtaDisplayText(kSlotLine1, "The mesh can send it again.");
    } else if (EspNowOta.has_manifest) {
      snprintf_P(text, sizeof(text), PSTR("Update paused at %u%%."), percent);
      EspNowOtaDisplayText(kSlotLine0, text);
      EspNowOtaDisplayText(kSlotLine1, "The mesh can resume it.");
    } else {
      EspNowOtaDisplayText(kSlotLine0, "Waiting for its firmware.");
      EspNowOtaDisplayText(kSlotLine1, "The mesh can send it.");
    }
    EspNowOtaDisplayText(kSlotLine2, "");
    EspNowOtaDisplayText(kSlotButton0, "Open hotspot");
    EspNowOtaDisplayText(kSlotButton1, "Restart");

  } else {
    EspNowOtaDisplayShow(all, sizeof(all), (1 << kSlotCode) | (1 << kSlotNetwork) | (1 << kSlotAddress) | (1 << kSlotButton0) | (1 << kSlotButton1));
    EspNowOtaDisplayText(kSlotTitle, "Hotspot open");
    // an open network: WIFI:T:nopass;S:<ssid>;; with \ ; , : and " escaped in the name
    int n = snprintf_P(text, sizeof(text), PSTR("WIFI:T:nopass;S:"));
    for (const char *p = TasmotaGlobal.hostname; *p && (n < (int)sizeof(text) - 4); p++) {
      if (strchr("\\;,:\"", *p)) { text[n++] = '\\'; }
      text[n++] = *p;
    }
    snprintf_P(text + n, sizeof(text) - n, PSTR(";;"));
    EspNowOtaDisplayText(kSlotCode, text);
    EspNowOtaDisplayText(kSlotNetwork, TasmotaGlobal.hostname);
    EspNowOtaDisplayText(kSlotAddress, "Open 192.168.4.1");
    EspNowOtaDisplayText(kSlotButton0, "Close hotspot");
    EspNowOtaDisplayText(kSlotButton1, "Restart");
  }
  EspNowOtaDisplay.view = view;
}

/*********************************************************************************************/

// Restart: the app, when its partition holds a whole image, which the boot loader checks; this image again otherwise
static void EspNowOtaDisplayRestart(void) {
  const esp_partition_t *app = esp_ota_get_next_update_partition(nullptr);
  bool to_app = app && (ESP_OK == esp_ota_set_boot_partition(app));
  AddLog(LOG_LEVEL_INFO, PSTR("EOT: Restart asked on the display, into %s"), to_app ? PSTR("the app") : PSTR("the safeboot"));
  TasmotaGlobal.restart_flag = 2;
}

static void EspNowOtaDisplayFrame(const char *payload) {
  if (!strcmp_P(payload, PSTR("ev,safeboot,page,show"))) {
    if (!EspNowOtaDisplay.page) { AddLog(LOG_LEVEL_INFO, PSTR("EOT: Display page up")); }
    EspNowOtaDisplay.page = true;
    EspNowOtaDisplayForget();
    EspNowOtaDisplay.has_bar = false;
    EspNowOtaDisplay.ask = kAskBarX;          // the bar's box and colours, asked for one at a time
    EspNowOtaDisplay.ask_ms = 0;
    return;
  }
  uint8_t view = EspNowOtaDisplay.view;
  if ((kOtaViewWaiting != view) && (kOtaViewHotspot != view)) { return; }  // no button is shown while the image comes
  if (!strcmp_P(payload, PSTR("ev,safeboot,bRow12,tap"))) {
    if (kOtaViewWaiting == view) {
      AddLog(LOG_LEVEL_INFO, PSTR("EOT: Hotspot asked on the display"));
      WifiConfig(WIFI_MANAGER);
    } else {
      AddLog(LOG_LEVEL_INFO, PSTR("EOT: Hotspot closed on the display"));
      TasmotaGlobal.restart_flag = 2;
    }
  } else if (!strcmp_P(payload, PSTR("ev,safeboot,bRow13,tap"))) {
    EspNowOtaDisplayRestart();
  }
}

// What the display says: a frame of the page (55 BB), or an answer that ends in FF FF FF, of which only a number counts
static void EspNowOtaDisplayRead(void) {
  uint8_t *rx = EspNowOtaDisplay.rx;
  while (EspNowOtaDisplay.serial->available()) {
    uint8_t b = EspNowOtaDisplay.serial->read();
    if (EspNowOtaDisplay.rx_len >= sizeof(EspNowOtaDisplay.rx)) { EspNowOtaDisplay.rx_len = 0; }
    rx[EspNowOtaDisplay.rx_len++] = b;
    uint32_t n = EspNowOtaDisplay.rx_len;
    if ((n >= 2) && (0x55 == rx[0]) && (0xBB == rx[1])) {
      if (n < 4) { continue; }
      uint32_t len = rx[2] | (rx[3] << 8);
      if (len > sizeof(EspNowOtaDisplay.rx) - 7) { EspNowOtaDisplay.rx_len = 0; continue; }
      if (n < 4 + len + 2) { continue; }
      if (EspNowOtaDisplayCrc(rx, 4 + len) == (rx[4 + len] | (rx[5 + len] << 8))) {
        char payload[ESPNOW_OTA_DISPLAY_RX_MAX];
        memcpy(payload, rx + 4, len);
        payload[len] = '\0';
        EspNowOtaDisplayFrame(payload);
      }
      EspNowOtaDisplay.rx_len = 0;
    } else if ((1 == n) && (0x55 == b)) {
      continue;                                // perhaps a frame
    } else if ((n >= 3) && (0xFF == rx[n - 1]) && (0xFF == rx[n - 2]) && (0xFF == rx[n - 3])) {
      if ((8 == n) && (0x71 == rx[0]) && (EspNowOtaDisplay.ask < kAskCount)) {
        EspNowOtaDisplay.answer[EspNowOtaDisplay.ask] = (int32_t)(rx[1] | (rx[2] << 8) | (rx[3] << 16) | ((uint32_t)rx[4] << 24));
        EspNowOtaDisplay.ask++;
        EspNowOtaDisplay.ask_ms = 0;
        if (kAskCount == EspNowOtaDisplay.ask) { EspNowOtaDisplay.has_bar = true; }
      }
      EspNowOtaDisplay.rx_len = 0;
    }
  }
}

/*********************************************************************************************/

static void EspNowOtaDisplayInit(void) {
  if (strcmp(SettingsText(SET_TEMPLATE_NAME), ESPNOW_OTA_DISPLAY_TEMPLATE)) { return; }
  EspNowOtaDisplay.serial = &Serial2;
  EspNowOtaDisplay.serial->begin(ESPNOW_OTA_DISPLAY_BAUD, SERIAL_8N1, ESPNOW_OTA_DISPLAY_RX, ESPNOW_OTA_DISPLAY_TX);
  EspNowOtaDisplay.enabled = true;
  static const uint8_t end[3] = { 0xFF, 0xFF, 0xFF };
  EspNowOtaDisplay.serial->write(end, sizeof(end));  // ends whatever the display was given before
  EspNowOtaDisplaySend(PSTR("sleep=0"));             // awake, and kept awake
  EspNowOtaDisplaySend(PSTR("thsp=0"));
  EspNowOtaDisplaySend(PSTR("ussp=0"));
}

static void EspNowOtaDisplayLoop(void) {
  if (!EspNowOtaDisplay.enabled) { return; }
  EspNowOtaDisplayRead();
  if (!EspNowOtaDisplay.page || (EspNowOtaDisplay.ask >= kAskCount)) { return; }
  // the bar's box and colours, one question at a time: a display that does not answer leaves the page without its bar
  uint32_t now = millis();
  if (EspNowOtaDisplay.ask_ms && (now - EspNowOtaDisplay.ask_ms < ESPNOW_OTA_DISPLAY_ANSWER_MS)) { return; }
  if (EspNowOtaDisplay.ask_ms) {
    AddLog(LOG_LEVEL_INFO, PSTR("EOT: Display did not say %s, no bar"), EspNowOtaAskWhat[EspNowOtaDisplay.ask]);
    EspNowOtaDisplay.ask = kAskCount;
    return;
  }
  char command[24];
  snprintf_P(command, sizeof(command), PSTR("get %s"), EspNowOtaAskWhat[EspNowOtaDisplay.ask]);
  EspNowOtaDisplaySend(command);
  EspNowOtaDisplay.ask_ms = now ? now : 1;
}

static void EspNowOtaDisplayEverySecond(void) {
  if (!EspNowOtaDisplay.enabled || EspNowOtaDisplay.absent) { return; }
  if (!EspNowOtaDisplay.page) {
    if (EspNowOtaDisplay.tries++ >= ESPNOW_OTA_DISPLAY_PAGE_TRIES) {
      EspNowOtaDisplay.absent = true;
      AddLog(LOG_LEVEL_INFO, PSTR("EOT: Display has no safeboot page"));
      return;
    }
    EspNowOtaDisplaySend(PSTR("page safeboot"));
    return;
  }
  if (EspNowOtaDisplay.ask < kAskCount) { return; }  // the bar's colours first
  EspNowOtaDisplayRender();
}

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv105(uint32_t function) {
  switch (function) {
    case FUNC_LOOP:
      EspNowOtaDisplayLoop();
      break;
    case FUNC_EVERY_SECOND:
      EspNowOtaDisplayEverySecond();
      break;
    case FUNC_INIT:
      EspNowOtaDisplayInit();
      break;
    case FUNC_ACTIVE:
      return true;
  }
  return false;
}

#endif  // USE_ESPNOW_OTA_DISPLAY
#endif  // USE_ESPNOW_OTA_RECEIVER
#endif  // ESP32
