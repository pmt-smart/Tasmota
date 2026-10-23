/*
  xdrv_97_button_decouple.ino - Relay buttons with a decoupled tap and a guarded hold

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
#ifdef USE_BUTTON_DECOUPLE
/*********************************************************************************************\
 * Takes over every button that has a relay of the same number, replacing the
 * generic multi-press handling with two gestures:
 *
 *   tap   coupled (the default): toggles the relay the moment the button goes
 *         down, without waiting to see whether a second press follows.
 *         decoupled: reported on release as {"Button<x>":{"Action":"SINGLE"}},
 *         at most once per BUTTON_DECOUPLE_TAP_GAP_MS, and the relay stays as
 *         it is. With nothing listening to the report, a tap does nothing.
 *   hold  decoupled: held for BUTTON_DECOUPLE_HOLD_MS, one beep and the relay
 *         toggles. A hold within BUTTON_DECOUPLE_GUARD_MS of the last toggle it
 *         made gets a refusal beep instead, and the relay does not change.
 *         Holding on after the beep does nothing more. Coupled, the relay has
 *         already toggled on the way down, so a hold adds nothing.
 *
 * The hold works without rules, scripts or Berry: it is the way to switch the
 * relay whatever the rest of the device is doing. The guard exists for relays
 * that power smart bulbs, many of which factory reset after a sequence of quick
 * power cycles.
 *
 * Multi-press relay switching, the long-press reset and the WiFi manager are
 * not available on these buttons: no sequence of presses on them reaches
 * another relay or the device settings.
 *
 * Nothing changes until the driver is enabled: a device that carries it
 * behaves as one without it, and the generic handling keeps every button. Once
 * enabled it stays so across restarts, since a hold that works only after the
 * scripting has started would not be the fallback it is meant to be.
 *
 * Settings live in their own NVS namespace rather than in the global settings
 * struct, so the driver stays self-contained and carries its own versioning.
 *
 * Inert: while a device installs something that must not be interrupted, as a
 * display being flashed, every button with a relay does nothing, neither the tap
 * nor the hold, whether the driver is enabled or not. It is not saved: a restart
 * ends it, and the generic handling or this driver has the buttons again.
 *
 * Commands:
 *   ButtonDecoupleEnable 0|1  - take the buttons over, or give them back to the
 *                               generic handling; bare, reports the state
 *   ButtonDecoupleInert 0|1   - 1 makes every button with a relay do nothing until
 *                               0 or a restart; bare, reports the state
 *   ButtonDecouple<x> 0|1     - 1 reports button <x>'s tap instead of toggling
 *                               relay <x>; bare, reports the current value
 *   ButtonDecouple            - the value of every button with a relay, as a list
\*********************************************************************************************/

#define XDRV_97                      97

#ifndef BUTTON_DECOUPLE_HOLD_MS
#define BUTTON_DECOUPLE_HOLD_MS      4000
#endif
#ifndef BUTTON_DECOUPLE_GUARD_MS
#define BUTTON_DECOUPLE_GUARD_MS     15000
#endif
#ifndef BUTTON_DECOUPLE_TAP_GAP_MS
#define BUTTON_DECOUPLE_TAP_GAP_MS   1000
#endif

#define BUTTON_DECOUPLE_NVS_NAMESPACE "btn_decouple"
#define BUTTON_DECOUPLE_VERSION      2
#define BUTTON_DECOUPLE_MAX          8

struct BUTTON_DECOUPLE_SETTINGS {
  uint8_t version;
  uint8_t enabled;                   // the buttons are this driver's
  uint8_t decoupled;                 // bit n: the tap of button n+1 is reported, not acted on
} ButtonDecoupleSettings = { BUTTON_DECOUPLE_VERSION, 0, 0 };

struct BUTTON_DECOUPLE {
  uint32_t pressed_at[BUTTON_DECOUPLE_MAX];
  uint32_t toggled_at[BUTTON_DECOUPLE_MAX];
  uint32_t tapped_at[BUTTON_DECOUPLE_MAX];
  uint8_t pressed;                   // bit n: button n+1 is down
  uint8_t held;                      // bit n: this press has become a hold
  uint8_t toggled;                   // bit n: a hold has toggled relay n+1 since boot
  uint8_t tapped;                    // bit n: button n+1 has reported a tap since boot
  bool inert;                        // no button with a relay does anything, until a restart
} ButtonDecouple;

void ButtonDecoupleSettingsLoad(void) {
  // NvmLoad() returns true as soon as the namespace opens, even when there is no
  // blob to read, and then leaves the buffer as it was: version 0 is never ours
  BUTTON_DECOUPLE_SETTINGS loaded = { 0, 0, 0 };
  if (NvmLoad(BUTTON_DECOUPLE_NVS_NAMESPACE, "settings", &loaded, sizeof(loaded)) &&
      (BUTTON_DECOUPLE_VERSION == loaded.version)) {
    ButtonDecoupleSettings = loaded;
  }
}

void ButtonDecoupleSettingsSave(void) {
  NvmSave(BUTTON_DECOUPLE_NVS_NAMESPACE, "settings", &ButtonDecoupleSettings, sizeof(ButtonDecoupleSettings));
}

void ButtonDecoupleBeep(uint32_t count) {
#ifdef USE_BUZZER
  BuzzerBeep(count);
#endif
}

// A hold on a decoupled button: the relay, unless it toggled too recently.
void ButtonDecoupleHold(uint32_t index, uint32_t now) {
  uint32_t mask = 1 << index;
  uint32_t since = now - ButtonDecouple.toggled_at[index];
  if ((ButtonDecouple.toggled & mask) && (since < BUTTON_DECOUPLE_GUARD_MS)) {
    ButtonDecoupleBeep(3);
    AddLog(LOG_LEVEL_INFO, PSTR("BTN: Button%d hold refused, relay toggled %u ms ago"), index +1, since);
    return;
  }
  ButtonDecoupleBeep(1);
  ButtonDecouple.toggled |= mask;
  ButtonDecouple.toggled_at[index] = now;
  AddLog(LOG_LEVEL_DEBUG, PSTR("BTN: Button%d hold toggles relay %d"), index +1, index +1);
  ExecuteCommandPower(index +1, POWER_TOGGLE, SRC_BUTTON);
}

// A tap on a decoupled button: reported the way SetOption73 reports one.
void ButtonDecoupleTap(uint32_t index, uint32_t now) {
  uint32_t mask = 1 << index;
  if ((ButtonDecouple.tapped & mask) && ((now - ButtonDecouple.tapped_at[index]) < BUTTON_DECOUPLE_TAP_GAP_MS)) {
    return;
  }
  ButtonDecouple.tapped |= mask;
  ButtonDecouple.tapped_at[index] = now;
  char scommand[10];
  snprintf_P(scommand, sizeof(scommand), PSTR(D_JSON_BUTTON "%d"), index +1);
  Response_P(S_JSON_SVALUE_ACTION_SVALUE, scommand, "SINGLE");
  MqttPublishPrefixTopicRulesProcess_P(RESULT_OR_STAT, scommand);
}

// Called on every button scan. True takes the button away from the generic handling.
bool ButtonDecouplePressed(void) {
  uint32_t index = XdrvMailbox.index;
  if (!ButtonDecoupleSettings.enabled && !ButtonDecouple.inert) { return false; }
  if ((index >= BUTTON_DECOUPLE_MAX) || (index >= TasmotaGlobal.devices_present)) {
    return false;                    // no relay of its own: the generic handling keeps it
  }
  if (ButtonDecouple.inert) {
    // taken, and nothing done: a press that started before ends as nothing too
    ButtonDecouple.pressed &= ~(1 << index);
    return true;
  }
  uint32_t mask = 1 << index;
  bool down = (PRESSED == XdrvMailbox.payload);
  bool decoupled = ButtonDecoupleSettings.decoupled & mask;
  uint32_t now = millis();

  if (down && !(ButtonDecouple.pressed & mask)) {
    ButtonDecouple.pressed |= mask;
    ButtonDecouple.held &= ~mask;
    ButtonDecouple.pressed_at[index] = now;
    if (!decoupled) {
      ExecuteCommandPower(index +1, POWER_TOGGLE, SRC_BUTTON);
    }
  } else if (down) {
    if (decoupled && !(ButtonDecouple.held & mask) &&
        ((now - ButtonDecouple.pressed_at[index]) >= BUTTON_DECOUPLE_HOLD_MS)) {
      ButtonDecouple.held |= mask;
      ButtonDecoupleHold(index, now);
    }
  } else if (ButtonDecouple.pressed & mask) {
    ButtonDecouple.pressed &= ~mask;
    if (decoupled && !(ButtonDecouple.held & mask)) {
      ButtonDecoupleTap(index, now);
    }
  }
  return true;
}

/*********************************************************************************************\
 * Commands
\*********************************************************************************************/

void CmndButtonDecouple(void) {
  uint32_t buttons = TasmotaGlobal.devices_present;
  if (buttons > BUTTON_DECOUPLE_MAX) { buttons = BUTTON_DECOUPLE_MAX; }
  if (0 == XdrvMailbox.usridx) {
    Response_P(PSTR("{\"%s\":["), XdrvMailbox.command);
    for (uint32_t i = 0; i < buttons; i++) {
      ResponseAppend_P(PSTR("%s%d"), (i) ? "," : "", bitRead(ButtonDecoupleSettings.decoupled, i));
    }
    ResponseAppend_P(PSTR("]}"));
    return;
  }
  if ((XdrvMailbox.index < 1) || (XdrvMailbox.index > buttons)) {
    ResponseCmndError();
    return;
  }
  uint32_t index = XdrvMailbox.index -1;
  if ((XdrvMailbox.payload == 0) || (XdrvMailbox.payload == 1)) {
    if (bitRead(ButtonDecoupleSettings.decoupled, index) != XdrvMailbox.payload) {
      bitWrite(ButtonDecoupleSettings.decoupled, index, XdrvMailbox.payload);
      ButtonDecoupleSettingsSave();
    }
    // a press in progress under the old value finishes as nothing
    ButtonDecouple.held |= (1 << index);
  }
  ResponseCmndIdxNumber(bitRead(ButtonDecoupleSettings.decoupled, index));
}

void CmndButtonDecoupleEnable(void) {
  if ((XdrvMailbox.payload == 0) || (XdrvMailbox.payload == 1)) {
    if (ButtonDecoupleSettings.enabled != XdrvMailbox.payload) {
      ButtonDecoupleSettings.enabled = XdrvMailbox.payload;
      ButtonDecoupleSettingsSave();
      // presses under the other owner finish as nothing
      ButtonDecouple.pressed = 0;
    }
  }
  ResponseCmndStateText(ButtonDecoupleSettings.enabled);
}

void CmndButtonDecoupleInert(void) {
  if ((XdrvMailbox.payload == 0) || (XdrvMailbox.payload == 1)) {
    ButtonDecouple.inert = XdrvMailbox.payload;
    // presses under either state finish as nothing
    ButtonDecouple.pressed = 0;
    ButtonDecouple.held = 0xFF;
  }
  ResponseCmndStateText(ButtonDecouple.inert);
}

// Leading "|" marks a flat command list without a shared prefix.
const char kButtonDecoupleCommands[] PROGMEM = "|" "ButtonDecouple|ButtonDecoupleEnable|ButtonDecoupleInert";
void (* const kButtonDecoupleCommand[])(void) PROGMEM = { &CmndButtonDecouple, &CmndButtonDecoupleEnable, &CmndButtonDecoupleInert };

/*********************************************************************************************\
 * Interface
\*********************************************************************************************/

bool Xdrv97(uint32_t function) {
  bool result = false;

  switch (function) {
    case FUNC_PRE_INIT:
      ButtonDecoupleSettingsLoad();
      break;
    case FUNC_BUTTON_PRESSED:
      result = ButtonDecouplePressed();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kButtonDecoupleCommands, kButtonDecoupleCommand);
      break;
  }
  return result;
}

#endif  // USE_BUTTON_DECOUPLE
#endif  // ESP32
