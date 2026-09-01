/*
  xdrv_98_espnow_direct_poc.ino - PoC 1 do modo de transporte `direct`
  (ver docs/15.1-esp-now.md do repo Casa Inteligente)

  Descartável de propósito: só responde UMA pergunta — o link ESP-NOW
  básico funciona entre os dois devices reais (NSPanel e ZBBridge Pro),
  medindo RTT real via ping/pong. Sem pairing/segurança (isso é o PoC 4,
  separado), sem fallback de canal fixo (PoC 3), sem produção nenhuma.

  Patch aplicado seguindo a regra de docs/10-firmware-decisoes.md §5:
  arquivo novo autocontido, atrás de uma única flag USE_ESPNOW_DIRECT_POC,
  ponto de gancho mínimo em tasmota_xx2c_global/xdrv_interface.ino (só
  registro do XDRV_98 na lista de drivers, inevitável — é como todo
  driver Tasmota se registra, ver xdrv_77_wizmote.ino como referência).
*/
#ifdef USE_ESPNOW_DIRECT_POC

#define XDRV_98                       98

#include <QuickEspNow.h>

// MAC dos dois devices reais (Casa Inteligente, 2026-09-01) — lidos via
// `Status 5` no console de cada um. Mesmo binário roda nos dois; em
// runtime compara com o próprio MAC pra decidir quem é o peer.
static const uint8_t kEspNowPocMacNSPanel[6]    = {0xA0, 0xA3, 0xB3, 0x88, 0xB1, 0x98};
static const uint8_t kEspNowPocMacZBBridgePro[6] = {0xD4, 0xE9, 0xF4, 0xF3, 0x0C, 0x8C};

struct {
  bool active = false;
  const uint8_t* peer_mac = nullptr;
} EspNowPoc;

void EspNowPocDataRcvd(uint8_t* address, uint8_t* data, uint8_t len, signed int rssi, bool broadcast) {
  if (len < 6) { return; }
  char buf[64];
  uint8_t n = (len < sizeof(buf) - 1) ? len : sizeof(buf) - 1;
  memcpy(buf, data, n);
  buf[n] = '\0';

  if (0 == strncmp(buf, "#ping:", 6)) {
    // eco imediato — mede RTT contra o próprio relógio de quem mandou,
    // mesmo espírito do #ping/#pong já usado no transporte tcp
    // (ver berry/zigbee_bridge.be, zbbridge_relay.be)
    char pong[64];
    snprintf(pong, sizeof(pong), "#pong:%s", buf + 6);
    quickEspNow.send(EspNowPoc.peer_mac, (const uint8_t*)pong, strlen(pong));
    AddLog(LOG_LEVEL_INFO, PSTR("NOWPOC: ping recebido (rssi %d), pong enviado"), rssi);
  }
  else if (0 == strncmp(buf, "#pong:", 6)) {
    uint32_t sent_ms = strtoul(buf + 6, nullptr, 10);
    uint32_t rtt = TimeDifference(sent_ms, millis());
    AddLog(LOG_LEVEL_INFO, PSTR("NOWPOC: pong recebido, RTT=%u ms (rssi %d)"), rtt, rssi);
  }
}

void EspNowPocInit(void) {
  WiFi.macAddress().length();  // no-op, garante WiFi já inicializado antes de ler o MAC abaixo
  uint8_t self_mac[6];
  WiFi.macAddress(self_mac);
  EspNowPoc.peer_mac = (0 == memcmp(self_mac, kEspNowPocMacNSPanel, 6))
    ? kEspNowPocMacZBBridgePro
    : kEspNowPocMacNSPanel;

  // sem canal explícito = segue o canal atual da STA (PoC 1 só testa
  // com WiFi normal conectado; fallback de canal fixo é o PoC 3,
  // separado, ver docs/15.1-esp-now.md)
  if (quickEspNow.begin()) {
    quickEspNow.onDataRcvd(EspNowPocDataRcvd);
    EspNowPoc.active = true;
    AddLog(LOG_LEVEL_INFO, PSTR("NOWPOC: iniciado, peer %02X:%02X:%02X:%02X:%02X:%02X"),
      EspNowPoc.peer_mac[0], EspNowPoc.peer_mac[1], EspNowPoc.peer_mac[2],
      EspNowPoc.peer_mac[3], EspNowPoc.peer_mac[4], EspNowPoc.peer_mac[5]);
  } else {
    AddLog(LOG_LEVEL_ERROR, PSTR("NOWPOC: falha ao iniciar quickEspNow"));
  }
}

// comando de console: `EspNowPocPing` manda um ping pro peer conhecido
// (mesmo padrão do `ZbBridgePing` já usado no transporte tcp, ver
// berry/zigbee_bridge.be) — resposta chega assíncrona, log mostra o RTT
void CmndEspNowPocPing(void) {
  if (!EspNowPoc.active) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  char payload[32];
  snprintf(payload, sizeof(payload), "#ping:%u", millis());
  quickEspNow.send(EspNowPoc.peer_mac, (const uint8_t*)payload, strlen(payload));
  ResponseCmndChar_P(PSTR("sent"));
}

const char kEspNowPocCommands[] PROGMEM = "EspNowPocPing";
void (* const kEspNowPocCommand[])(void) PROGMEM = { &CmndEspNowPocPing };

bool Xdrv98(uint32_t function) {
  bool result = false;
  switch (function) {
    case FUNC_INIT:
      EspNowPocInit();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowPocCommands, kEspNowPocCommand);
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_DIRECT_POC
