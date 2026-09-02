/*
  xdrv_98_espnow_direct_poc.ino - PoCs 1 e 4 do modo de transporte `direct`
  (ver docs/15.1-esp-now.md do repo Casa Inteligente)

  Descartável de propósito. PoC 1: link ESP-NOW básico funciona entre os
  dois devices reais (NSPanel e ZBBridge Pro), medindo RTT real via
  ping/pong. PoC 4: rejeição de mensagem forjada, via tag FNV-1a com
  segredo compartilhado hardcoded (NÃO é a escolha de produção — ver
  comentário perto de `kEspNowPocSecret` abaixo). Sem fallback de canal
  fixo (PoC 3, separado), sem produção nenhuma.

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

// PoC 4 (docs/15.1-esp-now.md): rejeição de mensagem forjada — QuickESPNow
// não autentica nada por padrão (achado real na revisão adversarial de
// docs/15-transporte-direct.md §3.2: peer.encrypt=false hardcoded na lib,
// qualquer MAC pode mandar payload que "parece" válido). Aqui: hash
// simples (FNV-1a) com segredo compartilhado, anexado ao payload como
// tag — suficiente pra PROVAR que a rejeição funciona, NÃO é a escolha
// final de produção. Fase 2 (arquitetura refinada) precisa de HMAC-SHA256
// de verdade (mbedtls, já disponível no core) e de um fluxo real de
// pareamento pra gerar/trocar o segredo — aqui é hardcoded só pro PoC.
static const uint8_t kEspNowPocSecret[] = {0x43, 0x61, 0x73, 0x61, 0x49, 0x6E, 0x74, 0x65}; // "CasaInte" - PoC apenas

static uint32_t EspNowPocTag(const uint8_t* data, size_t len) {
  uint32_t hash = 0x811C9DC5;  // FNV-1a offset basis
  for (size_t i = 0; i < sizeof(kEspNowPocSecret); i++) {
    hash ^= kEspNowPocSecret[i];
    hash *= 0x01000193;
  }
  for (size_t i = 0; i < len; i++) {
    hash ^= data[i];
    hash *= 0x01000193;
  }
  return hash;
}

struct {
  bool active = false;        // ESP-NOW is currently running
  bool enabled = false;       // runtime gate, see CmndEspNowPocEnable below
  bool stop_latched = false;  // stop() ran in this boot, a restart is required before starting again
  const uint8_t* peer_mac = nullptr;
} EspNowPoc;

// Monta payload assinado: "<corpo>|<8 hex do tag FNV-1a>". Separado do
// envio em si pra poder reusar tanto no caminho normal quanto no de
// teste de rejeição (CmndEspNowPocForge, abaixo).
static size_t EspNowPocSign(char* out, size_t out_size, const char* body) {
  uint32_t tag = EspNowPocTag((const uint8_t*)body, strlen(body));
  return snprintf(out, out_size, "%s|%08X", body, tag);
}

// Verifica a assinatura de uma mensagem recebida (formato "<corpo>|<tag>").
// Retorna true e preenche `body_out` (sem a parte da assinatura) só se
// bater — mensagem sem "|", com tag errado, ou forjada é rejeitada aqui,
// nunca chega no processamento de ping/pong abaixo. Ver PoC 4 em
// docs/15.1-esp-now.md.
static bool EspNowPocVerify(const char* buf, char* body_out, size_t body_out_size) {
  const char* sep = strrchr(buf, '|');
  if (!sep) { return false; }
  size_t body_len = sep - buf;
  if (body_len >= body_out_size) { return false; }
  memcpy(body_out, buf, body_len);
  body_out[body_len] = '\0';
  uint32_t expected_tag = EspNowPocTag((const uint8_t*)body_out, body_len);
  uint32_t received_tag = strtoul(sep + 1, nullptr, 16);
  return (expected_tag == received_tag);
}

void EspNowPocDataRcvd(uint8_t* address, uint8_t* data, uint8_t len, signed int rssi, bool broadcast) {
  if (len < 6) { return; }
  char buf[80];
  uint8_t n = (len < sizeof(buf) - 1) ? len : sizeof(buf) - 1;
  memcpy(buf, data, n);
  buf[n] = '\0';

  char body[64];
  if (!EspNowPocVerify(buf, body, sizeof(body))) {
    AddLog(LOG_LEVEL_ERROR, PSTR("NOWPOC: mensagem REJEITADA (assinatura inválida ou ausente): %s"), buf);
    return;
  }

  if (0 == strncmp(body, "#ping:", 6)) {
    // eco imediato — mede RTT contra o próprio relógio de quem mandou,
    // mesmo espírito do #ping/#pong já usado no transporte tcp
    // (ver berry/zigbee_bridge.be, zbbridge_relay.be)
    char pong_body[32];
    snprintf(pong_body, sizeof(pong_body), "#pong:%s", body + 6);
    char pong[64];
    size_t pong_len = EspNowPocSign(pong, sizeof(pong), pong_body);
    quickEspNow.send(EspNowPoc.peer_mac, (const uint8_t*)pong, pong_len);
    AddLog(LOG_LEVEL_INFO, PSTR("NOWPOC: ping recebido (rssi %d), pong enviado"), rssi);
  }
  else if (0 == strncmp(body, "#pong:", 6)) {
    uint32_t sent_ms = strtoul(body + 6, nullptr, 10);
    uint32_t rtt = TimeDifference(sent_ms, millis());
    AddLog(LOG_LEVEL_INFO, PSTR("NOWPOC: pong recebido, RTT=%u ms (rssi %d)"), rtt, rssi);
  }
}

// Chamado de FUNC_EVERY_SECOND, NÃO de FUNC_INIT — achado ao revisar o
// driver antes de flashar (2026-09-01): FUNC_INIT roda cedo demais no
// boot, mesma classe de bug que já derrubou o tcpserver() do modo tcp
// mais cedo nesta sessão (chamar API de rede antes do WiFi/lwIP estar
// pronto). `xdrv_77_wizmote.ino` (mesma lib QuickESPNow) evita isso do
// mesmo jeito: só chama `quickEspNow.begin()` quando
// `!TasmotaGlobal.global_state.wifi_down` (idiom estabelecido do
// próprio Tasmota pra "WiFi está de pé", ver support_wifi.ino). Guard
// `EspNowPoc.active` evita rechamar begin() a cada segundo depois que
// já iniciou.
void EspNowPocInit(void) {
  if (!EspNowPoc.enabled) { return; }  // off until requested, see CmndEspNowPocEnable
  if (EspNowPoc.active) { return; }
  if (TasmotaGlobal.global_state.wifi_down) { return; }  // WiFi ainda não subiu — espera o próximo tick

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

// Shuts the radio down. Kept separate from the command handler so the
// stop path stays callable from anywhere in the driver.
static void EspNowPocStop(void) {
  if (!EspNowPoc.active) { return; }
  quickEspNow.stop();
  EspNowPoc.active = false;
  EspNowPoc.stop_latched = true;
  AddLog(LOG_LEVEL_INFO, PSTR("NOWPOC: stopped, restart required to start again"));
}

// Console command: `EspNowPocEnable 1` starts ESP-NOW, `EspNowPocEnable 0`
// stops it, no payload reports the current state.
//
// ESP-NOW shares the radio with the WiFi station interface. While it runs
// with a peer installed for another station associated to the same access
// point, unicast traffic between those two stations breaks: TCP connects
// are reset on every port in both directions and ICMP becomes unreliable,
// while traffic to any other host (gateway, other stations) is unaffected.
// Defaulting to off means a build carrying this driver behaves exactly
// like a build without it until the feature is explicitly asked for.
//
// Starting again after a stop is deliberately refused. QuickEspNow::stop()
// calls esp_now_deinit() but leaves its own peer list populated, so the
// next send() reaches addPeer(), takes the "peer already exists" branch and
// runs ESP_ERROR_CHECK(esp_now_get_peer(...)) against an emptied driver
// peer table. That aborts the firmware rather than returning an error, so
// a reboot is the only way to bring both lists back in sync.
void CmndEspNowPocEnable(void) {
  if ((XdrvMailbox.payload >= 0) && (XdrvMailbox.payload <= 1)) {
    if (XdrvMailbox.payload) {
      if (EspNowPoc.stop_latched) {
        ResponseCmndChar_P(PSTR("restart required"));
        return;
      }
      EspNowPoc.enabled = true;  // actual start happens on the next FUNC_EVERY_SECOND tick
    } else {
      EspNowPoc.enabled = false;
      EspNowPocStop();
    }
  }
  ResponseCmndStateText(EspNowPoc.active);
}

// comando de console: `EspNowPocPing` manda um ping ASSINADO pro peer
// conhecido (mesmo padrão do `ZbBridgePing` já usado no transporte tcp,
// ver berry/zigbee_bridge.be) — resposta chega assíncrona, log mostra
// o RTT (só se a assinatura do pong bater, ver EspNowPocVerify acima).
void CmndEspNowPocPing(void) {
  if (!EspNowPoc.active) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  char body[32];
  snprintf(body, sizeof(body), "#ping:%u", millis());
  char payload[64];
  size_t payload_len = EspNowPocSign(payload, sizeof(payload), body);
  quickEspNow.send(EspNowPoc.peer_mac, (const uint8_t*)payload, payload_len);
  ResponseCmndChar_P(PSTR("sent"));
}

// comando de teste do PoC 4 (docs/15.1-esp-now.md): manda um ping com
// assinatura DELIBERADAMENTE ERRADA — sem um terceiro ESP32 disponível
// pra simular um atacante de verdade (MAC genuinamente diferente), isso
// valida a LÓGICA de rejeição (EspNowPocVerify) sem precisar de
// hardware extra. Sucesso esperado: o peer loga "REJEITADA" e nunca
// processa como ping de verdade (sem pong de volta).
void CmndEspNowPocForge(void) {
  if (!EspNowPoc.active) {
    ResponseCmndChar_P(PSTR("not active"));
    return;
  }
  char payload[48];
  snprintf(payload, sizeof(payload), "#ping:%u|DEADBEEF", millis());  // tag propositalmente errado
  quickEspNow.send(EspNowPoc.peer_mac, (const uint8_t*)payload, strlen(payload));
  ResponseCmndChar_P(PSTR("forged sent"));
}

// "|" inicial = sem prefixo compartilhado (idiom estabelecido em todo
// o codebase Tasmota pra driver com comando único/lista plana — achado
// revisando xdrv_01_9_webserver.ino/xdrv_02_9_mqtt.ino depois do
// comando dar "Unknown" no teste real, sem o "|" o parser de prefixo
// do DecodeCommand() interpretava a string inteira como prefixo em vez
// de nome de comando).
const char kEspNowPocCommands[] PROGMEM = "|" "EspNowPocEnable|EspNowPocPing|EspNowPocForge";
void (* const kEspNowPocCommand[])(void) PROGMEM = { &CmndEspNowPocEnable, &CmndEspNowPocPing, &CmndEspNowPocForge };

bool Xdrv98(uint32_t function) {
  bool result = false;
  switch (function) {
    case FUNC_EVERY_SECOND:
      EspNowPocInit();
      break;
    case FUNC_COMMAND:
      result = DecodeCommand(kEspNowPocCommands, kEspNowPocCommand);
      break;
  }
  return result;
}

#endif  // USE_ESPNOW_DIRECT_POC
