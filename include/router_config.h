#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PARAM_NAMESPACE "esp32_nat"
#define DEFAULT_AP_IP "192.168.4.1"
#define DEFAULT_AP_SSID "ESP32_NAT_Router"
#define DEFAULT_AP_PASSWORD ""
#define AP_MAX_CONNECTIONS 8

extern uint64_t sta_bytes_sent;
extern uint64_t sta_bytes_received;
extern uint16_t connect_count;
extern bool ap_connect;
extern uint32_t my_ip;
extern uint32_t my_ap_ip;

uint64_t get_sta_bytes_sent(void);
uint64_t get_sta_bytes_received(void);
void init_byte_counter(void);
uint32_t get_uptime_seconds(void);
void format_uptime(uint32_t seconds, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif
