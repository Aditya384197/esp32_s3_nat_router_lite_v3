#pragma once
#include "esp_http_server.h"
#ifdef __cplusplus
extern "C" {
#endif
httpd_handle_t start_webserver(uint16_t port);
void captive_portal_start(void);
void captive_portal_stop(void);
#ifdef __cplusplus
}
#endif
