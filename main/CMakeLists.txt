idf_component_register(
    SRCS "esp32_nat_router.c" "netif_hooks.c" "wifi_config.c"
    INCLUDE_DIRS "." "../include"
    PRIV_REQUIRES esp_wifi esp_netif esp_event nvs_flash esp_http_server lwip http_server esp_timer app_update
)

target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -fstack-protector-strong)
