#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "router_config.h"
#include "wifi_config.h"

char *ssid = NULL;
char *passwd = NULL;
char *ap_ssid = NULL;
char *ap_passwd = NULL;
char *admin_user = NULL;
char *admin_pass = NULL;
char *admin_salt = NULL;
uint32_t admin_iters = 0;
static bool wifi_scan_active = false;

static const char *TAG = "wifi_config";
static SemaphoreHandle_t cfg_mutex = NULL;
static portMUX_TYPE scan_mux = portMUX_INITIALIZER_UNLOCKED;

void wifi_config_init(void)
{
    if (!cfg_mutex) {
        cfg_mutex = xSemaphoreCreateMutex();
    }
    ESP_ERROR_CHECK(cfg_mutex ? ESP_OK : ESP_ERR_NO_MEM);
}

void wifi_config_lock(void)
{
    configASSERT(cfg_mutex != NULL);
    (void)xSemaphoreTake(cfg_mutex, portMAX_DELAY);
}

void wifi_config_unlock(void)
{
    configASSERT(cfg_mutex != NULL);
    (void)xSemaphoreGive(cfg_mutex);
}

bool wifi_scan_try_begin(void)
{
    bool started = false;
    portENTER_CRITICAL(&scan_mux);
    if (!wifi_scan_active) {
        wifi_scan_active = true;
        started = true;
    }
    portEXIT_CRITICAL(&scan_mux);
    return started;
}

void wifi_scan_end(void)
{
    portENTER_CRITICAL(&scan_mux);
    wifi_scan_active = false;
    portEXIT_CRITICAL(&scan_mux);
}

bool wifi_scan_is_active(void)
{
    bool active;
    portENTER_CRITICAL(&scan_mux);
    active = wifi_scan_active;
    portEXIT_CRITICAL(&scan_mux);
    return active;
}

static char *dup_or_empty(const char *s)
{
    char *p = strdup(s ? s : "");
    if (!p) ESP_LOGE(TAG, "out of memory");
    return p;
}

static esp_err_t nvs_get_string(const char *key, char **value)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return err;

    size_t len = 0;
    err = nvs_get_str(nvs, key, NULL, &len);
    if (err == ESP_OK) {
        *value = malloc(len);
        if (!*value) {
            err = ESP_ERR_NO_MEM;
        } else {
            err = nvs_get_str(nvs, key, *value, &len);
            if (err != ESP_OK) {
                free(*value);
                *value = NULL;
            }
        }
    }
    nvs_close(nvs);
    return err;
}

static esp_err_t nvs_set_two_strings(const char *key1, const char *value1,
                                     const char *key2, const char *value2)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_set_str(nvs, key1, value1);
    if (err == ESP_OK) err = nvs_set_str(nvs, key2, value2);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t wifi_config_load(void)
{
    wifi_config_lock();
    wifi_config_free();

    if (nvs_get_string("ssid", &ssid) != ESP_OK) ssid = dup_or_empty("");
    if (nvs_get_string("passwd", &passwd) != ESP_OK) passwd = dup_or_empty("");
    if (nvs_get_string("ap_ssid", &ap_ssid) != ESP_OK) ap_ssid = dup_or_empty(DEFAULT_AP_SSID);
    if (nvs_get_string("ap_passwd", &ap_passwd) != ESP_OK) ap_passwd = dup_or_empty(DEFAULT_AP_PASSWORD);
    /* No default admin credentials are ever compiled in: an empty
     * admin_pass means "setup not completed yet" and is handled
     * explicitly by the HTTP layer (see wifi_config_admin_configured). */
    if (nvs_get_string("admin_user", &admin_user) != ESP_OK) admin_user = dup_or_empty("");
    if (nvs_get_string("admin_pass", &admin_pass) != ESP_OK) admin_pass = dup_or_empty("");
    if (nvs_get_string("admin_salt", &admin_salt) != ESP_OK) admin_salt = dup_or_empty("");
    {
        nvs_handle_t nvs;
        uint32_t iters = 0;
        if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
            if (nvs_get_u32(nvs, "admin_iters", &iters) != ESP_OK) iters = 0;
            nvs_close(nvs);
        }
        admin_iters = iters;
    }

    bool ok = ssid && passwd && ap_ssid && ap_passwd && admin_user && admin_pass && admin_salt;
    wifi_config_unlock();
    return ok ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t wifi_config_save_sta(const char *new_ssid, const char *new_passwd)
{
    if (!new_ssid || !new_passwd || strlen(new_ssid) == 0 || strlen(new_ssid) > 32 || strlen(new_passwd) > 63) {
        return ESP_ERR_INVALID_ARG;
    }

    char *s = dup_or_empty(new_ssid);
    char *p = dup_or_empty(new_passwd);
    if (!s || !p) {
        free(s);
        free(p);
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = nvs_set_two_strings("ssid", new_ssid, "passwd", new_passwd);
    if (err == ESP_OK) {
        wifi_config_lock();
        free(ssid);
        free(passwd);
        ssid = s;
        passwd = p;
        wifi_config_unlock();
    } else {
        free(s);
        free(p);
    }
    return err;
}

esp_err_t wifi_config_save_ap(const char *new_ssid, const char *new_passwd)
{
    if (!new_ssid || !new_passwd || strlen(new_ssid) == 0 || strlen(new_ssid) > 32 || strlen(new_passwd) > 63) {
        return ESP_ERR_INVALID_ARG;
    }
    if (new_passwd[0] && strlen(new_passwd) < 8) return ESP_ERR_INVALID_ARG;

    char *s = dup_or_empty(new_ssid);
    char *p = dup_or_empty(new_passwd);
    if (!s || !p) {
        free(s);
        free(p);
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = nvs_set_two_strings("ap_ssid", new_ssid, "ap_passwd", new_passwd);
    if (err == ESP_OK) {
        wifi_config_lock();
        free(ap_ssid);
        free(ap_passwd);
        ap_ssid = s;
        ap_passwd = p;
        wifi_config_unlock();
    } else {
        free(s);
        free(p);
    }
    return err;
}

esp_err_t wifi_config_save_admin_hash(const char *new_user, const char *salt_hex, const char *hash_hex, uint32_t iters)
{
    if (!new_user || !salt_hex || !hash_hex || strlen(new_user) == 0 || strlen(new_user) > 32 ||
        strlen(salt_hex) != 32 || strlen(hash_hex) != 64 || iters == 0) return ESP_ERR_INVALID_ARG;

    char *u = dup_or_empty(new_user);
    char *s = dup_or_empty(salt_hex);
    char *h = dup_or_empty(hash_hex);
    if (!u || !s || !h) {
        free(u); free(s); free(h);
        return ESP_ERR_NO_MEM;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) err = nvs_set_str(nvs, "admin_user", new_user);
    if (err == ESP_OK) err = nvs_set_str(nvs, "admin_salt", salt_hex);
    if (err == ESP_OK) err = nvs_set_str(nvs, "admin_pass", hash_hex);
    if (err == ESP_OK) err = nvs_set_u32(nvs, "admin_iters", iters);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);

    if (err == ESP_OK) {
        wifi_config_lock();
        free(admin_user); free(admin_salt); free(admin_pass);
        admin_user = u; admin_salt = s; admin_pass = h;
        admin_iters = iters;
        wifi_config_unlock();
    } else {
        free(u); free(s); free(h);
    }
    return err;
}

bool wifi_config_admin_configured(void)
{
    wifi_config_lock();
    bool configured = admin_pass && admin_pass[0] != '\0';
    wifi_config_unlock();
    return configured;
}

bool wifi_config_admin_hashed(void)
{
    wifi_config_lock();
    bool hashed = admin_pass && strlen(admin_pass) == 64 &&
                  admin_salt && strlen(admin_salt) == 32;
    wifi_config_unlock();
    return hashed;
}

esp_err_t wifi_config_apply_ap(void)
{
    wifi_config_t cfg = {0};
    wifi_config_lock();
    strlcpy((char *)cfg.ap.ssid, ap_ssid, sizeof(cfg.ap.ssid));
    strlcpy((char *)cfg.ap.password, ap_passwd, sizeof(cfg.ap.password));
    cfg.ap.ssid_len = strlen(ap_ssid);
    cfg.ap.authmode = ap_passwd[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    wifi_config_unlock();
    cfg.ap.channel = 1;
    cfg.ap.max_connection = AP_MAX_CONNECTIONS;
    cfg.ap.beacon_interval = 100;
    cfg.ap.pmf_cfg.required = false;
    return esp_wifi_set_config(WIFI_IF_AP, &cfg);
}

esp_err_t wifi_config_apply_sta(void)
{
    wifi_config_t cfg = {0};
    wifi_config_lock();
    strlcpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid));
    strlcpy((char *)cfg.sta.password, passwd, sizeof(cfg.sta.password));
    wifi_config_unlock();
    cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    cfg.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    cfg.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    return esp_wifi_set_config(WIFI_IF_STA, &cfg);
}

void wifi_config_free(void)
{
    free(ssid);
    free(passwd);
    free(ap_ssid);
    free(ap_passwd);
    free(admin_user);
    free(admin_pass);
    free(admin_salt);
    ssid = NULL;
    passwd = NULL;
    ap_ssid = NULL;
    ap_passwd = NULL;
    admin_user = NULL;
    admin_pass = NULL;
    admin_salt = NULL;
    admin_iters = 0;
}
