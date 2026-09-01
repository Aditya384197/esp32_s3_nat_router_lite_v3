#include <stdint.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "router_config.h"

extern esp_netif_t *wifiSTA;

static struct netif *sta_netif = NULL;
static netif_input_fn original_input = NULL;
static netif_linkoutput_fn original_output = NULL;
static const char *TAG = "byte_counter";

/* sta_bytes_received/sent are deliberately NOT lock-protected: this is
 * the per-packet forwarding hot path, and each counter has exactly one
 * writer (input_hook writes only sta_bytes_received, output_hook writes
 * only sta_bytes_sent) so there is no writer/writer race. The HTTP
 * status page is the only reader; on a 32-bit core a 64-bit read can in
 * theory tear across a word boundary, but that only produces a
 * momentarily-wrong *display* number (self-corrects next poll) and only
 * near a 4 GiB rollover. Locking every forwarded packet to protect a
 * cosmetic counter would cost real throughput, so it is intentionally
 * left unsynchronized. */
static IRAM_ATTR err_t input_hook(struct pbuf *p, struct netif *netif)
{
    if (netif == sta_netif && p) {
        sta_bytes_received += p->tot_len;
    }
    return original_input ? original_input(p, netif) : ERR_VAL;
}

static IRAM_ATTR err_t output_hook(struct netif *netif, struct pbuf *p)
{
    if (netif == sta_netif && p) {
        sta_bytes_sent += p->tot_len;
    }
    return original_output ? original_output(netif, p) : ERR_IF;
}

void init_byte_counter(void)
{
    if (!wifiSTA || original_input) return;

    extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
    sta_netif = esp_netif_get_netif_impl(wifiSTA);
    if (!sta_netif) return;

    original_input = sta_netif->input;
    original_output = sta_netif->linkoutput;
    sta_netif->input = input_hook;
    sta_netif->linkoutput = output_hook;
    ESP_LOGI(TAG, "STA byte counters enabled");
}

uint64_t get_sta_bytes_sent(void)
{
    return sta_bytes_sent;
}

uint64_t get_sta_bytes_received(void)
{
    return sta_bytes_received;
}
