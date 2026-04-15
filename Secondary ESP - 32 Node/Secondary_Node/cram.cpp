#include "cram.h"
#include "mbedtls/md.h"

// Shared secret key (must match Node B)
static const uint8_t shared_key[16] = {
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC,
    0xDD, 0xEE, 0xFF, 0x10};

void cram_init()
{
    Serial.println("CRAM Initialized");
}

// Generate random nonce
void generate_nonce(uint8_t *nonce, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        nonce[i] = esp_random() & 0xFF;
    }
}

// Generate HMAC-SHA256
void generate_hmac(uint8_t *data, size_t len, uint8_t *output)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, shared_key, 16);
    mbedtls_md_hmac_update(&ctx, data, len);
    mbedtls_md_hmac_finish(&ctx, output);

    mbedtls_md_free(&ctx);
}

// Verify HMAC
bool verify_hmac(uint8_t *data, size_t len, uint8_t *received_hmac)
{
    uint8_t computed[32];
    generate_hmac(data, len, computed);

    return memcmp(computed, received_hmac, 32) == 0;
}

// Debug helper
void print_hex(uint8_t *data, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}