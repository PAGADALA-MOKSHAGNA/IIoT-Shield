#ifndef CRAM_H
#define CRAM_H

#include <Arduino.h>

// Initialize CRAM (optional)
void cram_init();

// Generate random nonce
void generate_nonce(uint8_t *nonce, size_t len);

// Generate HMAC-SHA256
void generate_hmac(uint8_t *data, size_t len, uint8_t *output);

// Verify HMAC
bool verify_hmac(uint8_t *data, size_t len, uint8_t *received_hmac);

// Debug print
void print_hex(uint8_t *data, size_t len);

#endif