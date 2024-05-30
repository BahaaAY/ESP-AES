/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "sdkconfig.h"
#include <inttypes.h>
#include <mbedtls/gcm.h>
#include <stdio.h>
#include <string.h>

// Function to initialize a random key
int generate_random_key(unsigned char *key, size_t key_size) {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *personalization = "MyEntropy";
  int ret;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  // Seed and setup entropy source for DRBG
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)personalization,
                              strlen(personalization));
  if (ret != 0) {
    printf("Failed in mbedtls_ctr_drbg_seed: %d\n", ret);
    return ret;
  }

  // Generate a random key
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_size);
  if (ret != 0) {
    printf("Failed in mbedtls_ctr_drbg_random: %d\n", ret);
    return ret;
  }

  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  return 0;
}

// Function to print bytes for debugging
void print_hex(const char *label, unsigned char *buff, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) {
    printf("%02X ", buff[i]);
  }
  printf("\n");
}
void app_main(void) {

  mbedtls_gcm_context gcm;
  unsigned char key[32];
  unsigned char nonce[12];
  unsigned char input[64];
  unsigned char output[128];
  unsigned char decrypted[128];
  unsigned char tag[16];
  int ret;
  int i = 0;

  while (1) {
    i++; // Increment counter for each iteration
    sprintf((char *)input, "Hello World %d", i);
    // Initialize GCM context
    mbedtls_gcm_init(&gcm);

    // Generate a random key
    if (generate_random_key(key, sizeof(key)) != 0) {
      printf("Key generation failed\n");
    } else {
      printf("Key generation success\n");

      // Initialize random nonce
      generate_random_key(nonce,
                          sizeof(nonce)); // Nonce should be unique per
                                          // encryption Set up the key
      ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
      if (ret != 0) {
        printf("Failed in mbedtls_gcm_setkey: %d\n", ret);

      } else {
        printf("Key set success\n");

        // Encrypt the data
        ret = mbedtls_gcm_crypt_and_tag(
            &gcm, MBEDTLS_GCM_ENCRYPT, sizeof(input), nonce, sizeof(nonce),
            NULL, 0, input, output, sizeof(tag), tag);
        if (ret != 0) {
          printf("Failed in mbedtls_gcm_crypt_and_tag: %d\n", ret);

        } else {
          printf("Encryption success\n");
          // Decrypt the data
          ret = mbedtls_gcm_auth_decrypt(&gcm, sizeof(input), nonce,
                                         sizeof(nonce), NULL, 0, tag,
                                         sizeof(tag), output, decrypted);
          if (ret != 0) {
            printf("Failed in mbedtls_gcm_auth_decrypt: %d\n", ret);

          } else {
            printf("Decryption success\n");
            // Output results
            print_hex("Key", key, sizeof(key));
            print_hex("Nonce", nonce, sizeof(nonce));
            print_hex("Tag", tag, sizeof(tag));
            printf("Original: %s\n", input);
            printf("Encrypted: ");
            print_hex("", output, sizeof(input));
            printf("Decrypted: %s\n", decrypted);

            // Free GCM context
            mbedtls_gcm_free(&gcm);
          }
        }
      }
    }
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}
