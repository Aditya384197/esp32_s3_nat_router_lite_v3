set(CERT_DIR "${CMAKE_CURRENT_LIST_DIR}/../../certs")
file(MAKE_DIRECTORY "${CERT_DIR}")
set(SERVER_CERT "${CERT_DIR}/server_cert.pem")
set(SERVER_KEY "${CERT_DIR}/server_key.pem")
if(NOT EXISTS "${SERVER_CERT}" OR NOT EXISTS "${SERVER_KEY}")
    find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
    execute_process(COMMAND "${OPENSSL_EXECUTABLE}" ecparam -name prime256v1 -genkey -noout -out "${SERVER_KEY}" RESULT_VARIABLE RC1)
    if(NOT RC1 EQUAL 0)
        message(FATAL_ERROR "Failed to generate HTTPS private key")
    endif()
    execute_process(COMMAND "${OPENSSL_EXECUTABLE}" req -new -x509 -sha256 -days 825 -key "${SERVER_KEY}" -out "${SERVER_CERT}" -subj "/CN=ESP32-S3-NAT-Router" -addext "subjectAltName=IP:192.168.4.1,DNS:router.local" RESULT_VARIABLE RC2)
    if(NOT RC2 EQUAL 0)
        message(FATAL_ERROR "Failed to generate HTTPS certificate")
    endif()
endif()

idf_component_register(
    SRCS "http_server.c"
    INCLUDE_DIRS "include" "../../include"
    PRIV_REQUIRES esp_https_server esp_http_server esp_wifi esp_netif lwip mbedtls esp_timer nvs_flash
    EMBED_TXTFILES "${SERVER_CERT}" "${SERVER_KEY}"
)

target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -fstack-protector-strong)
