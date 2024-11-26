#ifndef GNSPA_H
#define GNSPA_H

#include <stdint.h>

#define MACHINE_ID_SIZE 36
#define OTP_SIZE 6
#define HMAC_SIZE 32

#pragma pack(push, 1) // 패딩을 없애기 위해 1바이트 정렬 지시자 사용

struct Packet {
    char machine_id[MACHINE_ID_SIZE];
    uint16_t nonce;
    uint64_t timestamp;
    uint32_t source_ip;
    char totp_value[OTP_SIZE];
    unsigned char hmac_value[HMAC_SIZE];
};
#pragma pack(pop)

int spa_fill_packet(const char *shared_secret, const char *machine_id, struct Packet *packet);
int spa_send_packet(const struct Packet *packet, const char *server_ip, int server_port);

#endif  // GNSPA_H
