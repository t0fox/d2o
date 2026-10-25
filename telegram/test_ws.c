#include "tg_ws.h"
#include "tg_net.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_nip_host_to_ipv4(void) {
    char ip[16];
    assert(tg_nip_host_to_ipv4("192.0.2.44.nip.io", ip) == 1);
    assert(strcmp(ip, "192.0.2.44") == 0);
    assert(tg_nip_host_to_ipv4("1.2.3.4.nip.io.", ip) == 1);
    assert(strcmp(ip, "1.2.3.4") == 0);
    assert(tg_nip_host_to_ipv4("relay.example", ip) == 0);
    assert(tg_nip_host_to_ipv4("1.2.3.999.nip.io", ip) == 0);
    assert(tg_nip_host_to_ipv4("1.2.3.nip.io", ip) == 0);
    assert(tg_nip_host_to_ipv4("+1.2.3.4.nip.io", ip) == 0);
    assert(tg_nip_host_to_ipv4(" 1.2.3.4.nip.io", ip) == 0);
}

static void test_masked_client_frame(void) {
    const uint8_t message[] = {0x00, 0x7f, 0x80, 0xff};
    uint8_t frame[32];
    size_t written = 0;
    assert(tg_ws_encode_client_frame(frame, sizeof(frame), TG_WS_BINARY,
                                     message, sizeof(message), &written) == 0);
    assert(written == 10 && frame[0] == 0x82 && frame[1] == 0x84);
    assert(memcmp(frame + 2, "\0\0\0\0", 4) != 0);
    for (size_t i = 0; i < sizeof(message); ++i)
        assert(frame[6 + i] == (uint8_t)(message[i] ^ frame[2 + i % 4]));
    assert(tg_ws_encode_client_frame(frame, 8, TG_WS_BINARY,
                                     message, sizeof(message), &written) != 0);
}

static void test_server_frame_bounds(void) {
    const uint8_t valid[] = {0x82, 0x03, 'a', 'b', 'c'};
    const uint8_t masked[] = {0x82, 0x81, 0, 0, 0, 0, 'x'};
    const uint8_t fragmented[] = {0x02, 0x01, 'x'};
    const uint8_t oversized[] = {0x82, 127, 0, 0, 0, 0, 0, 0, 0x20, 0, 0};
    uint8_t opcode;
    const uint8_t *payload;
    size_t payload_len, consumed;
    assert(tg_ws_decode_server_frame(valid, sizeof(valid), 3, &opcode,
        &payload, &payload_len, &consumed) == 0);
    assert(opcode == TG_WS_BINARY && payload_len == 3 && consumed == sizeof(valid));
    assert(memcmp(payload, "abc", 3) == 0);
    assert(tg_ws_decode_server_frame(masked, sizeof(masked), 10, &opcode,
        &payload, &payload_len, &consumed) != 0);
    assert(tg_ws_decode_server_frame(fragmented, sizeof(fragmented), 10,
        &opcode, &payload, &payload_len, &consumed) != 0);
    assert(tg_ws_decode_server_frame(oversized, sizeof(oversized),
        TG_WS_MAX_MESSAGE, &opcode, &payload, &payload_len, &consumed) != 0);
}

int main(void) {
    test_nip_host_to_ipv4();
    test_masked_client_frame();
    test_server_frame_bounds();
    puts("Тесты WebSocket framing и nip.io: ок");
    return 0;
}
