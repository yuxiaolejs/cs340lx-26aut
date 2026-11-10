// Chip-free unit tests for the TLV and APDU layers (plus the given CRC).
// Nothing here touches I2C, so you can run this with no SE050 attached.
// T=1 and the actual SE050 commands are tested end-to-end in main.c.
//
// Expected bytes come from AN12413 and the worked examples in the README.
#include "rpi.h"
#include "se050.h"

static int n_pass = 0, n_fail = 0;

#define CHECK(cond)                                                    \
    do                                                                 \
    {                                                                  \
        if (cond)                                                      \
            n_pass++;                                                  \
        else                                                           \
        {                                                              \
            n_fail++;                                                  \
            printk("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
        }                                                              \
    } while (0)

// compare got[0..n) against want[0..n), dump both on mismatch.
static int bytes_eq(const char *what, const uint8_t *got, const uint8_t *want, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (got[i] != want[i])
        {
            printk("FAIL %s: mismatch at byte %d\n  got : ", what, i);
            for (int j = 0; j < n; j++)
                printk("%x ", got[j]);
            printk("\n  want: ");
            for (int j = 0; j < n; j++)
                printk("%x ", want[j]);
            printk("\n");
            return 0;
        }
    }
    return 1;
}

static const uint8_t keyid[4] = {'t', 'o', 't', 'p'};
static const uint8_t key[20] = "12345678901234567890";
// RFC6238: T = 1111111109 / 30 = 37037036 = 0x023523EC, 8 bytes big-endian
static const uint8_t time_step[8] = {0x00, 0x00, 0x00, 0x00, 0x02, 0x35, 0x23, 0xec};

/**********************************************************************
 * CRC (given to you, but a quick sanity check never hurts)
 */
static void test_crc(void)
{
    // standard CRC16-X25 check value
    CHECK(crc16_x25((const uint8_t *)"123456789", 9) == 0x906e);

    // AppletSelect frame from the README: CRC bytes on the wire are 0xa8 0xc8
    uint8_t sel[] = {0x5a, 0x00, 0x16,
                     0x00, 0xa4, 0x04, 0x00, 0x10,
                     0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
                     0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
                     0x00};
    CHECK(crc16_x25(sel, sizeof sel) == 0xc8a8);
}

/**********************************************************************
 * TLV encode
 */
static void test_tlv_encode(void)
{
    uint8_t buf[300];
    uint8_t *end;

    // short form: tag | len | value
    end = tlv_encode(buf, 0x41, keyid, 4);
    uint8_t want_short[] = {0x41, 0x04, 't', 'o', 't', 'p'};
    CHECK(end == buf + 6);
    CHECK(bytes_eq("tlv_encode short", buf, want_short, 6));

    // single-byte value (e.g., MACAlgo = HMAC_SHA1)
    uint8_t algo = 0x18;
    end = tlv_encode(buf, 0x42, &algo, 1);
    uint8_t want_one[] = {0x42, 0x01, 0x18};
    CHECK(end == buf + 3);
    CHECK(bytes_eq("tlv_encode 1 byte", buf, want_one, 3));

    // empty value
    end = tlv_encode(buf, 0x44, 0, 0);
    uint8_t want_empty[] = {0x44, 0x00};
    CHECK(end == buf + 2);
    CHECK(bytes_eq("tlv_encode empty", buf, want_empty, 2));

    // 127 is the largest length that still fits in one byte
    uint8_t val[255];
    for (int i = 0; i < 255; i++)
        val[i] = i;
    end = tlv_encode(buf, 0x43, val, 127);
    CHECK(end == buf + 2 + 127);
    CHECK(buf[0] == 0x43 && buf[1] == 127);
    CHECK(bytes_eq("tlv_encode 127 value", buf + 2, val, 127));

    // 128 needs the 0x81 form: tag | 0x81 | len | value
    end = tlv_encode(buf, 0x43, val, 128);
    CHECK(end == buf + 3 + 128);
    CHECK(buf[0] == 0x43 && buf[1] == 0x81 && buf[2] == 128);
    CHECK(bytes_eq("tlv_encode 128 value", buf + 3, val, 128));

    // 255, the max we can pass in a uint8_t
    end = tlv_encode(buf, 0x43, val, 255);
    CHECK(end == buf + 3 + 255);
    CHECK(buf[1] == 0x81 && buf[2] == 255);

    // chaining: the returned pointer is where the next TLV goes
    end = tlv_encode(buf, 0x41, keyid, 4);
    end = tlv_encode(end, 0x43, key, 20);
    CHECK(end == buf + 6 + 22);
    CHECK(buf[6] == 0x43 && buf[7] == 0x14);
    CHECK(bytes_eq("tlv_encode chained", buf + 8, key, 20));
}

/**********************************************************************
 * TLV decode
 */
static void test_tlv_decode(void)
{
    uint8_t tag, *val, *next;
    uint16_t len;

    // short form
    uint8_t s[] = {0x41, 0x04, 't', 'o', 't', 'p'};
    next = tlv_decode(s, sizeof s, &tag, &val, &len);
    CHECK(next == s + 6);
    CHECK(tag == 0x41 && len == 4 && val == s + 2);

    // 0x81 form, even for a small value: the chip really does this,
    // e.g., the 20-byte MAC from MACOneShot can come back as 41 81 14 ...
    uint8_t m[3 + 20];
    m[0] = 0x41, m[1] = 0x81, m[2] = 0x14;
    for (int i = 0; i < 20; i++)
        m[3 + i] = 0xa0 + i;
    next = tlv_decode(m, sizeof m, &tag, &val, &len);
    CHECK(next == m + 23);
    CHECK(tag == 0x41 && len == 20 && val == m + 3);

    // 0x82 form: two length bytes, big-endian (kept small so it fits in
    // the uint8_t tlv_len; the parsing is the same for big values)
    uint8_t big[] = {0x43, 0x82, 0x00, 0x05, 1, 2, 3, 4, 5};
    next = tlv_decode(big, sizeof big, &tag, &val, &len);
    CHECK(next == big + sizeof big);
    CHECK(tag == 0x43 && len == 5 && val == big + 4);

    // walk two back-to-back TLVs using the returned pointer
    uint8_t two[] = {0x41, 0x02, 0xaa, 0xbb, 0x42, 0x81, 0x01, 0xcc};
    next = tlv_decode(two, sizeof two, &tag, &val, &len);
    CHECK(next == two + 4 && tag == 0x41 && len == 2 && val[0] == 0xaa && val[1] == 0xbb);
    next = tlv_decode(next, sizeof two - 4, &tag, &val, &len);
    CHECK(next == two + sizeof two && tag == 0x42 && len == 1 && val[0] == 0xcc);

    // malformed input: return NULL rather than reading past the buffer
    uint8_t trunc_hdr[] = {0x41};
    CHECK(tlv_decode(trunc_hdr, sizeof trunc_hdr, &tag, &val, &len) == 0);
    uint8_t trunc_val[] = {0x41, 0x04, 't', 'o'};
    CHECK(tlv_decode(trunc_val, sizeof trunc_val, &tag, &val, &len) == 0);

    // round trip through the encoder, for a length that needs 0x81
    uint8_t buf[300], v[200];
    for (int i = 0; i < 200; i++)
        v[i] = 255 - i;
    uint8_t *end = tlv_encode(buf, 0x45, v, 200);
    next = tlv_decode(buf, end - buf, &tag, &val, &len);
    CHECK(next == end && tag == 0x45 && len == 200);
    CHECK(bytes_eq("tlv round trip", val, v, 200));
}

/**********************************************************************
 * APDU assemble
 *   need_resp: low 8 bits = "add an Le byte?", bits 15:8 = the Le value.
 */
static void test_apdu_assemble(void)
{
    uint8_t apdu[300], data[64], *p;
    int n;

    // header only: no data (no Lc), no Le
    n = apdu_assemble(apdu, 0x04, 0x00, 0x00, 0, 0, 0);
    uint8_t want_hdr[] = {0x80, 0x04, 0x00, 0x00};
    CHECK(n == 4);
    CHECK(bytes_eq("apdu header only", apdu, want_hdr, 4));

    // header + Le only (Le = 0x00 means "up to 256 bytes")
    n = apdu_assemble(apdu, 0x02, 0x00, 0x00, 0, 0, (0x00 << 8) | 1);
    uint8_t want_le[] = {0x80, 0x02, 0x00, 0x00, 0x00};
    CHECK(n == 5);
    CHECK(bytes_eq("apdu Le only", apdu, want_le, 5));

    // a non-zero Le value ends up in the last byte
    n = apdu_assemble(apdu, 0x02, 0x00, 0x00, 0, 0, (0x14 << 8) | 1);
    CHECK(n == 5 && apdu[4] == 0x14);

    // WriteSymmKey from the README: 80 01 05 00 1c | 41 04 totp | 43 14 key
    p = tlv_encode(data, 0x41, keyid, 4);
    p = tlv_encode(p, 0x43, key, 20);
    n = apdu_assemble(apdu, 0x01, 0x05, 0x00, data, p - data, 0);
    uint8_t want_wsk[33] = {0x80, 0x01, 0x05, 0x00, 0x1c,
                            0x41, 0x04, 't', 'o', 't', 'p',
                            0x43, 0x14};
    for (int i = 0; i < 20; i++)
        want_wsk[13 + i] = key[i];
    CHECK(n == 33);
    CHECK(bytes_eq("apdu WriteSymmKey", apdu, want_wsk, 33));

    // and the README's cross-check: as the 2nd I-block (PCB = 0x40),
    // the T=1 CRC bytes are 0x51 0x33
    uint8_t frame[3 + 33] = {0x5a, 0x40, 33};
    for (int i = 0; i < 33; i++)
        frame[3 + i] = apdu[i];
    CHECK(crc16_x25(frame, sizeof frame) == 0x3351);

    // MACOneShot (HMAC_SHA1) for the RFC6238 time step, Le = 0x00
    //   80 03 0d 45 13 | 41 04 totp | 42 01 18 | 43 08 <time> | 00
    uint8_t algo = 0x18;
    p = tlv_encode(data, 0x41, keyid, 4);
    p = tlv_encode(p, 0x42, &algo, 1);
    p = tlv_encode(p, 0x43, time_step, 8);
    n = apdu_assemble(apdu, 0x03, 0x0d, 0x45, data, p - data, 1);
    uint8_t want_mac[] = {0x80, 0x03, 0x0d, 0x45, 0x13,
                          0x41, 0x04, 't', 'o', 't', 'p',
                          0x42, 0x01, 0x18,
                          0x43, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x35, 0x23, 0xec,
                          0x00};
    CHECK(n == sizeof want_mac);
    CHECK(bytes_eq("apdu MACOneShot", apdu, want_mac, sizeof want_mac));

    // DeleteSecureObject: 80 04 00 28 06 | 41 04 totp
    p = tlv_encode(data, 0x41, keyid, 4);
    n = apdu_assemble(apdu, 0x04, 0x00, 0x28, data, p - data, 0);
    uint8_t want_del[] = {0x80, 0x04, 0x00, 0x28, 0x06,
                          0x41, 0x04, 't', 'o', 't', 'p'};
    CHECK(n == sizeof want_del);
    CHECK(bytes_eq("apdu DeleteSecureObject", apdu, want_del, sizeof want_del));
}

/**********************************************************************
 * R-APDU decode: body | SW1 SW2
 */
static void test_rapdu_decode(void)
{
    uint8_t *body;
    uint16_t sw;
    int n;

    // MACOneShot-style reply: TLV[TAG_1] with the MAC, then 90 00
    uint8_t r[22 + 2];
    r[0] = 0x41, r[1] = 0x14;
    for (int i = 0; i < 20; i++)
        r[2 + i] = i;
    r[22] = 0x90, r[23] = 0x00;
    n = rapdu_decode(r, sizeof r, &body, &sw);
    CHECK(n == 22);
    CHECK(body == r);
    CHECK(sw == 0x9000);

    // status only, no body (e.g., WriteSymmKey success)
    uint8_t ok[] = {0x90, 0x00};
    n = rapdu_decode(ok, sizeof ok, &body, &sw);
    CHECK(n == 0 && sw == 0x9000);

    // error status words are big-endian too (SW1 is the high byte)
    uint8_t nf[] = {0x6a, 0x82};
    n = rapdu_decode(nf, sizeof nf, &body, &sw);
    CHECK(n == 0 && sw == 0x6a82);

    // too short to even hold a status word
    uint8_t bad[] = {0x90};
    CHECK(rapdu_decode(bad, sizeof bad, &body, &sw) < 0);
}

void notmain(void)
{
    test_crc();
    test_tlv_encode();
    test_tlv_decode();
    test_apdu_assemble();
    test_rapdu_decode();

    printk("%d passed, %d failed\n", n_pass, n_fail);
    if (n_fail == 0)
        printk("ALL TESTS PASSED\n");
}
