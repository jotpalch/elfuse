/*
 * GDB RSP transport and hex helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"

#include "debug/gdbstub-rsp.h"

static const char hex_chars[] = "0123456789abcdef";

int gdb_hex_encode(char *dst, const uint8_t *src, size_t len)
{
    return (int) bytes_to_hex(dst, src, len);
}

/* Combine two hex digits into a byte.
 *
 * Returns 0 when either is not a hex digit, leaving *out untouched.
 *
 * Both nibbles are validated before either is shifted. hex_nibble returns -1
 * for a non-digit, and shifting a negative int left is undefined behavior, so
 * the obvious "(hex_nibble(hi) << 4) | hex_nibble(lo)" is UB on any input the
 * remote sends that is not hex. The remote controls these bytes completely.
 */
/*@ predicate is_hex_digit(integer c) =
      ('0' <= c <= '9') || ('a' <= c <= 'f') || ('A' <= c <= 'F');
 */
/*@
  requires \valid(out);
  assigns *out;
  ensures \result == 0 || \result == 1;
  ensures \result != 0 <==> (is_hex_digit((unsigned char) hi) &&
                             is_hex_digit((unsigned char) lo));
  ensures \result != 0 ==> *out == 16 * hex_val((unsigned char) hi) +
                                    hex_val((unsigned char) lo);
 */
static bool gdb_hex_pair(char hi, char lo, uint8_t *out)
{
    int h = hex_nibble((unsigned char) hi);
    if (h < 0)
        return false;

    int l = hex_nibble((unsigned char) lo);
    if (l < 0)
        return false;

    /* Unsigned arithmetic, and "* 16 +" rather than "<< 4 |": a signed left
     * shift that overflows is undefined, and the prover reasons about the
     * arithmetic form directly whereas the bitwise OR needs it to first
     * establish that the two operands do not share bits.
     */
    *out = (uint8_t) ((unsigned int) h * 16u + (unsigned int) l);
    return true;
}

/* Decode len bytes from 2*len hex digits.
 *
 * Returns len, or -1 on the first non-hex digit.
 *
 * The caller must supply 2*len readable digits; nothing here can check that,
 * which is why the contract states it. Decoding stops at the first bad digit
 * without reading its partner: the pair used to be read together before either
 * was validated, so a NUL landing on an even index caused a one-byte read past
 * it, and gdb_rsp_recv can place that NUL at the last byte of the packet
 * buffer.
 */
/*@
  requires len <= INT_MAX;
  requires \valid(dst + (0 .. len - 1));
  requires \valid_read(src + (0 .. 2 * len - 1));
  requires \separated(dst + (0 .. len - 1), src + (0 .. 2 * len - 1));
  assigns dst[0 .. len - 1];
  ensures \result == -1 || \result == (int) len;
  ensures \result != -1 <==>
            (\forall integer k; 0 <= k < 2 * len ==>
               is_hex_digit((unsigned char) src[k]));
  ensures \result != -1 ==>
            (\forall integer k; 0 <= k < len ==>
               dst[k] == 16 * hex_val((unsigned char) src[2 * k]) +
                              hex_val((unsigned char) src[2 * k + 1]));
 */
int gdb_hex_decode(uint8_t *dst, const char *src, size_t len)
{
    /*@
      loop invariant 0 <= i <= len;
      loop invariant \forall integer k; 0 <= k < 2 * i ==>
                       is_hex_digit((unsigned char) src[k]);
      loop invariant \forall integer k; 0 <= k < i ==>
                       dst[k] == 16 * hex_val((unsigned char) src[2 * k]) +
                                      hex_val((unsigned char) src[2 * k + 1]);
      loop assigns i, dst[0 .. len - 1];
      loop variant len - i;
     */
    for (size_t i = 0; i < len; i++) {
        /* Read the digits in order and bail between them. Handing both to
         * gdb_hex_pair would not do: C evaluates both arguments before the
         * call, so the low digit gets read before the high one is rejected,
         * which is the overread this loop is supposed to avoid.
         */
        int hi = hex_nibble((unsigned char) src[i * 2]);
        if (hi < 0)
            return -1;

        int lo = hex_nibble((unsigned char) src[i * 2 + 1]);
        if (lo < 0)
            return -1;

        dst[i] = (uint8_t) ((unsigned int) hi * 16u + (unsigned int) lo);
    }
    return (int) len;
}

/* Consume a run of hex digits and return its value, advancing *pp past them.
 *
 * The scan is bounded only by the terminating NUL, so the caller must pass a
 * NUL-terminated string; gdb_rsp_recv guarantees that for every packet it
 * returns. The contract states it rather than leaving it to the reader.
 *
 * NOT proved: the returned value. Specifying it needs a recursive logic
 * function over the digit run, and the resulting loop invariant (which must
 * relate the accumulator to a pointer-offset expression through a modulo-2^64
 * fold) times out in Z3 even at 120s. What is proved here is memory safety,
 * termination, and that *pp only advances within the same object. The value is
 * covered end to end by tests/test-gdbstub.sh, whose memory and register cases
 * cannot pass if addresses parse wrongly.
 *
 * More than 16 digits wraps, which is deliberate and matches gdbserver: the
 * value feeds addresses and lengths that every caller bound-checks against
 * guest memory anyway, so a wrapped value is rejected downstream rather than
 * here, where refusing it would change the parse position.
 */
/*@
  requires \valid(pp);
  requires valid_read_string(*pp);
  assigns *pp;
  ensures valid_read_string(*pp);
  ensures \base_addr(*pp) == \base_addr(\old(*pp));
  ensures \offset(*pp) >= \offset(\old(*pp));
 */
uint64_t gdb_parse_hex(const char **pp)
{
    const char *p = *pp;
    uint64_t val = 0;

    /*@
      loop invariant valid_read_string(p);
      loop invariant \base_addr(p) == \base_addr(\at(*pp, Pre));
      loop invariant \offset(p) >= \offset(\at(*pp, Pre));
      loop assigns p, val;
      loop variant strlen(p);
     */
    while (1) {
        int d = hex_nibble((unsigned char) *p);
        if (d < 0)
            break;

        /* val * 16 + d, not (val << 4) | d: same value for d <= 15 (the shift
         * clears the low nibble), and the prover reasons about the arithmetic
         * form without first proving the operands are disjoint.
         */
        val = val * 16u + (uint64_t) d;
        p++;
    }
    *pp = p;
    return val;
}

/* RSP checksum: the low byte of the sum of the payload. Wrapping is the
 * protocol, not an accident, so uint8_t arithmetic is deliberate.
 *
 * byte_sum below defines that value recursively, folding modulo 256 at every
 * step exactly as the uint8_t accumulator does. Defining it as a plain sum and
 * taking "% 256" only in the postcondition also specifies the right value, but
 * then every loop step asks the prover to show (x % 256 + b) % 256 == (x + b) %
 * 256, which Z3 times out on.
 */
/*@ axiomatic RspByteSum {
      logic integer byte_sum{L}(char *d, integer n) reads d[0 .. n - 1];
      axiom byte_sum_empty{L}:
        \forall char *d; byte_sum(d, 0) == 0;
      axiom byte_sum_step{L}:
        \forall char *d, integer n; n > 0 ==>
          byte_sum(d, n) ==
            (byte_sum(d, n - 1) + (unsigned char) d[n - 1]) % 256;
    }
 */
/*@
  requires \valid_read(data + (0 .. len - 1));
  assigns \nothing;
  ensures \result == byte_sum(data, len);
 */
static uint8_t rsp_checksum(const char *data, size_t len)
{
    uint8_t sum = 0;
    /*@
      loop invariant 0 <= i <= len;
      loop invariant sum == byte_sum(data, i);
      loop assigns i, sum;
      loop variant len - i;
     */
    for (size_t i = 0; i < len; i++)
        sum += (uint8_t) data[i];
    return sum;
}

static int rsp_send_byte(int fd, char value)
{
    return write_all(fd, &value, 1);
}

int gdb_rsp_send(int fd, const char *data, size_t len)
{
    uint8_t cksum = rsp_checksum(data, len);
    char hdr = '$';
    char trailer[3];
    trailer[0] = '#';
    trailer[1] = hex_chars[(cksum >> 4) & 0xF];
    trailer[2] = hex_chars[cksum & 0xF];

    struct iovec iov[3] = {
        {.iov_base = &hdr, .iov_len = 1},
        {.iov_base = (void *) data, .iov_len = len},
        {.iov_base = trailer, .iov_len = 3},
    };

    int iovcnt = 3;
    struct iovec *cur = iov;
    size_t total = 1 + len + 3;

    while (total > 0) {
        ssize_t written = writev(fd, cur, iovcnt);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        total -= (size_t) written;
        while (iovcnt > 0 && (size_t) written >= cur->iov_len) {
            written -= (ssize_t) cur->iov_len;
            cur++;
            iovcnt--;
        }
        if (iovcnt > 0 && written > 0) {
            cur->iov_base = (char *) cur->iov_base + written;
            cur->iov_len -= (size_t) written;
        }
    }
    return 0;
}

void gdb_rsp_reset(gdb_rsp_ctx_t *ctx)
{
    ctx->read_pos = 0;
    ctx->read_len = 0;
    ctx->no_ack_mode = false;
}

bool gdb_rsp_pending(const gdb_rsp_ctx_t *ctx)
{
    return ctx->read_pos < ctx->read_len;
}

void gdb_rsp_set_noack(gdb_rsp_ctx_t *ctx, bool enabled)
{
    ctx->no_ack_mode = enabled;
}

/* Read one RSP packet from the client into @buf. Strips $...# framing and
 * verifies the checksum, sending + acknowledgment on success.
 *
 * Returns packet length, 0 on EOF, -1 on error. Also handles bare 0x03 (Ctrl+C)
 * by returning "\x03" as a 1-byte packet.
 *
 * Uses a static read buffer to batch socket reads instead of reading one byte
 * at a time. Packets exceeding @bufsz are rejected with E00.
 */
int gdb_rsp_recv(gdb_rsp_ctx_t *ctx, int fd, char *buf, size_t bufsz)
{
    /* Two bytes minimum: every returned packet is NUL-terminated, and the bare
     * 0x03 (Ctrl+C) reply needs one byte for the payload and one for the
     * terminator. Accepting bufsz 1 would hand back an unterminated packet and
     * break the guarantee gdb_parse_hex's contract relies on.
     */
    if (bufsz < 2) {
        errno = EINVAL;
        return -1;
    }

    int state = 0;
    size_t pos = 0;
    char ck_hi = 0, ck_lo = 0;
    bool overflow = false;

    while (1) {
        if (!gdb_rsp_pending(ctx)) {
            ssize_t n = read(fd, ctx->read_buf, GDB_RSP_READ_BUF_SIZE);
            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                return (n == 0) ? 0 : -1;
            }
            ctx->read_pos = 0;
            ctx->read_len = (size_t) n;
        }

        while (gdb_rsp_pending(ctx)) {
            uint8_t c = ctx->read_buf[ctx->read_pos++];

            if (state == 0 && (c == '+' || c == '-'))
                continue;

            if (c == 0x03) {
                buf[0] = 0x03;

                /* Terminate like every other returned packet: gdb_parse_hex's
                 * contract requires a NUL-terminated string and cites this
                 * function as the guarantee. bufsz >= 2 is enforced above.
                 */
                buf[1] = '\0';
                return 1;
            }

            switch (state) {
            case 0:
                if (c == '$') {
                    state = 1;
                    pos = 0;
                    overflow = false;
                }
                break;
            case 1:
                if (c == '#') {
                    state = 2;
                    break;
                }
                if (!overflow) {
                    if (pos < bufsz - 1) {
                        buf[pos++] = (char) c;
                    } else {
                        overflow = true;
                    }
                }
                break;
            case 2:
                ck_hi = (char) c;
                state = 3;
                break;
            case 3: {
                ck_lo = (char) c;

                if (overflow) {
                    gdb_rsp_send(fd, "E00", 3);
                    state = 0;
                    pos = 0;
                    overflow = false;
                    break;
                }

                buf[pos] = '\0';

                /* A non-hex checksum is a corrupt packet, handled like a
                 * mismatch. Decoding it as a number first would shift a
                 * negative nibble.
                 */
                uint8_t expected;
                if (!gdb_hex_pair(ck_hi, ck_lo, &expected)) {
                    if (!ctx->no_ack_mode)
                        (void) rsp_send_byte(fd, '-');
                    state = 0;
                    pos = 0;
                    break;
                }

                uint8_t actual = rsp_checksum(buf, pos);
                if (expected == actual) {
                    if (!ctx->no_ack_mode)
                        (void) rsp_send_byte(fd, '+');
                    return (int) pos;
                } else {
                    if (!ctx->no_ack_mode)
                        (void) rsp_send_byte(fd, '-');
                    state = 0;
                    pos = 0;
                }
                break;
            }
            default:
                state = 0;
                break;
            }
        }
    }
}
