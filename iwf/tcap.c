/*
 * tcap.c - minimal TCAP / BER codec.
 *
 * Notes on length encoding
 * ------------------------
 * BER allows short form (1 byte, 0..127) or long form (0x80|N followed by
 * N bytes of length).  We support up to N=3 for both decode and encode,
 * which gives us 24-bit lengths (>16 MB) - safely larger than any TCAP
 * payload we care about.  Indefinite length (0x80 with no follow-up) is
 * legal in BER but not used in MAP/Gr in practice; we reject it on decode.
 *
 * Notes on transaction IDs
 * ------------------------
 * TS Q.773 allows OTID/DTID to be 1..4 octets.  We always emit 4 octets
 * (big-endian) so a peer can't probabilistically collide with a stale id
 * from a previous IWF instance restart.  On decode we accept any length
 * up to 4 and zero-extend to u32.
 */

#include "tcap.h"
#include "logging.h"

#include <stdint.h>
#include <string.h>

/* ====================================================================== */
/* BER primitives                                                         */
/* ====================================================================== */

int ber_enc_tag(uint8_t *buf, size_t cap, size_t *off, uint8_t tag)
{
    if (*off + 1 > cap) return -1;
    buf[(*off)++] = tag;
    return 1;
}

int ber_enc_length(uint8_t *buf, size_t cap, size_t *off, size_t len)
{
    if (len <= 0x7f) {
        if (*off + 1 > cap) return -1;
        buf[(*off)++] = (uint8_t)len;
        return 1;
    }
    if (len <= 0xff) {
        if (*off + 2 > cap) return -1;
        buf[(*off)++] = 0x81;
        buf[(*off)++] = (uint8_t)len;
        return 2;
    }
    if (len <= 0xffff) {
        if (*off + 3 > cap) return -1;
        buf[(*off)++] = 0x82;
        buf[(*off)++] = (uint8_t)(len >> 8);
        buf[(*off)++] = (uint8_t)(len & 0xff);
        return 3;
    }
    if (len <= 0xffffff) {
        if (*off + 4 > cap) return -1;
        buf[(*off)++] = 0x83;
        buf[(*off)++] = (uint8_t)(len >> 16);
        buf[(*off)++] = (uint8_t)(len >> 8);
        buf[(*off)++] = (uint8_t)(len & 0xff);
        return 4;
    }
    return -1;
}

int ber_enc_tlv(uint8_t *buf, size_t cap, size_t *off,
                uint8_t tag, const uint8_t *val, size_t val_len)
{
    if (ber_enc_tag(buf, cap, off, tag) < 0) return -1;
    if (ber_enc_length(buf, cap, off, val_len) < 0) return -1;
    if (*off + val_len > cap) return -1;
    if (val_len) memcpy(buf + *off, val, val_len);
    *off += val_len;
    return 0;
}

int ber_enc_integer_u32(uint8_t *buf, size_t cap, size_t *off,
                        uint8_t tag, uint32_t v)
{
    /* Minimal-length two's-complement INTEGER. Find MSB. */
    uint8_t bytes[5];
    int n = 0;
    bytes[0] = (uint8_t)((v >> 24) & 0xff);
    bytes[1] = (uint8_t)((v >> 16) & 0xff);
    bytes[2] = (uint8_t)((v >> 8)  & 0xff);
    bytes[3] = (uint8_t)( v        & 0xff);
    /* Strip leading 0x00 bytes, but keep one if the next-byte's top bit
     * is set (otherwise the value reads back negative). */
    int start = 0;
    while (start < 3 && bytes[start] == 0 && !(bytes[start + 1] & 0x80))
        start++;
    n = 4 - start;
    return ber_enc_tlv(buf, cap, off, tag, bytes + start, (size_t)n);
}

int ber_dec_length(const uint8_t *buf, size_t len, size_t *off, size_t *out_len)
{
    if (*off >= len) return -1;
    uint8_t b = buf[(*off)++];
    if ((b & 0x80) == 0) { *out_len = b; return 0; }
    if (b == 0x80)       return -1;     /* indefinite length: rejected */
    size_t nbytes = b & 0x7f;
    if (nbytes > 4 || *off + nbytes > len) return -1;
    size_t l = 0;
    for (size_t i = 0; i < nbytes; i++) l = (l << 8) | buf[(*off)++];
    *out_len = l;
    return 0;
}

int ber_dec_tlv(const uint8_t *buf, size_t len, size_t *off,
                uint8_t *out_tag, const uint8_t **out_val, size_t *out_val_len)
{
    if (*off >= len) return -1;
    *out_tag = buf[(*off)++];
    size_t l = 0;
    if (ber_dec_length(buf, len, off, &l) < 0) return -1;
    if (*off + l > len) return -1;
    *out_val = buf + *off;
    *out_val_len = l;
    *off += l;
    return 0;
}

int ber_dec_integer_u32(const uint8_t *val, size_t val_len, uint32_t *out)
{
    if (!val_len || val_len > 5) return -1;
    /* Skip a leading 0x00 used to keep the value positive. */
    size_t i = 0;
    if (val_len == 5 && val[0] == 0x00) i = 1;
    uint32_t v = 0;
    for (; i < val_len; i++) v = (v << 8) | val[i];
    *out = v;
    return 0;
}

/* ====================================================================== */
/* Transaction-layer decode                                               */
/* ====================================================================== */

static int decode_otid_dtid(const uint8_t *val, size_t val_len, uint32_t *out)
{
    if (val_len == 0 || val_len > 4) return -1;
    uint32_t v = 0;
    for (size_t i = 0; i < val_len; i++) v = (v << 8) | val[i];
    *out = v;
    return 0;
}

static int decode_components(const uint8_t *buf, size_t len, tcap_msg_t *out)
{
    size_t off = 0;
    while (off < len && out->n_components < TCAP_MAX_COMPONENTS) {
        uint8_t tag;
        const uint8_t *val;
        size_t val_len;
        if (ber_dec_tlv(buf, len, &off, &tag, &val, &val_len) < 0) return -1;

        tcap_component_t *c = &out->components[out->n_components++];
        memset(c, 0, sizeof(*c));
        c->opcode = -1;
        c->error_code = -1;

        switch (tag) {
        case TCAP_CMP_INVOKE:        c->kind = TCAP_CMP_KIND_INVOKE; break;
        case TCAP_CMP_RETURN_RESULT: c->kind = TCAP_CMP_KIND_RES;    break;
        case TCAP_CMP_RETURN_ERROR:  c->kind = TCAP_CMP_KIND_ERR;    break;
        case TCAP_CMP_REJECT:        c->kind = TCAP_CMP_KIND_REJECT; break;
        default:
            /* Unknown component - skip but don't bail (TCAP allows extensions). */
            out->n_components--;
            continue;
        }

        /* Component body. */
        size_t inner_off = 0;
        const uint8_t *inner = val;
        size_t inner_len = val_len;

        /* Invoke ID (INTEGER, mandatory). */
        uint8_t itag;
        const uint8_t *ival;
        size_t ilen;
        if (ber_dec_tlv(inner, inner_len, &inner_off, &itag, &ival, &ilen) < 0)
            return -1;
        if (itag != TCAP_TAG_INVOKE_ID || ilen != 1) {
            /* Some stacks use multi-byte invoke IDs; accept up to 4. */
            if (itag == TCAP_TAG_INVOKE_ID && ilen <= 4 && ilen > 0) {
                c->invoke_id = ival[ilen - 1];
            } else {
                return -1;
            }
        } else {
            c->invoke_id = ival[0];
        }

        /* For ReturnResult, the inner is wrapped in a SEQUENCE [0]: skip. */
        if (c->kind == TCAP_CMP_KIND_RES && inner_off < inner_len) {
            /* Linked-Id [0] (optional) on Invoke. */
            if (inner[inner_off] == 0x30) {
                const uint8_t *seq;
                size_t seq_len;
                if (ber_dec_tlv(inner, inner_len, &inner_off, &itag,
                                &seq, &seq_len) < 0) return -1;
                /* Inside SEQUENCE: opcode INTEGER then parameters. */
                size_t soff = 0;
                if (ber_dec_tlv(seq, seq_len, &soff, &itag, &ival, &ilen) < 0)
                    return -1;
                if (itag == TCAP_TAG_OPCODE_LOCAL) {
                    uint32_t op = 0;
                    ber_dec_integer_u32(ival, ilen, &op);
                    c->opcode = (int)op;
                }
                if (soff < seq_len) {
                    c->parameters = seq + soff;
                    c->parameters_len = seq_len - soff;
                }
                continue;
            }
        }

        /* Invoke or ReturnError: opcode/errorCode INTEGER then parameters. */
        if (inner_off < inner_len) {
            if (ber_dec_tlv(inner, inner_len, &inner_off, &itag, &ival, &ilen) < 0)
                return -1;
            if (c->kind == TCAP_CMP_KIND_INVOKE) {
                if (itag == TCAP_TAG_LINKED_ID) {
                    /* Linked-Id present, opcode follows */
                    if (ilen >= 1) {
                        c->have_linked_id = true;
                        c->linked_id = ival[ilen - 1];
                    }
                    if (ber_dec_tlv(inner, inner_len, &inner_off,
                                    &itag, &ival, &ilen) < 0) return -1;
                }
                if (itag == TCAP_TAG_OPCODE_LOCAL) {
                    uint32_t op = 0;
                    ber_dec_integer_u32(ival, ilen, &op);
                    c->opcode = (int)op;
                }
            } else if (c->kind == TCAP_CMP_KIND_ERR) {
                if (itag == TCAP_TAG_ERROR_LOCAL) {
                    uint32_t ec = 0;
                    ber_dec_integer_u32(ival, ilen, &ec);
                    c->error_code = (int)ec;
                }
            }
        }
        if (inner_off < inner_len) {
            c->parameters = inner + inner_off;
            c->parameters_len = inner_len - inner_off;
        }
    }
    return 0;
}

int tcap_decode(const uint8_t *buf, size_t len, tcap_msg_t *out)
{
    if (!buf || len < 2 || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->raw = buf;
    out->raw_len = len;

    size_t off = 0;
    uint8_t tag;
    const uint8_t *body;
    size_t body_len;
    if (ber_dec_tlv(buf, len, &off, &tag, &body, &body_len) < 0) return -1;

    switch (tag) {
    case TCAP_TAG_BEGIN:    out->type = TCAP_MSG_BEGIN;    break;
    case TCAP_TAG_END:      out->type = TCAP_MSG_END;      break;
    case TCAP_TAG_CONTINUE: out->type = TCAP_MSG_CONTINUE; break;
    case TCAP_TAG_ABORT:    out->type = TCAP_MSG_ABORT;    break;
    default:
        LOGW("tcap", "unknown transaction tag 0x%02x len=%zu", tag, body_len);
        return -1;
    }

    size_t boff = 0;
    while (boff < body_len) {
        uint8_t t;
        const uint8_t *v;
        size_t vlen;
        if (ber_dec_tlv(body, body_len, &boff, &t, &v, &vlen) < 0) return -1;
        switch (t) {
        case TCAP_TAG_OTID:
            if (decode_otid_dtid(v, vlen, &out->otid) < 0) return -1;
            out->have_otid = true;
            break;
        case TCAP_TAG_DTID:
            if (decode_otid_dtid(v, vlen, &out->dtid) < 0) return -1;
            out->have_dtid = true;
            break;
        case TCAP_TAG_DIALOGUE:
            out->dialogue = v;
            out->dialogue_len = vlen;
            break;
        case TCAP_TAG_COMPONENTS:
            if (decode_components(v, vlen, out) < 0) return -1;
            break;
        default:
            /* P-Abort cause or vendor extensions - we don't act on them. */
            break;
        }
    }
    return 0;
}

/* The dialogue portion is itself a TLV-tagged blob:
 *
 *   [APPLICATION 11] -> EXTERNAL [UNIVERSAL 8]:
 *       direct-reference OBJECT IDENTIFIER  (the dialogue-as-id OID)
 *       single-ASN1-type [0] EXPLICIT       -> AARQ / AARE
 *           AARQ-apdu = [APPLICATION 0]:
 *               protocol-version [0]
 *               application-context-name [1] EXPLICIT OBJECT IDENTIFIER
 *               ...
 *
 * For our purposes the only thing we want out of the dialogue is the AC OID,
 * which tells us which MAP operation context is in play.
 */
int tcap_dialogue_oid_get(const tcap_msg_t *msg,
                          const uint8_t **out_oid, size_t *out_len)
{
    if (!msg || !msg->dialogue || msg->dialogue_len < 4) return -1;
    /* Peel EXTERNAL (tag 0x28 in IMPLICIT form, or 0x60). The various stacks
     * disagree on the encoding. We scan for the first OID (tag 0x06) inside
     * a constructed [1] EXPLICIT (tag 0xA1) container. */
    const uint8_t *p = msg->dialogue;
    size_t n = msg->dialogue_len;
    for (size_t i = 0; i + 2 < n; i++) {
        if (p[i] == 0xA1 && (p[i + 1] & 0x80) == 0) {
            size_t l = p[i + 1];
            if (i + 2 + l > n) continue;
            const uint8_t *q = p + i + 2;
            if (l >= 2 && q[0] == 0x06 && q[1] <= l - 2) {
                *out_oid = q + 2;
                *out_len = q[1];
                return 0;
            }
        }
    }
    return -1;
}

/* ====================================================================== */
/* Component-layer encode                                                 */
/* ====================================================================== */

/*  Invoke ::= SEQUENCE {
 *    invokeID INTEGER,
 *    opCode CHOICE { localValue INTEGER, ... },
 *    parameter ANY OPTIONAL }                                           */
static int enc_component(uint8_t comp_tag,
                         uint8_t *buf, size_t cap, size_t *off,
                         uint8_t invoke_id, uint8_t op_tag, int op_value,
                         const uint8_t *parameters, size_t parameters_len)
{
    /* Build inner body into a scratch area first so we know its length. */
    uint8_t inner[1024];
    size_t io = 0;
    if (ber_enc_integer_u32(inner, sizeof(inner), &io,
                            TCAP_TAG_INVOKE_ID, invoke_id) < 0) return -1;
    if (op_tag) {
        if (ber_enc_integer_u32(inner, sizeof(inner), &io,
                                op_tag, (uint32_t)op_value) < 0) return -1;
    }
    if (parameters && parameters_len) {
        if (io + parameters_len > sizeof(inner)) return -1;
        memcpy(inner + io, parameters, parameters_len);
        io += parameters_len;
    }
    return ber_enc_tlv(buf, cap, off, comp_tag, inner, io);
}

int tcap_enc_invoke(uint8_t *buf, size_t cap, size_t *off,
                    uint8_t invoke_id, int local_opcode,
                    const uint8_t *parameters, size_t parameters_len)
{
    return enc_component(TCAP_CMP_INVOKE, buf, cap, off,
                         invoke_id, TCAP_TAG_OPCODE_LOCAL, local_opcode,
                         parameters, parameters_len);
}

int tcap_enc_return_result(uint8_t *buf, size_t cap, size_t *off,
                           uint8_t invoke_id, int local_opcode,
                           const uint8_t *parameters, size_t parameters_len)
{
    /*  ReturnResult ::= SEQUENCE {
     *    invokeID INTEGER,
     *    result SEQUENCE { opCode ..., parameter ANY } OPTIONAL }       */
    uint8_t inner[1024];
    size_t io = 0;
    if (ber_enc_integer_u32(inner, sizeof(inner), &io,
                            TCAP_TAG_INVOKE_ID, invoke_id) < 0) return -1;

    /* Inner SEQUENCE for "result" present iff parameters is non-empty. */
    if (parameters || local_opcode >= 0) {
        uint8_t seq[768];
        size_t so = 0;
        if (local_opcode >= 0) {
            if (ber_enc_integer_u32(seq, sizeof(seq), &so,
                                    TCAP_TAG_OPCODE_LOCAL,
                                    (uint32_t)local_opcode) < 0) return -1;
        }
        if (parameters && parameters_len) {
            if (so + parameters_len > sizeof(seq)) return -1;
            memcpy(seq + so, parameters, parameters_len);
            so += parameters_len;
        }
        if (ber_enc_tlv(inner, sizeof(inner), &io, 0x30 /* SEQUENCE */,
                        seq, so) < 0) return -1;
    }
    return ber_enc_tlv(buf, cap, off, TCAP_CMP_RETURN_RESULT, inner, io);
}

int tcap_enc_return_error(uint8_t *buf, size_t cap, size_t *off,
                          uint8_t invoke_id, int local_error_code,
                          const uint8_t *parameters, size_t parameters_len)
{
    return enc_component(TCAP_CMP_RETURN_ERROR, buf, cap, off,
                         invoke_id, TCAP_TAG_ERROR_LOCAL, local_error_code,
                         parameters, parameters_len);
}

/* ====================================================================== */
/* Transaction-layer encode                                               */
/* ====================================================================== */

static int enc_tid(uint8_t *buf, size_t cap, size_t *off, uint8_t tag,
                   uint32_t tid)
{
    uint8_t b[4];
    b[0] = (uint8_t)(tid >> 24);
    b[1] = (uint8_t)(tid >> 16);
    b[2] = (uint8_t)(tid >>  8);
    b[3] = (uint8_t)(tid);
    return ber_enc_tlv(buf, cap, off, tag, b, 4);
}

int tcap_encode_message(tcap_msg_type_t type,
                        uint32_t otid, bool have_otid,
                        uint32_t dtid, bool have_dtid,
                        const uint8_t *dialogue, size_t dialogue_len,
                        const uint8_t *components, size_t components_len,
                        uint8_t *out, size_t out_cap)
{
    uint8_t body[4096];
    size_t bo = 0;

    /* OTID for Begin/Continue. */
    if (have_otid) {
        if (enc_tid(body, sizeof(body), &bo, TCAP_TAG_OTID, otid) < 0)
            return -1;
    }
    /* DTID for Continue/End/Abort. */
    if (have_dtid) {
        if (enc_tid(body, sizeof(body), &bo, TCAP_TAG_DTID, dtid) < 0)
            return -1;
    }
    /* Dialogue portion. */
    if (dialogue && dialogue_len) {
        if (ber_enc_tlv(body, sizeof(body), &bo,
                        TCAP_TAG_DIALOGUE, dialogue, dialogue_len) < 0)
            return -1;
    }
    /* Component portion. */
    if (components && components_len) {
        if (ber_enc_tlv(body, sizeof(body), &bo,
                        TCAP_TAG_COMPONENTS, components, components_len) < 0)
            return -1;
    }

    /* Wrap with transaction tag. */
    uint8_t tag = 0;
    switch (type) {
    case TCAP_MSG_BEGIN:    tag = TCAP_TAG_BEGIN;    break;
    case TCAP_MSG_CONTINUE: tag = TCAP_TAG_CONTINUE; break;
    case TCAP_MSG_END:      tag = TCAP_TAG_END;      break;
    case TCAP_MSG_ABORT:    tag = TCAP_TAG_ABORT;    break;
    default: return -1;
    }
    size_t off = 0;
    if (ber_enc_tlv(out, out_cap, &off, tag, body, bo) < 0) return -1;
    return (int)off;
}
