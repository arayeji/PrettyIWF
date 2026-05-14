/*
 * tcap.h - minimal TCAP (ITU-T Q.771 / Q.773) BER codec for the MAP IWF.
 *
 * We implement only what the five supported MAP operations need:
 *
 *   - Transaction portion:
 *       Begin       [APPLICATION 2]  0x62   (received from SGSN, sent to SGSN
 *                                            for IWF-originated Cancel/ISD)
 *       Continue    [APPLICATION 5]  0x65
 *       End         [APPLICATION 4]  0x64
 *       Abort       [APPLICATION 7]  0x67
 *
 *   - Transaction IDs (octet string, 1..4 bytes):
 *       Origin TID      [APPLICATION 8]   0x48
 *       Destination TID [APPLICATION 9]   0x49
 *
 *   - Dialogue portion:        [APPLICATION 11]  0x6B  (carries AARQ/AARE OID)
 *   - Component portion:       [APPLICATION 12]  0x6C
 *       Invoke              [1]  0xA1
 *       ReturnResultLast    [2]  0xA2
 *       ReturnError         [3]  0xA3
 *       Reject              [4]  0xA4
 *
 * The codec is zero-copy on decode (each tcap_component_t.parameters points
 * into the caller buffer) and append-only on encode (the caller passes a
 * scratch buffer big enough for the largest message, ~2 kB is plenty).
 *
 * No fragmentation, no extended-length forms over 64 KB, no class 4 (reject
 * generation; we just log on receive).  Real-world MAP/Gr messages are well
 * under 1 KB.
 */

#ifndef IWF_TCAP_H
#define IWF_TCAP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* TCAP message type tags (BER, APPLICATION class, constructed). */
#define TCAP_TAG_BEGIN          0x62
#define TCAP_TAG_END            0x64
#define TCAP_TAG_CONTINUE       0x65
#define TCAP_TAG_ABORT          0x67

#define TCAP_TAG_OTID           0x48        /* Origin Transaction ID       */
#define TCAP_TAG_DTID           0x49        /* Destination Transaction ID  */
#define TCAP_TAG_DIALOGUE       0x6B
#define TCAP_TAG_COMPONENTS     0x6C

/* Component tags (BER, CONTEXT-SPECIFIC class, constructed). */
#define TCAP_CMP_INVOKE         0xA1
#define TCAP_CMP_RETURN_RESULT  0xA2
#define TCAP_CMP_RETURN_ERROR   0xA3
#define TCAP_CMP_REJECT         0xA4

/* Component sub-element tags. */
#define TCAP_TAG_INVOKE_ID      0x02        /* INTEGER */
#define TCAP_TAG_LINKED_ID      0x80        /* [0] INTEGER */
#define TCAP_TAG_OPCODE_LOCAL   0x02        /* INTEGER (local code)     */
#define TCAP_TAG_OPCODE_GLOBAL  0x06        /* OBJECT IDENTIFIER        */
#define TCAP_TAG_ERROR_LOCAL    0x02        /* INTEGER (error code)     */

/* Per-dialogue defaults (matches the [map_iwf].t_dialogue_ms config knob). */
#define TCAP_DEFAULT_T_MS       10000

/* ----- Decoded view ------------------------------------------------- */

typedef enum {
    TCAP_MSG_BEGIN              = TCAP_TAG_BEGIN,
    TCAP_MSG_CONTINUE           = TCAP_TAG_CONTINUE,
    TCAP_MSG_END                = TCAP_TAG_END,
    TCAP_MSG_ABORT              = TCAP_TAG_ABORT,
} tcap_msg_type_t;

typedef enum {
    TCAP_CMP_KIND_INVOKE        = TCAP_CMP_INVOKE,
    TCAP_CMP_KIND_RES           = TCAP_CMP_RETURN_RESULT,
    TCAP_CMP_KIND_ERR           = TCAP_CMP_RETURN_ERROR,
    TCAP_CMP_KIND_REJECT        = TCAP_CMP_REJECT,
} tcap_component_kind_t;

typedef struct {
    tcap_component_kind_t kind;
    uint8_t   invoke_id;            /* TS Q.773 §3.2 - signed but we keep 1B */
    bool      have_linked_id;
    uint8_t   linked_id;
    int       opcode;               /* local code (MAP operationCode) or -1   */
    int       error_code;           /* local code for ReturnError (or -1)     */
    const uint8_t *parameters;      /* points into the caller buffer          */
    size_t    parameters_len;
} tcap_component_t;

#define TCAP_MAX_COMPONENTS         4

typedef struct {
    tcap_msg_type_t   type;
    bool              have_otid;
    uint32_t          otid;         /* 1..4 octets, big-endian, stored as u32 */
    bool              have_dtid;
    uint32_t          dtid;
    /* Dialogue portion (AARQ/AARE etc.) - kept as opaque bytes; we only
     * inspect the application context OID via tcap_dialogue_oid_get(). */
    const uint8_t    *dialogue;
    size_t            dialogue_len;
    tcap_component_t  components[TCAP_MAX_COMPONENTS];
    size_t            n_components;
    const uint8_t    *raw;
    size_t            raw_len;
} tcap_msg_t;

int  tcap_decode(const uint8_t *buf, size_t len, tcap_msg_t *out);

/* If the dialogue portion is present and carries an AARQ (Begin) or AARE
 * (Continue/End), return the application-context OID and its length. The
 * returned pointer is non-NULL on success and points into the caller buffer.
 * Returns -1 if the dialogue portion is absent or malformed. */
int  tcap_dialogue_oid_get(const tcap_msg_t *msg,
                           const uint8_t **out_oid, size_t *out_len);

/* ----- Encoding ----------------------------------------------------- */

/* Component layer encoder.  Appends a single Invoke / ReturnResult / Error
 * component to the buffer in `buf` (at `*off`).  Returns the bytes written
 * or -1 if the buffer is too small. */
int  tcap_enc_invoke(uint8_t *buf, size_t cap, size_t *off,
                     uint8_t invoke_id, int local_opcode,
                     const uint8_t *parameters, size_t parameters_len);

int  tcap_enc_return_result(uint8_t *buf, size_t cap, size_t *off,
                            uint8_t invoke_id, int local_opcode,
                            const uint8_t *parameters, size_t parameters_len);

int  tcap_enc_return_error(uint8_t *buf, size_t cap, size_t *off,
                           uint8_t invoke_id, int local_error_code,
                           const uint8_t *parameters, size_t parameters_len);

/* Transaction layer encoder.  Builds a complete TCAP message into `out`.
 *
 *   - Begin:    type=BEGIN, otid required, dtid ignored.
 *   - Continue: type=CONTINUE, both ids required.
 *   - End:      type=END, dtid required, otid ignored.
 *   - Abort:    type=ABORT, dtid required, components ignored.
 *
 * `dialogue` may be NULL to omit the dialogue portion (legal for MAP v1
 * but our typical flow always carries an AARQ/AARE).
 *
 * Returns total length written, or -1 on encoder error. */
int  tcap_encode_message(tcap_msg_type_t type,
                         uint32_t otid, bool have_otid,
                         uint32_t dtid, bool have_dtid,
                         const uint8_t *dialogue, size_t dialogue_len,
                         const uint8_t *components, size_t components_len,
                         uint8_t *out, size_t out_cap);

/* Helpers used internally and by map_codec.c. */
int  ber_enc_tag(uint8_t *buf, size_t cap, size_t *off, uint8_t tag);
int  ber_enc_length(uint8_t *buf, size_t cap, size_t *off, size_t len);
int  ber_enc_tlv(uint8_t *buf, size_t cap, size_t *off,
                 uint8_t tag, const uint8_t *val, size_t val_len);
int  ber_enc_integer_u32(uint8_t *buf, size_t cap, size_t *off,
                         uint8_t tag, uint32_t v);
int  ber_dec_tlv(const uint8_t *buf, size_t len, size_t *off,
                 uint8_t *out_tag, const uint8_t **out_val, size_t *out_val_len);
int  ber_dec_length(const uint8_t *buf, size_t len, size_t *off, size_t *out_len);
int  ber_dec_integer_u32(const uint8_t *val, size_t val_len, uint32_t *out);

#endif /* IWF_TCAP_H */
