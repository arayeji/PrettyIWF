#!/usr/bin/env bash
# Apply static PDP address changes to osmo-sgsn 1.13.1 source.
set -euo pipefail

SRC="${OSMO_SGSN_SRC:-$HOME/osmo-sgsn}"
GSUB="$SRC/src/sgsn/gprs_subscriber.c"
SGTP="$SRC/src/sgsn/sgsn_libgtp.c"

test -f "$GSUB" && test -f "$SGTP"

grep -q 'Static PDP IPv4' "$GSUB" && echo "gprs_subscriber.c already patched" || \
python3 - "$GSUB" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding='utf-8').read()
needle = "\t\tpdp_data->qos_subscribed_len = pdp_info->qos_enc_len;\n\n\t\tif (pdp_info->pdp_charg_enc"
insert = "\t\tpdp_data->qos_subscribed_len = pdp_info->qos_enc_len;\n\n\t\tmemcpy(&pdp_data->pdp_address[0], &pdp_info->pdp_address[0],\n\t\t       sizeof(pdp_data->pdp_address[0]));\n\t\tmemcpy(&pdp_data->pdp_address[1], &pdp_info->pdp_address[1],\n\t\t       sizeof(pdp_data->pdp_address[1]));\n\n\t\tif (pdp_data->pdp_address[0].u.sa.sa_family == AF_INET) {\n\t\t\tchar ip[INET_ADDRSTRLEN];\n\t\t\tosmo_sockaddr_ntop(&pdp_data->pdp_address[0].u.sa, ip);\n\t\t\tLOGGSUBSCRP(LOGL_INFO, subscr,\n\t\t\t\t    \"Static PDP IPv4 %s (ctx=%zu APN %s)\\n\",\n\t\t\t\t    ip, ctx_id, pdp_data->apn_str);\n\t\t}\n\n\t\tif (pdp_info->pdp_charg_enc"
if needle not in text:
    raise SystemExit('gprs_subscriber.c anchor not found')
open(path, 'w', encoding='utf-8').write(text.replace(needle, insert, 1))
print('patched gprs_subscriber.c')
PY

grep -q 'sgsn_subscr_pdp_by_apn' "$SGTP" && echo "sgsn_libgtp.c already patched" || \
python3 - "$SGTP" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding='utf-8').read()
helpers = '''
static struct sgsn_subscriber_pdp_data *
sgsn_subscr_pdp_by_apn(struct sgsn_mm_ctx *mmctx,
\t\t       const uint8_t *apn_wire, size_t apn_wire_len)
{
\tstruct sgsn_subscriber_pdp_data *pdp;
\tchar apn_str[GSM_APN_LENGTH];

\tif (!mmctx || !mmctx->subscr || !mmctx->subscr->sgsn_data)
\t\treturn NULL;
\tif (!apn_wire || apn_wire_len == 0)
\t\treturn NULL;
\tif (osmo_apn_to_str(apn_str, apn_wire, apn_wire_len) <= 0)
\t\treturn NULL;

\tllist_for_each_entry(pdp, &mmctx->subscr->sgsn_data->pdp_list, list) {
\t\tif (!osmo_strcasecmp(pdp->apn_str, apn_str))
\t\t\treturn pdp;
\t}
\treturn NULL;
}

static bool gtp_eua_has_ipv4(const struct pdp_t *pdp)
{
\tif (pdp->eua.l < 6)
\t\treturn false;
\tif ((pdp->eua.v[0] & 0x0f) != PDP_TYPE_ORG_IETF)
\t\treturn false;
\tif (pdp->eua.v[1] != PDP_TYPE_N_IETF_IPv4)
\t\treturn false;
\treturn *(const uint32_t *)(pdp->eua.v + 2) != 0;
}

static void gtp_eua_set_ipv4(struct pdp_t *pdp, uint32_t addr)
{
\tpdp->eua.l = 6;
\tpdp->eua.v[0] = 0xF1;
\tpdp->eua.v[1] = PDP_TYPE_N_IETF_IPv4;
\tmemcpy(pdp->eua.v + 2, &addr, 4);
}

'''
anchor1 = "\n/* generate a PDP context based on the IE's from the 04.08 message,"
if anchor1 not in text:
    raise SystemExit('sgsn_libgtp.c helper anchor not found')
text = text.replace(anchor1, helpers + anchor1, 1)
block = '''
\t/* HLR/HSS static IPv4 from GSUP INSERT_DATA (pdp_address). */
\t{
\t\tstruct sgsn_subscriber_pdp_data *sub_pdp = NULL;

\t\tif (pdp->apn_use.l)
\t\t\tsub_pdp = sgsn_subscr_pdp_by_apn(mmctx, pdp->apn_use.v, pdp->apn_use.l);
\t\tif (!sub_pdp && TLVP_PRESENT(tp, GSM48_IE_GSM_APN))
\t\t\tsub_pdp = sgsn_subscr_pdp_by_apn(mmctx,
\t\t\t\tTLVP_VAL(tp, GSM48_IE_GSM_APN),
\t\t\t\tTLVP_LEN(tp, GSM48_IE_GSM_APN));

\t\tif (sub_pdp && sub_pdp->pdp_address[0].u.sa.sa_family == AF_INET
\t\t    && !gtp_eua_has_ipv4(pdp)) {
\t\t\tchar ip[INET_ADDRSTRLEN];

\t\t\tosmo_sockaddr_ntop(&sub_pdp->pdp_address[0].u.sa, ip);
\t\t\tLOGPDPCTXP(LOGL_NOTICE, pctx,
\t\t\t\t   "Using subscribed static IPv4 %s in Create-PDP EUA\\n", ip);
\t\t\tgtp_eua_set_ipv4(pdp, sub_pdp->pdp_address[0].u.sin.sin_addr.s_addr);
\t\t}
\t}

'''
anchor2 = "\t\tpdp->apn_use.l = 0;\n\t}\n\n\t/* Protocol Configuration Options from GMM */"
if anchor2 not in text:
    raise SystemExit('sgsn_libgtp.c EUA anchor not found')
text = text.replace(anchor2, "\t\tpdp->apn_use.l = 0;\n\t}" + block + "\n\t/* Protocol Configuration Options from GMM */", 1)
open(path, 'w', encoding='utf-8').write(text)
print('patched sgsn_libgtp.c')
PY

echo "Apply complete."
