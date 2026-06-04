# M3UA / STP integration notes

When `[map_iwf]` is enabled, the IWF connects to **osmo-stp** as an M3UA ASP client.

## Typical checklist

1. **Routing context** — `[stp] routing_context` must match the STP `routing-key` for your AS.
2. **Point codes** — `[stp] remote_pc` must match a route the STP can reach; `[map_iwf] local_pc` is your IWF OPC.
3. **SCTP** — IWF dials `[stp] ip:port`; set `[stp] local_ip` if the STP ACLs on source address.
4. **Dynamic ASP** — Prefer STP `accept-asp-connections` / dynamic ASP; avoid conflicting static ASP definitions on the same port.

## Symptom: ASP up, no MAP

- Verify SCCP subsystem and GT routing on the STP toward the peer HLR/SGSN.
- Confirm `local_gt` and partner `[roaming_hlr]` entries match your numbering plan.

## Symptom: DUNA / routing unavailable

- Check M3UA NOTIFY and route availability for the destination point code.
- Ensure only one stack binds the same SCTP port role (client vs server).

This document is deployment-agnostic; replace addresses and point codes in `iwf.conf`.
