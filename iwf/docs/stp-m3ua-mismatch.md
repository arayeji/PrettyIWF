# M3UA / STP integration notes

When `[map_iwf]` is enabled, the IWF connects to **osmo-stp** as an M3UA ASP client.

## Typical checklist

1. **Routing context** — `[stp] routing_context` must match the STP `routing-key` for your AS.
2. **Network indicator** — `[stp] network_indicator` must match the STP `network-indicator`
   (e.g. `reserved` = 3 for typical osmo-stp lab configs). A mismatch yields STP
   `MGMT_ERR Unexpected Message` / `NI=0 not matching ss7 instance configured NI=3`.
3. **Point codes** — `[stp] remote_pc` must match a route the STP can reach; `[map_iwf] local_pc` is your IWF OPC.
4. **SCTP** — IWF dials `[stp] ip:port`; set `[stp] local_ip` if the STP ACLs on source address.
5. **Dynamic ASP** — Prefer STP `accept-asp-connections` / dynamic ASP; avoid conflicting static ASP definitions on the same port.

## Symptom: ASP up, no MAP / "GT Routing not implemented yet"

libosmo-sccp **cannot** route outbound SCCP with `routing-indicator GT` — IWF
must send **PC+SSN** to the STP with the HLR GT in the called-party address.
Set `[stp] remote_pc` to the STP point code (IWF uses it as outbound DPC).

- Verify SCCP subsystem and GT translation on the **STP** toward the peer HLR.
- Confirm `local_gt` and partner `[roaming_hlr]` entries match your numbering plan.

## Symptom: MGMT_ERR Unexpected Message (error 6)

STP log (osmo-stp): `Discarding received XUA Message 1:1: NI=0 not matching ss7
instance configured NI=3`. Set `[stp] network_indicator = reserved` (or `3`) to match
the STP `cs7 instance` `network-indicator` setting.

## Symptom: DUNA for 0.0.0 / "no route" on STP

STP log: `MTP-TRANSFER.req for dpc=0=0.0.0: no route!` — IWF was using CDPA PC=0.
Set `[stp] remote_pc` to the **STP's own point code** (e.g. `1.246.0` for cs7 instance 0).
IWF sends MAP with that DPC so osmo-stp handles SCCP/GTT locally instead of MTP-routing to 0.0.0.

Also add `sccp-address` GT translation on the STP for the peer HLR GT (e.g. `1234567890123` →
roaming partner route via `as-roam` / PC `6.54.2`).

## Symptom: DUNA / routing unavailable

- Check M3UA NOTIFY and route availability for the destination point code.
- Ensure only one stack binds the same SCTP port role (client vs server).

This document is deployment-agnostic; replace addresses and point codes in `iwf.conf`.
