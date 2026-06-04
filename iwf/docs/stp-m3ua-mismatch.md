# IWF ↔ osmo-stp M3UA mismatch (tracked)

**Host:** lab-epc01 `10.0.0.5`  
**STP:** `10.0.0.21:2905` (dynamic ASP e.g. `asp-dyn-*`)  
**IWF ASP:** `asp-clnt-iwf` (libosmo `osmo_sccp_simple_client`, IPSP **client**)  
**Status:** Open — MAP may work intermittently; STP load + log churn from M3UA errors

## Symptoms

| Side | Log |
|------|-----|
| IWF | `asp-asp-clnt-iwf: Received unsupported M3UA Message Class 2` |
| IWF | `ASPTM-ASP_AC_ACK not permitted` (state `ASP_ACTIVE`) |
| STP | `MGMT_ERR 'Unsupported Message Class'` |
| STP | `MGMT_ERR 'Unexpected Message'` |

Config alignment (looks OK on paper):

- `[stp] routing_context = 4` ↔ STP `routing-key 4` → OPC `1.2.3`
- `[map_iwf] local_pc = 1.2.3`
- `[stp] remote_pc = 6.54.2` (STP reachable PC)

## M3UA message classes (RFC 4666)

| Class | Name | Who sends to IWF ASP |
|-------|------|----------------------|
| 0 | MGMT | Optional |
| 1 | Transfer (payload) | **Required** for MAP/SCCP |
| 2 | **SSNM** (DUNA/DAVA/…) | **STP (SG)** → ASP — normal |
| 3 | ASPSM (ASP Up/Down) | Handshake |
| 4 | ASPTM (ASP Active/Inactive) | Handshake |

**Class 2** is not a “wrong protocol” — it is **signalling network management** from the SG.  
IWF logs “unsupported” when **libosmo-sigtran** on the ASP does not handle that SNM (older build) or handles it only in the wrong FSM state.

## Root cause (working theory)

1. **SSNM (class 2) from STP** after ASP goes **ACTIVE** — expected SG behaviour.
2. **IWF libosmo** either:
   - too old → logs *Unsupported Message Class 2* and may return M3UA Error → STP **MGMT_ERR**, or
   - receives SNM in a bad state → **Unexpected Message** on STP.
3. **`ASPTM-ASP_AC_ACK not permitted` in `ASP_ACTIVE`:** duplicate / late **ASP Active** handshake — STP sends `ASPAC_ACK` when IWF FSM already ACTIVE (re-sync, dynamic ASP + static name clash, or SCTP flap).

**Not** caused by wrong `routing_context` alone (RCTX=4 matches).

## Runtime evidence (2026-06-03)

```
NOTIFY AS Inactive → Ignoring M-ASP_ACTIVE.confirm → NOTIFY AS Active
→ unsupported M3UA Message Class 2
→ ASPTM-ASP_AC_ACK not permitted
```

SCTP/M3UA does reach **ASP_ACTIVE** briefly; errors are **post-activation** noise + possible STP error PDUs.

## Checks (STP — `10.0.0.21`)

```bash
# VTY
show cs7 instance 0
show cs7 asp
show cs7 as
```

Verify:

- [ ] **One** ASP path for IWF: either **dynamic** `accept-asp-connections` **or** static `asp … 2905` — not both fighting for same peer IP.
- [ ] Dynamic ASP uses **passive** / server role; IWF is **client** (ephemeral source port).
- [ ] `routing-key 4` → DPC `1.2.3` (packed from `1.2.3` = `0x002b` / ITU 14-bit — confirm STP uses same format).
- [ ] No second static `asp-clnt-iwf` bound to wrong IP if only dynamic is intended.
- [ ] `permit_dyn_rkm_alloc` / RKM policy matches fixed `routing_context=4`.

## Checks (IWF — `10.0.0.5`)

```bash
grep -A8 '^\[stp\]' /etc/iwf/iwf.conf
grep -A6 '^\[map_iwf\]' /etc/iwf/iwf.conf
journalctl -u iwf -f | grep -iE 'm3ua|asp|ss7'
```

Verify:

- [ ] `ip = 10.0.0.21` (not `127.0.0.1` sample from repo).
- [ ] `local_ip = 10.0.0.5` if STP ACLs on source.
- [ ] `routing_context = 4` matches STP.
- [ ] libosmo-sigtran version on build host (SNM-on-ASP support landed ~2021 in libosmo-sigtran).

## Remediation options

| Priority | Action |
|----------|--------|
| P1 | **STP:** single ASP model for IWF (dynamic only); remove duplicate static ASP for same client name/IP. |
| P1 | **Upgrade** libosmo-sigtran/libosmocore on IWF build to version with `m3ua_rx_snm_asp()` (handles DUNA/DAVA; ignores DUPU/SCON/DRST silently). |
| P2 | **STP:** if Huawei/SG sends heavy SSNM, confirm no Error PDU storm back to dynamic ASP. |
| P2 | **IWF code:** `ss7_link.c` skips `osmo_ss7_asp_restart()` when `osmo_ss7_asp_active()` (reduces duplicate ASPTM). |
| P3 | Capture `tcpdump -i any host 10.0.0.21 and sctp port 2905` during flap — classify class 2/3/4 PDU direction. |

## Success criteria

- [ ] No `unsupported M3UA Message Class 2` on IWF for 15+ minutes idle.
- [ ] No `ASPTM-ASP_AC_ACK not permitted` after stable ACTIVE.
- [ ] No STP `MGMT_ERR` on `asp-dyn-*` for IWF source IP.
- [ ] MAP TCAP (MCI roaming) TX/RX on SSN 149 without SS7 retry storms.

## Code references (IWF)

- `iwf/ss7_link.c` — `osmo_sccp_simple_client()`, RCTX, `osmo_ss7_asp_restart()`
- `iwf/main.c` — `map_iwf_on_ss7_readable()` → `osmo_select_main_ctx(1)` each epoll idle tick
- `iwf/iwf.conf` `[stp]` comments on client/ephemeral port vs STP :2905

## Related (separate issues)

- IWF → DRA Diameter **CEA 3010** (unknown peer) — not M3UA; see Diameter `peer_ip` / AcceptPeer on DRA.
- Huawei `hiwebmme01` SCTP peer **DOWN** — separate from STP M3UA.
