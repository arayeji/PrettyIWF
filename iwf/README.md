# iwf — GTP-C and MAP↔Diameter Interworking Function

Two cooperating IWF modules in one binary:

1. **GTPv1-C ⇄ GTPv2-C** (always-on, dependency-free):
   lets Osmocom **osmo-sgsn** (Gn, GTPv1-C) talk to Open5GS **SGW-C**
   (S4, GTPv2-C), while user-plane GTP-U flows directly between the RNC
   and **UPG-VPP** via 3GPP Direct Tunnel. The IWF itself never sees a
   GTP-U packet.

2. **MAP ⇄ Diameter S6d** (optional, requires `libosmo-sigtran`):
   terminates inbound MAP/Gr from roaming SGSNs over SS7 (via `osmo-stp`)
   and translates the five mobility/authentication operations to S6d
   Diameter toward PyHSS. See **MAP-IWF** section below.

```
   RNC ──── GTPv1-U (Direct Tunnel) ─────────────────┐
    │                                                ▼
    │   GTPv1-C/Gn         GTPv1-C/Gn          UPG-VPP SGW-U
osmo-sgsn ─────────► iwf ─────────► ────► (no peer)
                       │ GTPv2-C/S4
                       └─────────► Open5GS SGW-C ── PFCP ── UPG-VPP
```

**Lab (sgsnemu, no RNC):** GTP-U still comes from the SGSN host. The IWF sets **S4-SGSN-U** in Create Session Request to the **user-plane GSN** from Create PDP Request (last IE 133 when two are present, per TS 29.060 order) or, if absent, the **UDP source IP** of the request — **not** the IWF `local_ip` — so the UPF accepts GTP-U from `sgsnemu`.

**Bearer activation toward Open5GS / UPG-VPP:** sgsnemu does not send `Update PDP Context`, so the IWF would never issue a `Modify Bearer Request`. Open5GS sgwcd installs the SGW-U **DL FAR in BUFFER** until a Modify Bearer Request supplies the access-side F-TEID (visible as `FAR#1[0]: BUFFER notify_cp=1 bar_id=1` in `vppctl show upf session`). To unblock downlink, the IWF emits a Modify Bearer Request **right after** Create Session Response, reusing the SGSN GTP-U F-TEID it already learned from Create PDP Context Request. The matching MBResp does not generate a GTPv1 Update PDP Response.

## Build

The project has no external dependencies — `uthash.h` is vendored.
Targets Linux x86_64; tested with gcc 11+.

```bash
cd iwf
make            # produces ./iwf
sudo make install   # optional, copies to /usr/local/sbin
```

### Automated Ubuntu setup

```bash
cd iwf
chmod +x setup-ubuntu.sh
# Compile only (installs build-essential via apt; may use sudo):
./setup-ubuntu.sh --build-only

# Full install: binary, /etc/iwf/iwf.conf, log dir, systemd unit
sudo IWF_LOCAL_IP=10.0.0.5 IWF_SGWC_IP=10.0.0.30 ./setup-ubuntu.sh --install -y
sudo systemctl status iwf
```

See `setup-ubuntu.sh --help` and the comment block at the top of that script for manual step-by-step instructions and all environment variables.

If you see `/usr/bin/env: 'bash\r': No such file or directory`, the script has Windows (CRLF) line endings. From the `iwf` directory run `sed -i 's/\r$//' setup-ubuntu.sh` (or `dos2unix setup-ubuntu.sh`), then `chmod +x setup-ubuntu.sh` again. The repo’s `.gitattributes` keeps `*.sh` as LF on fresh clones.

### `iwf.service` exits with status 1 (restart loop)

1. **See the error in the journal** (recent builds also mirror ERROR lines to stderr):

   `sudo journalctl -u iwf -n 40 --no-pager`

2. **Check the log file** if `[logging] file` is not `-`:

   `sudo tail -50 /var/log/iwf/iwf.log`

3. **Typical causes**

   - **`local_ip must be set`** — `[iwf] listen_ip = 0.0.0.0` but `local_ip` is missing or invalid. Set `local_ip` to the host’s real Gn/S4 IPv4, or bind `listen_ip` to that address instead of `0.0.0.0`.
   - **`bind … failed: Address already in use`** — Something else already owns **UDP on that IP:port** (very often **Open5GS SGW-C** on the same VM, also bound to `*:2123` or `0.0.0.0:2123`). Only **one** process can bind a given `(local_ip, port)` pair.
     - **Preferred:** run the IWF on a **different host** (or container with its own IP) from SGW-C.
     - **Same host, two IPs:** give the machine two addresses; bind IWF with `listen_ip = <Gn-facing-IP>` and ensure SGW-C listens only on **another** local IP (see Open5GS `gtpc` `address` vs your IWF `listen_ip`). Example: IWF `listen_ip = 10.0.0.5`, SGW-C listens on `10.0.0.30` — then both can use port 2123 on **different** addresses.
     - **Not workable:** two stacks both on `0.0.0.0:2123` on one host (kernel will reject the second bind).
     - Inspect: `sudo ss -ulnp | grep 2123`
   - **`bad sgwc ip`** — typo or empty `[sgwc] ip` in `/etc/iwf/iwf.conf`.
   - **`failed to load config`** — wrong path in `ExecStart` or unreadable `/etc/iwf/iwf.conf`.

### GTPv2 Create Session Response: cause **103**

TS 29.274 value **103** = *Conditional IE missing*. With **Open5GS SGW-C**, this often means the **PGW S5/S8-C F-TEID** IE (GTPv2 **F-TEID** instance **1**) is missing from **Create Session Request** — SGWC logs **`No PGW IP`**. Set **`[smf] ip`** to your **SMF / PGW-C GTP-C IPv4** (same address as in `smf.yaml`).

**`[smf] teid` must be `0`** for an initial Create Session. Open5GS SMF treats a non-zero header TEID as a lookup into existing sessions; if no match is found it logs **`No Session`**, returns Cause **64 (Context Not Found)** with no further IEs, and Open5GS SGW-C then reports **`No GTP TEID`** / **`No PDN Address Allocation`** in `src/sgwc/s5c-handler.c` and forwards GTP cause **103** back to the IWF. SMF allocates its own S5/S8-C TEID and returns it in the Create Session Response.

### GTPv2 Create Session Response: cause **70**

`[smf] ERROR: Unknown RAT Type [1]` (smf/s5c-handler.c) means Open5GS SMF received **RAT Type = UTRAN (1)** and only accepts **EUTRAN (6)** and **WLAN (3)**. SMF returns Cause **MANDATORY_IE_INCORRECT (70)** which SGW-C forwards as GTP **70** back to the IWF. The IWF setting **`[iwf] rat_type = eutran`** (the default) makes Open5GS accept the session regardless of the real radio. Set `rat_type = utran` only if your EPC core actually supports UTRAN on S5/S8.

**ULI** can also trigger 103 for **RAT = UTRAN** if the SGW expects it. The IWF builds **ULI** from GTPv1 **RAI** when present; if your emulator omits RAI, use **`[iwf] synthetic_uli_no_rai = 1`** (lab only: IMSI PLMN + zero LAC/RAC).

If **Create Session Request** already includes **ULI** and **PGW/SMF F-TEID** (logged `len=` is larger than without `[smf]`) but the response is still **103**, Open5GS may be mapping a **PFCP** failure on **SGW-C ⇄ SGW-U** to GTP cause **103** (`gtp_cause_from_pfcp` maps PFCP *Conditional IE missing* to GTP **103**). Check **SGW-C** / **SGW-U** (or UPF) logs and **`sudo tcpdump -ni any udp port 8805 -vv`** during the attempt.

## Configuration

Edit `iwf.conf` (the install target also drops a sample at
`/etc/iwf/iwf.conf.example`):

```ini
[iwf]
listen_ip   = 0.0.0.0
listen_port = 2123
local_ip    = 10.0.0.5     ; advertised in F-TEID / GSN Address
; synthetic_uli_no_rai = 1      ; optional lab: ULI from IMSI if Gn omits RAI

[sgsn]
ip          = 10.0.0.20     ; informational only

[sgwc]
ip          = 10.0.0.30
port        = 2123

[smf]
# SMF / PGW-C S5/S8 GTP-C — F-TEID instance 1 in Create Session Request (required by Open5GS SGWC).
# teid MUST be 0 for an initial Create Session (the SMF allocates its TEID in the response).
ip          = 10.0.0.9
teid        = 0

[logging]
level       = info              ; error|warn|info|debug|trace
file        = /var/log/iwf.log  ; "-" or empty = stderr
```

> The IWF binds **one** UDP socket on `listen_port`. If `listen_ip` is a
> concrete address, the socket is bound there. If `listen_ip` is `0.0.0.0`
> and **`local_ip`** is set, the implementation binds **only** `local_ip`
> (same port) so another GTP-C process can use a different local address on
> the same host. Set environment **`IWF_LISTEN_ON_ANY=1`** to bind `0.0.0.0`
> instead. GTPv1-C and GTPv2-C are multiplexed on that socket by GTP version.

## Run

```bash
sudo ./iwf -c iwf.conf -l debug
```

The process logs structured lines with `imsi=` and `seq=` keys so a single
session can be followed end-to-end:

```text
2026-01-01T12:00:00.123 [INFO ] [translate] RX-Gn v1 Create-PDP-Req
  teid=0x00000000 seq=42 imsi=001010000000001 apn=internet ies=12
2026-01-01T12:00:00.124 [INFO ] [translate] TX-S4 Create-Session-Req
  imsi=001010000000001 seq=1 len=146
2026-01-01T12:00:00.140 [INFO ] [translate] RX-S4 v2 Create-Session-Resp
  teid=0x10000002 seq=1 imsi=001010000000001 apn=internet ies=6
2026-01-01T12:00:00.141 [INFO ] [translate] TX-Gn Create-PDP-Resp
  imsi=001010000000001 seq=42 cause=128
  sgwu=10.0.0.40 teid=0x000000a1 ue_ip=10.45.0.2
```

## Integration with osmo-sgsn

In your osmo-sgsn config, point the Gn/GGSN interface at the IWF
instead of a real GGSN:

```vty
sgsn
 ggsn 0 remote-ip 10.0.0.5   ! IWF listen_ip
 ggsn 0 gtp-version 1
 apn internet ggsn 0
```

osmo-sgsn will send Create/Update/Delete PDP Context Requests to the IWF
on UDP/2123. The IWF mints fresh control-plane TEIDs and advertises its
own IP in the GSN Address IE, so osmo-sgsn treats it as if it were a
GGSN.

## Integration with Open5GS SGW-C

Open5GS SGW-C expects S4 traffic from an SGSN on UDP/2123. The IWF acts
as that SGSN. In `sgwc.yaml`:

```yaml
sgwc:
  gtpc:
    server:
      - address: 10.0.0.30   # SGW-C listens here
  pfcp:
    server:
      - address: 10.0.0.30
    client:
      sgwu:
        - address: 10.0.0.40  # UPG-VPP PFCP address
```

No explicit per-SGSN peer config is needed — Open5GS accepts S4 by
source IP. Just make sure routing lets the IWF's `local_ip` reach SGW-C
on UDP/2123.

The IWF must also send **SMF’s S5/S8-C F-TEID** inside **Create Session Request** (see **`[smf]`** in `iwf.conf`). Match **`[smf] ip`** to the SMF GTP-C address in **`smf.yaml`** (`s5c` / `gtpc`). **`[smf] teid`** must be the TEID SMF uses for that GTP peer (see SGWC/SMF logs or a packet capture from a known-good session).

## PFCP verification on UPG-VPP

After a PDP Context is established you can confirm UPG-VPP has the
session installed:

```bash
# UPG-VPP CLI inside VPP
vppctl show upf session
vppctl show upf far
vppctl show upf pdr

# expected: 1 session per UE, 2 PDRs (UL + DL), 2 FARs
# the DL FAR forwards to the RNC's TEID once Update PDP Context arrives.
```

You can also watch PFCP on the SGW-C ⇆ UPG-VPP link:

```bash
sudo tcpdump -ni any -s0 udp port 8805 -vv
# - Session Establishment Request (after Create PDP)
# - Session Modification Request  (after Update PDP - RNC TEID is plumbed)
# - Session Deletion Request      (after Delete PDP)
```

## GTPv1-C / GTPv2-C message traces

Sniff Gn (osmo-sgsn ⇄ iwf):

```bash
sudo tcpdump -ni any -s0 udp port 2123 and host 10.0.0.20 -vv
```

Sniff S4 (iwf ⇄ SGW-C):

```bash
sudo tcpdump -ni any -s0 udp port 2123 and host 10.0.0.30 -vv
```

Or open Wireshark with the `gtp` and `gtpv2` dissectors enabled. The
IWF emits TRACE-level hex dumps of every message it transmits when
`logging.level = trace`.

### Example end-to-end flow

```
osmo-sgsn → IWF       GTPv1 Create PDP Context Request seq=42
                       IMSI=001010000000001 NSAPI=5 APN=internet
                       TEID-C=0xa0 TEID-D=0xb0 GSN=10.0.0.20
IWF      → SGW-C      GTPv2 Create Session Request    seq=1 TEID=0
                       IMSI MSISDN ULI ServingNet RAT=UTRAN
                       F-TEID(S4-SGSN-C)=0x10000002@10.0.0.5
                       F-TEID(S5/S8-PGW-C)=<smf>@<smf-ip>
                       APN=internet PDN=IPv4 PAA=0.0.0.0 AMBR=1G/1G
                       BearerCtx{EBI=5 QoS{QCI=9} F-TEID(S4-SGSN-U)}
SGW-C    → IWF        GTPv2 Create Session Response   seq=1 cause=16
                       F-TEID(S5/S8-SGW-C)=0x20000001@10.0.0.30
                       PAA=10.45.0.2
                       BearerCtx{EBI=5 cause=16
                         F-TEID(S1U-SGW-U)=0xa1@10.0.0.40}
IWF      → osmo-sgsn  GTPv1 Create PDP Context Response seq=42 cause=128
                       Reordering=0xfe ChargingId TEID-D=0xa1
                       TEID-C(IWF)=0x10000001 EUA=10.45.0.2
                       GSN(C)=10.0.0.5 GSN(U)=10.0.0.40
                       (TS 29.060: two IE 133 in this order — user plane is SGW-U)
osmo-sgsn → RNC       RAB Assignment (uses TEID-D=0xa1 @ 10.0.0.40)
RNC      → UPG-VPP    GTPv1-U packets directly to 10.0.0.40 / 0xa1
```

`Update PDP Context` (the RNC's TEID, learned after RAB establishment)
is translated to `Modify Bearer Request`; the bearer-context F-TEID for
S4-SGSN-U is updated to point at the RNC so UPG-VPP knows where to send
DL packets.

## Project layout

```
iwf/
  main.c          - entry point, epoll event loop, UDP I/O
  iwf.h           - 3GPP constants and shared helpers
  gtpv1.[ch]      - GTPv1-C TS 29.060 wire format
  gtpv2.[ch]      - GTPv2-C TS 29.274 wire format
  session.[ch]    - per-IMSI/NSAPI state machine + uthash table
  translate.[ch]  - IE mapping & state transitions
  config.[ch]     - INI-style config parser
  logging.[ch]    - structured logger
  runtime.h       - process-wide handles
  uthash.h        - single-header hash table (vendored)
  Makefile        - C11, no external deps
  iwf.conf        - sample configuration
```

## Error handling at a glance

| Condition                              | Behaviour                                              |
|----------------------------------------|---------------------------------------------------------|
| Malformed GTP datagram                 | Logged at WARN, dropped, no state change                |
| Unknown TEID in inbound v2 response    | Logged at WARN, dropped                                 |
| Session idle > `IWF_SESSION_TIMEOUT_S` | Periodic sweep removes the session and frees both TEIDs |
| SGW-C unreachable (ICMP unreachable)   | `sendto()` errno surfaces via `iwf_send_v2` log line    |
| Create/Modify/Delete Resp cause != 16  | Mapped to GTPv1 cause 199 (No Resources) toward SGSN    |

## Notes / known limits

- IPv6 PDP contexts are not yet plumbed (PAA decoder accepts IPv4 only).
- 3G QoS Profile → QCI mapping is a sensible best-effort default (see
  `translate.c::map_qos_to_qci_ambr`). Extend it with operator policy as
  needed.
- Retransmissions are detected via session state (a CSReq for a session
  already in `WAIT_CS_RESP` is silently coalesced); a formal T3/N3
  retry timer can be added on top of the existing timerfd loop.

---

## MAP-IWF (MAP ⇄ Diameter S6d)

A second, independently-enabled module inside the same `iwf` binary.
It receives MAP/Gr from a foreign SGSN (over SS7 via `osmo-stp`) and
translates to Diameter S6d toward PyHSS. The two modules share the
event loop, config system and logging.

```
   Foreign SGSN (roaming)
        │  MAP/Gr (SS7 over SCTP/GRX)
        ▼
   osmo-stp ──── M3UA/SCCP ────► iwf (MAP-IWF) ──── Diameter S6d ────► PyHSS
                                  ▲
                                  └── same process, same epoll loop as
                                      the GTP IWF described above
```

### Operations translated (3GPP TS 29.002 ⇄ TS 29.272)

| MAP operation (Gr)                | Diameter command (S6d) |
|-----------------------------------|------------------------|
| `sendAuthenticationInfo`  (op 56) | AIR/AIA (cmd 318)      |
| `updateGprsLocation`      (op 23) | ULR/ULA (cmd 316)      |
| `cancelLocation`          (op 3 ) | CLR/CLA (cmd 317)      |
| `purgeMS`                 (op 67) | PUR/PUA (cmd 321)      |
| `insertSubscriberData`    (op 7 ) | (pushed inside UGL flow after ULA) |

For `updateGprsLocation` the IWF synthesises an `insertSubscriberData`
Invoke toward the SGSN carrying MSISDN / APN / AMBR pulled out of the
ULA `Subscription-Data`, exactly like a real HLR would; then the
parent UGL ReturnResult is emitted.

### File map

```
map_iwf.{c,h}      module entrypoint + per-operation translation engine
map_iwf_priv.h     internal shared state (Diameter + SS7 + sweep timer)
map_session.{c,h}  dialogue table, keyed on TCAP TID; secondary index on
                   Diameter Session-Id
tcap.{c,h}         minimal TCAP (Q.771) + BER primitives
map_codec.{c,h}    ASN.1 BER codec for the five MAP operations + AARQ/AARE
diameter.{c,h}     Diameter base (CER/DWR/DPR) + S6d AIR/ULR/CLR/PUR codec
ss7_link.{c,h}     libosmo-sigtran M3UA/SCCP glue (stubbed when
                   built without MAP_IWF_ENABLED=1)
```

### Build

```bash
# GTP-only build (default; no extra deps):
make

# Full build with MAP-IWF (requires libosmocore + libosmo-sigtran + libosmo-sccp):
sudo apt install libosmocore-dev libosmo-sccp-dev libosmo-sigtran-dev
make clean
make MAP_IWF_ENABLED=1
```

If `MAP_IWF_ENABLED=1` is omitted but `[map_iwf].enabled = 1` in
`iwf.conf`, the binary refuses to bring MAP-IWF up at startup with a
clear error pointing to the rebuild flag.

### Configuration

See the three new sections appended to `iwf.conf`:

```ini
[map_iwf]
enabled       = 1
local_gt      = 1234567890      ; your network E.164 Global Title
local_pc      = 1.2.3            ; ITU 3-8-3 point code
local_ssn     = 149              ; SGSN SSN
t_dialogue_ms = 10000

[stp]
ip            = 127.0.0.1        ; osmo-stp SCTP IP
port          = 2905             ; M3UA port
remote_pc     = 1.2.1

[diameter_s6d]
peer_ip       = 10.0.0.50    ; PyHSS Diameter IP
peer_port     = 3868
origin_host   = iwf.mnc012.mcc432.3gppnetwork.org
origin_realm  = mnc012.mcc432.3gppnetwork.org
dest_host     = pyhss.mnc012.mcc432.3gppnetwork.org
dest_realm    = mnc012.mcc432.3gppnetwork.org
watchdog_ms   = 30000
request_timeout_ms = 10000
```

### Event-loop wiring

`main.c` adds four extra fds to its single epoll set when
`map_iwf_enabled()` is true:

| Role                       | fd source                       | Handler                          |
|----------------------------|---------------------------------|----------------------------------|
| `MAP_EPOLL_ROLE_SS7`       | libosmo-sigtran SCCP user       | `map_iwf_on_ss7_readable()`      |
| `MAP_EPOLL_ROLE_DIAMETER`  | TCP socket to PyHSS             | `map_iwf_on_diameter_readable()` |
| `MAP_EPOLL_ROLE_DWA_TIMER` | timerfd (Tw, default 30s)       | `map_iwf_on_dwa_timer_tick()`    |
| `MAP_EPOLL_ROLE_T_TIMER`   | timerfd (1s sweep)              | `map_iwf_on_ttimer_tick()`       |

Role tags live in a disjoint numeric range from `SOCK_GTP` / `SOCK_TIMER`,
so the dispatcher in `main.c` is a single `switch` with no overlap.

### Per-dialogue state

```c
struct map_session {
    uint32_t   tcap_dialogue_id;     /* our originating TID  */
    uint32_t   peer_tcap_dialogue_id;/* SGSN-allocated peer  */
    char       imsi_str[16];         /* "001010000000001"    */
    char       diameter_session_id[128];
    uint32_t   diameter_hop_by_hop;
    uint32_t   diameter_end_to_end;
    map_op_t   map_op;
    map_sess_state_t state;          /* IDLE / WAIT_DIAMETER / WAIT_MAP_TX /
                                        WAIT_MAP_ACK / DONE / ABORTED */
    struct in_addr sgsn_ip;
    uint32_t   sccp_conn_id;
    uint8_t    visited_plmn_bcd[3];  /* TS 24.008 packed     */
    map_auth_vector_t av[5];         /* for SAI flow         */
    char       msisdn_str[24];       /* extracted from ULA   */
    char       ula_apn[64];
    uint64_t   ula_ambr_ul_bps, ula_ambr_dl_bps;
    time_t     created_at, last_activity;
    int        t_dialogue_ms;
};
```

Primary index `hh_tid` is keyed on `tcap_dialogue_id`; secondary index
`hh_sid` is keyed on the Diameter `Session-Id` string so answer messages
arriving on the shared TCP connection can be routed back in O(1).

### IE mappings

**SAI → AIR**

| MAP                                    | Diameter (S6d)                          |
|----------------------------------------|------------------------------------------|
| `IMSI`                                 | `User-Name`                              |
| derived from IMSI MCC/MNC              | `Visited-PLMN-Id`                        |
| `numberOfRequestedVectors = 5`         | grouped `Requested-UTRAN-GERAN-Auth-Info`|
| (constant)                             | `Immediate-Response-Preferred = 1`       |
| (constant)                             | `RAT-Type = 1001 (GPRS)`                 |

**AIA → SAI Resp**

| Diameter `Authentication-Info` child   | MAP `AuthenticationQuintuplet`          |
|----------------------------------------|------------------------------------------|
| `E-UTRAN-Vector` / `UTRAN-Vector`      | one quintuplet per vector                |
| `RAND, AUTN, XRES, CK, IK`             | repacked verbatim into MAP OCTET STRINGs |

(Up to 5 vectors are returned in `AuthenticationSetList`.)

**UGL → ULR**

| MAP                | Diameter                                    |
|--------------------|---------------------------------------------|
| `IMSI`             | `User-Name`                                 |
| `sgsn-Number`      | (used to derive `Origin-Host` of the SGSN — informational) |
| derived from IMSI  | `Visited-PLMN-Id`                           |
| (constant)         | `ULR-Flags = S6d-Indicator + GPRS-Subscription-Required` |
| (constant)         | `RAT-Type = 1001 (GPRS)`                    |

**ULA → ISD (Invoke) + UGL Resp**

| Diameter `Subscription-Data`           | MAP `InsertSubscriberData` Invoke argument |
|----------------------------------------|--------------------------------------------|
| `MSISDN` AVP (701)                     | `msisdn` (ISDN-AddressString)              |
| `APN-Configuration.Service-Selection`  | `apn-Configuration-Profile.APN`            |
| `APN-Configuration.AMBR`               | `apn-Configuration.AMBR` (kbps, /1000)     |

### Error handling

| Condition                              | Behaviour                                                 |
|----------------------------------------|------------------------------------------------------------|
| Diameter `Result-Code` ≠ 2001/2002     | MAP `ReturnError(systemFailure)` + TCAP-End to SGSN        |
| Diameter `User-Unknown` (5001)         | MAP `ReturnError(unknownSubscriber)`                       |
| Diameter `Roaming-Not-Allowed`         | MAP `ReturnError(roamingNotAllowed)`                       |
| TCAP T-dialogue (default 10s)          | dialogue swept; ABORT generated implicitly by stale TID    |
| Diameter peer disconnect mid-request   | in-flight dialogues fail with MAP SystemFailure            |
| TCP/SCTP failure                       | exponential backoff reconnect (1s → 60s)                   |

### Operational notes

- The Diameter side opens a single TCP connection; `CER/CEA` runs at
  startup and `DWR` ticks every `watchdog_ms`. A peer `DPR` triggers a
  clean disconnect + scheduled reconnect.
- The SS7 side runs as an M3UA ASP (IPSP-client) against `osmo-stp`.
  `osmo-stp` does the GT/PC routing; the IWF just owns an SSN.
- Stats are emitted at shutdown (`map_rx`, `map_tx`, `diam_rx`,
  `diam_tx`, `timeouts`, `sysfail`). Hook them into Prometheus later
  via a small exporter — the counters live in `map_iwf_state.stat_*`.

## License

Provided as-is for production integration work. Bring your own license.
