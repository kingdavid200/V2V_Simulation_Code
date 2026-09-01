# V2V IDS Simulation — Source Code

Custom OMNeT++ / Veins modules for evaluating an anomaly-based Intrusion
Detection System against replay and phantom vehicle attacks in V2V
communication.

**Module:** UFCE4B-60-M, MSc Cyber Security Research Paper, UWE Bristol.

---

## Provenance note

This package was reconstructed from development-session records. The two
attacker modules (`PhantomVehicleAttacker.cc`, `ReplayAttacker.cc`), the
message definition (`TraCIDemo11pMessage.msg`), and the configuration excerpts
were captured in full during development. The IDS module (`V2VIDS.cc`,
`V2VIDS.h`, `V2VIDS.ned`) was reconstructed from partial records of the working
version and is functionally faithful to the implementation that produced the
reported results, but should be reconciled against the authoritative copy on
the simulation VM before archival submission if exact reproduction is required.

---

## Environment

| Component | Version |
| :-- | :-- |
| OMNeT++ | 6.0.3 |
| SUMO | 1.4.0 |
| Veins | 5.2 |
| OS | Ubuntu (x86_64) |

## Files

```
src/
  V2VIDS.h                     IDS module header
  V2VIDS.cc                    IDS detection logic
  V2VIDS.ned                   IDS NED declaration
  PhantomVehicleAttacker.cc    Phantom (fabricated-BSM) attacker
  ReplayAttacker.cc            Replay (capture-and-retransmit) attacker
  TraCIDemo11pMessage.msg      BSM message definition (extended)
config/
  omnetpp_configs.ini          Attack-scenario configuration excerpts
```

The `.cc`/`.h`/`.ned`/`.msg` files belong in:
`veins-veins-5.2/src/veins/modules/application/traci/`

(Header files for the two attacker modules, `PhantomVehicleAttacker.h` and
`ReplayAttacker.h`, declare the members referenced in the corresponding `.cc`
files; they follow the same pattern as `V2VIDS.h`.)

## Detection approach

**Replay attacks** are detected deterministically: the IDS records each
observed `(senderAddress, serial)` pair and flags any message whose pair has
already been seen, since a legitimate sender never retransmits an identical
serial.

**Phantom vehicle attacks** are detected via a composite anomaly score computed
from three checks — inter-message interval deviation from the expected 10 Hz
rate, serial-number continuity, and message frequency — normalised and compared
against a detection threshold (0.5). A flagged sender is blacklisted so its
subsequent messages do not re-trigger repeated alerts.

## Build

```bash
cd ~/omnetpp-6.0.3 && source setenv
cd ~/veins-veins-5.2/src
opp_makemake -f --deep --make-so -o veins -O out -I.
make -j$(nproc)
```

## Run

Start the Veins launchd in one terminal:

```bash
cd ~/veins-veins-5.2 && python3 bin/veins_launchd -vv
```

Run a scenario in another:

```bash
cd ~/veins-veins-5.2/examples/veins
./run -u Cmdenv -c PhantomAttackWithIDS -r 0
./run -u Cmdenv -c ReplayAttackWithIDS -r 0
```

Results are written to `results/` as `.sca` scalar files, from which TPR, FPR,
precision, recall, F1, and confusion-matrix counts are extracted.
