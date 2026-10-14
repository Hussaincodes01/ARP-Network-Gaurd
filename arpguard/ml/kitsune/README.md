# Vendored Kitsune / KitNET

Upstream: https://github.com/ymirsky/Kitsune-py (commit `7c8ea51`), MIT licence
(see `LICENSE`). Paper: Mirsky et al., *Kitsune: An Ensemble of Autoencoders
for Online Network Intrusion Detection*, NDSS 2018.

Only the model and the feature statistics are vendored (`AfterImage.py`,
`netStat.py`, `KitNET/`). ARPGuard feeds packets in with its own parser
(`arpguard/core/parser.py`) instead of upstream's tshark/scapy
`FeatureExtractor.py`, using the same field rules (ARP uses the ARP
sender/target IPs and the protocol tag `arp`, ICMP uses `icmp`, and frames
with no network layer fall back to the MAC addresses).

Every change from upstream is marked `[arpguard]` in the source:

| File | Change | Why |
|---|---|---|
| `AfterImage.py` | `np.Inf` → `np.inf`, `np.na` → `np.nan`, dropped a debug `print` | `np.Inf` was removed in NumPy 2; `np.na` was a typo that would raise |
| `netStat.py` | dropped `pyximport`, relative import, fixed `np.isnan(list)` | no Cython toolchain needed; the old check raised on a list of lambdas |
| `KitNET/KitNET.py` | relative imports, `print` → `logging` | package-safe imports, quiet output |
| `KitNET/dA.py` | relative import, `numpy.Inf` → `numpy.inf` | NumPy 2 |
| `KitNET/utils.py` | SciPy imported lazily | SciPy is only needed by an unused helper |
| `KitNET/corClust.py` | falls back to `KitNET/_linkage.py` when SciPy is absent | keeps the serverless bundle small |

`KitNET/_linkage.py` re-implements SciPy's single-linkage algorithm (Prim's
MST, stable sort, union-find relabelling) so the learned feature map is the
same with or without SciPy; `tests/test_kitsune.py` checks this when SciPy is
installed.
