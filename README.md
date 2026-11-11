# md-dsp

scripts and data from my (Michael Doyle's) work in Notre Dame's Data Security and Privacy Lab.

`colocation/` holds 23 create→quote→delete cycles of c3-standard-4 TDX Confidential VMs (on-demand, one project, us-central1-a, 2026-10-28). The cycles ran one at a time, so the data tests host reuse, not concurrent co-residency. `data/tdx_cycles_10_28_raw.csv` is the record; the _statistics CSV adds creation-timing statistics and omits the three 18:26–18:32 runs. `data/ppid_map.csv` maps each instance to the PPID and Platform Instance ID in its PCK certificate; quote signatures were not verified. `loadbalancer/` is a placeholder for potential future work.

```
dsp-lab/
├── colocation/
│   ├── scripts/
│   └── data/
└── loadbalancer/
```
