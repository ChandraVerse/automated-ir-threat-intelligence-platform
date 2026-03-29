# Memory Analysis Samples

This directory stores memory dump files used for Volatility analysis.

## Adding a Sample

1. Obtain a raw memory dump (`.raw`, `.mem`, `.vmem`, `.dmp`)
2. Place it in this directory
3. Run the dispatcher:

```bash
python -m memory_analysis.dispatcher --dump memory-analysis/samples/your_dump.raw --output output/
```

## Sample Output

After running the dispatcher, JSON artifacts are placed in `output/`:

```
output/
  pslist_<timestamp>.json
  netscan_<timestamp>.json
  dlllist_<timestamp>.json
  malfind_<timestamp>.json
```

## Note

Memory dumps are **not committed to this repository** (added to `.gitignore`).
For testing, use public DFIR challenge images from:
- https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
- https://cyberdefenders.org
