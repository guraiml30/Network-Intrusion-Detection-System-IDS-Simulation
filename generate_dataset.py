"""Write a synthetic flow dataset to data/sample_flows.csv."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from netids.simulator import generate_traffic  # pyright: ignore[reportMissingImports]

out = ROOT / "data" / "sample_flows.csv"
out.parent.mkdir(exist_ok=True)
df = generate_traffic(3000, seed=42)
df.to_csv(out, index=False)
print(f"Wrote {len(df)} synthetic flows to {out}")
print(df["label"].value_counts().to_string())
