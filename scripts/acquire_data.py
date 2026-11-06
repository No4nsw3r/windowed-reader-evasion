"""Acquire the starter datasets into isolated dirs. Downloads only.
Nothing here executes skill content; files are treated as inert data."""
import os, pyarrow as pa, pyarrow.parquet as pq
from huggingface_hub import snapshot_download, HfFileSystem

BASE = r".\data"

# 1) MaliciousSkillBench — full (35 MB), labeled malicious/benign + fixed splits
print("[1] MaliciousSkillBench: downloading full snapshot ...")
dst = os.path.join(BASE, "malicious_skill_bench")
snapshot_download(repo_id="ProtectSkills/MaliciousSkillBench",
                  repo_type="dataset", local_dir=dst)
print("    -> done:", dst)

# 2) SkillMD-138K — bounded sample (first ~2000 rows streamed, no 560MB pull)
print("[2] SkillMD-138K: streaming a bounded sample (no full download) ...")
fs = HfFileSystem()
src = "datasets/FayeZC/SkillMD-138K/train.parquet"
with fs.open(src, "rb") as f:
    pf = pq.ParquetFile(f)
    total_rows = pf.metadata.num_rows
    cols = pf.schema_arrow.names
    first = next(pf.iter_batches(batch_size=2000))
tbl = pa.Table.from_batches([first])
out = os.path.join(BASE, "skillmd_138k", "sample_2000.parquet")
os.makedirs(os.path.dirname(out), exist_ok=True)   # was missing: this script exited 1 on
                                                   # FileNotFoundError on a clean checkout
pq.write_table(tbl, out)
print(f"    full file rows: {total_rows:,}  columns: {cols}")
print(f"    -> wrote sample rows: {tbl.num_rows} to {out}")
print()
print("    NOTE: this 2000-row sample is a provenance check, not the benign arm. No")
print("    analysis script reads it. The scripts that need the benign corpus need the")
print("    whole 560 MB file, which is not sampled here because a bounded read cannot")
print("    reproduce a draw over 138k rows. To get it:")
print()
print("      python -c \"from huggingface_hub import hf_hub_download as d; "
      "print(d('FayeZC/SkillMD-138K','train.parquet',repo_type='dataset',"
      f"local_dir=r'{os.path.join(BASE, 'skillmd_138k')}'))\"")
print()
print("    Then v2_layering.py, v2_skillgate.py, v2_phase3_cross.py,")
print("    v3_span_read_frac.py and v3_jointmiss_audit_pack.py can run.")
