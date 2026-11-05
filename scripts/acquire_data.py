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
pq.write_table(tbl, out)
print(f"    full file rows: {total_rows:,}  columns: {cols}")
print(f"    -> wrote sample rows: {tbl.num_rows} to {out}")
print("    (full 560MB train.parquet available on demand)")
