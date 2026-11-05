import sys
from huggingface_hub import HfApi

api = HfApi()
for repo in ["ProtectSkills/MaliciousSkillBench", "FayeZC/SkillMD-138K"]:
    print("=" * 70)
    print("REPO:", repo)
    try:
        info = api.repo_info(repo_id=repo, repo_type="dataset", files_metadata=True)
    except Exception as e:
        print("  ERROR:", repr(e))
        continue
    total = 0
    rows = []
    for s in info.siblings:
        size = s.size or 0
        total += size
        rows.append((size, s.rfilename))
    rows.sort(reverse=True)
    for size, name in rows[:40]:
        print(f"  {size/1e6:9.2f} MB  {name}")
    print(f"  --- files: {len(rows)}, total: {total/1e6:.1f} MB ---")
