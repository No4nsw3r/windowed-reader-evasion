import os, io, glob, pandas as pd
BASE = r".\data"

def hr(t): print("\n" + "=" * 68 + "\n" + t + "\n" + "=" * 68)

# --- MaliciousSkillBench ---
hr("MaliciousSkillBench / primary.parquet")
p = os.path.join(BASE, "malicious_skill_bench", "primary.parquet")
df = pd.read_parquet(p)
print("shape:", df.shape)
print("columns:", list(df.columns))
# label column detection
cand = [c for c in df.columns if df[c].dropna().astype(str).str.lower().isin(
        ["malicious","benign","true","false","0","1"]).mean() > 0.8]
for c in cand:
    print(f"  label-like column '{c}':")
    print(df[c].value_counts(dropna=False).to_string().replace("\n", "\n    "))
# source column
for c in df.columns:
    if "source" in c.lower():
        print(f"  '{c}' distinct sources: {df[c].nunique()}  top:")
        print(df[c].value_counts().head(6).to_string().replace("\n","\n    "))
        break

hr("MaliciousSkillBench / fixed splits")
for sp in sorted(glob.glob(os.path.join(BASE, "malicious_skill_bench", "splits", "*.csv"))):
    s = pd.read_csv(sp)
    name = os.path.basename(sp)
    splitcol = [c for c in s.columns if s[c].astype(str).str.lower().isin(["train","test","val","validation"]).mean()>0.5]
    info = ""
    if splitcol:
        info = " | " + " ".join(f"{k}={v}" for k,v in s[splitcol[0]].value_counts().items())
    print(f"  {name:32s} rows={len(s):6d} cols={list(s.columns)}{info}")

# --- SkillMD-138K sample ---
hr("SkillMD-138K (sample_2000)")
sm = pd.read_parquet(os.path.join(BASE, "skillmd_138k", "sample_2000.parquet"))
print("shape:", sm.shape, "| columns:", list(sm.columns))
print("distinct repos in sample:", sm["repo"].nunique())
print("stars: min=%s median=%s max=%s" % (sm.stars.min(), int(sm.stars.median()), sm.stars.max()))
print("avg words per SKILL.md:", int(sm["words"].mean()))

# --- Trail of Bits ---
hr("Trail of Bits / overtly-malicious-skills")
sk = os.path.join(BASE, "tob_overtly_malicious_skills", "skills")
if os.path.isdir(sk):
    for d in sorted(os.listdir(sk)):
        files = glob.glob(os.path.join(sk, d, "**", "*"), recursive=True)
        files = [f for f in files if os.path.isfile(f)]
        print(f"  {d:22s} ({len(files)} files): " +
              ", ".join(sorted(os.path.basename(f) for f in files))[:90])

# --- DataDog ---
hr("DataDog ai-skills manifest")
import json
d = json.load(io.open(os.path.join(BASE, "datadog_ai_skills", "manifest.json"), encoding="utf-8"))
print("malicious AI-skill package names:", len(d))
