# 라벨 감사 패킷

작업 지침은 저장소 루트의 `PHASE5_지침.md` 1장입니다. 먼저 읽으십시오.

```
sheets/sheet_annot1.csv   기록표 450행 (주 주석자)
sheets/sheet_annot2.csv   기록표 100행 (신뢰도 표본, 두 번째 주석자)
items/S0001.md .. S0450.md  판정 대상 본문
key/key.csv               정답 키 — 감사가 끝날 때까지 열지 말 것
```

`items/` 안의 파일 일부는 공개 벤치마크에서 가져온 실제 악성 스킬 본문입니다. 읽기만
하십시오. 실행하지 말고, 에이전트에게 이 디렉터리를 작업 대상으로 주지 마십시오.

판정이 끝나면:

```
python -I scripts/v2_phase5_audit_score.py
```

패킷을 다시 만들어야 하면 `python -I scripts/v2_phase5_audit_pack.py`인데, **기록표를
덮어씁니다.** 채운 시트는 먼저 다른 이름으로 복사해 두십시오.
