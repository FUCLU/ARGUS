from pathlib import Path
p=Path('sinkkb/triage/protocol.py')
for i,line in enumerate(p.read_text(encoding='utf-8').splitlines()[300:410], 301):
 print(f'{i}: {line}')
