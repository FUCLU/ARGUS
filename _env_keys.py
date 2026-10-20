from pathlib import Path

for number, raw in enumerate(Path('.env').read_text(encoding='utf-8-sig').splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith('#'):
        continue
    key = line.split('=', 1)[0].removeprefix('export ').strip()
    print(f'{number}: {key}=<redacted>')
