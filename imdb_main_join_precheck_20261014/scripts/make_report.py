#!/usr/bin/env python3
"""Display the preserved plaintext report only; no indexes, operators, queries or measurements."""
from pathlib import Path
if __name__ == '__main__':
    base = Path(__file__).resolve().parents[1]
    print((base / 'reports/IMDb主连接查询中文预检报告.txt').read_text(encoding='utf-8'))
