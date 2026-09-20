"""Muestra lo que respondio cada agente. Uso:  python ver_respuestas.py [vulnerable|prompt_only|hardened]"""
import json
import sys
from pathlib import Path

cache = json.loads(Path("results/cache.json").read_text(encoding="utf-8"))
mode = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"

for key, reply in cache.items():
    if key.endswith("|" + mode):
        print("=" * 60)
        print(key, f"({len(reply)} caracteres)")
        print(reply[:400] if reply.strip() else "<<RESPUESTA VACIA>>")
