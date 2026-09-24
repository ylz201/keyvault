"""Administrator subprocess helper; NOT a sandbox or agent credential broker."""
from __future__ import annotations
import os

def injection_environment(store, keys, project=None, include_global=False):
    if not keys:
        raise ValueError("At least one explicit --key is required")
    values = {}
    for key in keys:
        value = store.get(key, project=project) if project else None
        if value is None and include_global:
            value = store.get(key, project=None)
        if value is None:
            raise ValueError("A requested key is unavailable in the explicitly allowed scope")
        values[key] = value
    # Do not inherit API keys, proxy vars, PYTHONPATH, LD_PRELOAD or other parent data.
    env = {"PATH": os.defpath}
    if os.name == "nt" and "SystemRoot" in os.environ:
        env["SystemRoot"] = os.environ["SystemRoot"]
    return {**env, **values}
