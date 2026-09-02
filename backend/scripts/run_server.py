"""Launch SentinelWeb without server-level forwarding-header rewriting.

Source identity is resolved by the application's explicit TRUSTED_PROXY_IPS
policy. Uvicorn's independent proxy-header handling must therefore stay off.
"""

import os
import sys
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.getenv("SENTINELWEB_HOST", "127.0.0.1"),
        port=int(os.getenv("SENTINELWEB_PORT", "8000")),
        proxy_headers=False,
    )
