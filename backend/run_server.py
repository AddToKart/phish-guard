"""Local development entry-point for running the FastAPI backend with reload."""

from __future__ import annotations

from pathlib import Path

import uvicorn


if __name__ == "__main__":
    backend_dir = Path(__file__).parent
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=[str(backend_dir)],
        factory=False,
    )
