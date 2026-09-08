import sys
from pathlib import Path
from fastapi import FastAPI

backend_path = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_path))

from main import app as backend_app

app = FastAPI()
app.mount("/api", backend_app)
