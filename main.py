import os, json
from datetime import datetime
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import gspread
from google.oauth2.service_account import Credentials



app = FastAPI()

@app.get("/version") def version(): return {"version": "cors-1"}

# Libera acesso do site
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://leticiaxs.github.io",  # seu GitHub Pages
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.environ.get("API_KEY", "")
SHEET_ID = os.environ.get("SHEET_ID", "")
WORKSHEET_NAME = "Pedidos"
GOOGLE_CREDS_JSON = os.environ.get("GOOGLE_CREDS_JSON", "")

MARMITAS = [
    "Arroz, feijão e carne moída",
    "Arroz, feijão e frango",
    "Arroz, feijão e carne de panela",
    "Purê com carne moída",
    "Purê com frango",
    "Nhoque com carne moída",
    "Nhoque com frango",
    "Aipim temperado com carne moída",
    "Aipim com carne de panela",
    "Batata doce com carne moída",
    "Batata doce com frango",
    "Talharim tradicional com frango",
    "Talharim tradicional com carne moída",
    "Talharim de espinafre com carne moída",
    "Talharim de espinafre com frango",
]

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

def get_sheet():
    creds_dict = json.loads(GOOGLE_CREDS_JSON)
    creds = Credentials.from_service_account_info(creds_dict, scopes=SCOPES)
    gc = gspread.authorize(creds)
    sh = gc.open_by_key(SHEET_ID)
    return sh.worksheet(WORKSHEET_NAME)

class Pedido(BaseModel):
    nome: str
    whatsapp: str
    obs: str | None = ""
    quantidades: dict[str, int] = {}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/api/pedido")
def criar_pedido(p: Pedido, x_api_key: str | None = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401)

    itens = []
    total = 0

    for item in MARMITAS:
        q = p.quantidades.get(item, 0)
        if q > 0:
            itens.append(f"{item}:{q}")
            total += q

    itens_txt = " | ".join(itens) if itens else "Nenhum item"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sheet = get_sheet()
    sheet.append_row([timestamp, p.nome, p.whatsapp, itens_txt, total, p.obs])

    return {"ok": True, "total": total}
