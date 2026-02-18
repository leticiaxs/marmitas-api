import os, json
from datetime import datetime
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import gspread
from google.oauth2.service_account import Credentials

from pydantic import BaseModel

class MarmitaIn(BaseModel):
    id: int | None = None
    nome: str
    categoria: str = ""
    preco: float = 0
    ativo: bool = True
    ordem: int = 9999


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://leticiaxs.github.io"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Request
from fastapi.responses import Response

ALLOWED_ORIGINS = {"https://leticiaxs.github.io"}

@app.middleware("http")
async def force_cors(request: Request, call_next):
    if request.method == "OPTIONS":
        response = Response(status_code=204)
    else:
        response = await call_next(request)

    origin = request.headers.get("origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response

@app.get("/version")
def version():
    return {"version": "cors-2"}    

@app.get("/health")
def health():
    return {"ok": True}

#Environment Variables
API_KEY = os.environ.get("API_KEY", "")
SHEET_ID = os.environ.get("SHEET_ID", "")
GOOGLE_CREDS_JSON = os.environ.get("GOOGLE_CREDS_JSON", "")

WORKSHEET_PEDIDOS = os.environ.get("WORKSHEET_PEDIDOS", "Pedidos")
WORKSHEET_MARMITAS = os.environ.get("WORKSHEET_MARMITAS", "Marmitas")

ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


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

def get_sheet(name: str):
    creds_dict = json.loads(GOOGLE_CREDS_JSON)
    creds = Credentials.from_service_account_info(creds_dict, scopes=SCOPES)
    gc = gspread.authorize(creds)
    sh = gc.open_by_key(SHEET_ID)
    return sh.worksheet(name)


class Pedido(BaseModel):
    nome: str
    whatsapp: str
    obs: str | None = ""
    quantidades: dict[str, int] = {}

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/api/menu")
def menu():
    ws = get_sheet(WORKSHEET_MARMITAS)
    rows = ws.get_all_records()  # lê pelo cabeçalho
    # filtra ativos e ordena
    itens = []
    for r in rows:
        ativo = str(r.get("ativo", "")).strip().lower() in ("true", "1", "sim", "yes")
        if not ativo:
            continue
        itens.append({
            "id": int(r["id"]),
            "nome": str(r["nome"]).strip(),
            "categoria": str(r.get("categoria","")).strip(),
            "preco": float(r.get("preco") or 0),
            "ordem": int(r.get("ordem") or 9999),
        })
    itens.sort(key=lambda x: (x["ordem"], x["categoria"], x["nome"]))
    return {"ok": True, "itens": itens}


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

    sheet = get_sheet(WORKSHEET_PEDIDOS)
    sheet.append_row([timestamp, p.nome, p.whatsapp, itens_txt, total, p.obs])
    


    return {"ok": True, "total": total}

@app.post("/api/admin/marmita")
def upsert_marmita(m: MarmitaIn, x_admin_key: str | None = Header(default=None)):
    if ADMIN_KEY and x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")

    ws = get_sheet(WORKSHEET_MARMITAS)
    rows = ws.get_all_records()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # se id não veio, gerar próximo
    if m.id is None:
        max_id = 0
        for r in rows:
            try: max_id = max(max_id, int(r.get("id") or 0))
            except: pass
        m_id = max_id + 1
    else:
        m_id = int(m.id)

    # procura linha existente
    # get_all_records começa na linha 2 => índice +2
    found_row = None
    for i, r in enumerate(rows, start=2):
        try:
            if int(r.get("id") or 0) == m_id:
                found_row = i
                break
        except:
            continue

    values = [m_id, m.nome.strip(), m.categoria.strip(), float(m.preco), bool(m.ativo), int(m.ordem), now]

    if found_row:
        ws.update(f"A{found_row}:G{found_row}", [values])
    else:
        ws.append_row(values, value_input_option="USER_ENTERED")

    return {"ok": True, "id": m_id}


@app.delete("/api/admin/marmita/{m_id}")
def desativar_marmita(m_id: int, x_admin_key: str | None = Header(default=None)):
    if ADMIN_KEY and x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")

    ws = get_sheet(WORKSHEET_MARMITAS)
    rows = ws.get_all_records()
    for i, r in enumerate(rows, start=2):
        try:
            if int(r.get("id") or 0) == int(m_id):
                ws.update(f"E{i}", "FALSE")  # coluna ativo
                ws.update(f"G{i}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                return {"ok": True}
        except:
            pass

    raise HTTPException(status_code=404, detail="not found")

