# main.py
import os
import json
import re
from datetime import datetime
from typing import Optional, Dict, List, Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import gspread
from gspread.exceptions import WorksheetNotFound
from google.oauth2.service_account import Credentials

# -----------------------------
# App
# -----------------------------
app = FastAPI(title="Marmitas API", version="1.0.0")

# CORS (GitHub Pages + dev)
# Dica: Origin NÃO inclui path, só domínio.
ALLOWED_ORIGINS = [
    "https://leticiaxs.github.io",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# ENV / Config
# -----------------------------
API_KEY = os.environ.get("API_KEY", "")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

SHEET_ID = os.environ.get("SHEET_ID", "")
GOOGLE_CREDS_JSON = os.environ.get("GOOGLE_CREDS_JSON", "")

WORKSHEET_PEDIDOS = os.environ.get("WORKSHEET_PEDIDOS", "Pedidos")
WORKSHEET_MARMITAS = os.environ.get("WORKSHEET_MARMITAS", "Marmitas")
WORKSHEET_CARDAPIO_SEMANA = os.environ.get("WORKSHEET_CARDAPIO_SEMANA", "CardapioSemana")
WORKSHEET_CARDAPIO_ITENS = os.environ.get("WORKSHEET_CARDAPIO_ITENS", "CardapioItens")

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

# Cabeçalhos esperados (cria aba se não existir)
HEADERS = {
    WORKSHEET_MARMITAS: ["id", "nome", "categoria", "ativo", "ordem"],
    WORKSHEET_CARDAPIO_SEMANA: ["semana_id", "titulo", "ativa", "criado_em"],
    WORKSHEET_CARDAPIO_ITENS: ["semana_id", "marmita_id", "ordem"],
    WORKSHEET_PEDIDOS: ["timestamp", "semana_id", "nome", "whatsapp", "itens", "total_itens", "obs"],
}

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# -----------------------------
# Helpers (Sheets/Auth/Validation)
# -----------------------------
def _require_env():
    if not SHEET_ID:
        raise HTTPException(status_code=500, detail="SHEET_ID não configurado no ambiente")
    if not GOOGLE_CREDS_JSON:
        raise HTTPException(status_code=500, detail="GOOGLE_CREDS_JSON não configurado no ambiente")


def _get_client() -> gspread.Client:
    _require_env()
    try:
        creds_dict = json.loads(GOOGLE_CREDS_JSON)
    except Exception:
        raise HTTPException(status_code=500, detail="GOOGLE_CREDS_JSON inválido (não é JSON)")

    creds = Credentials.from_service_account_info(creds_dict, scopes=SCOPES)
    return gspread.authorize(creds)


def _open_spreadsheet():
    gc = _get_client()
    try:
        return gc.open_by_key(SHEET_ID)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Falha ao abrir planilha (SHEET_ID): {e}")


def _ensure_worksheet(ws_name: str):
    """Garante que a aba exista e tenha cabeçalho."""
    sh = _open_spreadsheet()
    try:
        ws = sh.worksheet(ws_name)
    except WorksheetNotFound:
        ws = sh.add_worksheet(title=ws_name, rows=1000, cols=20)
        # escreve cabeçalho se conhecido
        headers = HEADERS.get(ws_name)
        if headers:
            ws.append_row(headers, value_input_option="USER_ENTERED")
        return ws

    # se existe, verifica se tem cabeçalho (linha 1)
    headers_expected = HEADERS.get(ws_name)
    if headers_expected:
        try:
            first_row = ws.row_values(1)
            # se vazio, grava
            if not first_row:
                ws.append_row(headers_expected, value_input_option="USER_ENTERED")
        except Exception:
            # se não conseguir ler, segue (não quebra)
            pass

    return ws


def get_sheet(ws_name: str):
    return _ensure_worksheet(ws_name)


def require_admin(request: Request):
    """Valida ADMIN_KEY via header x-admin-key."""
    if not ADMIN_KEY:
        # Se você quiser forçar sempre, troque para: raise HTTPException(500, ...)
        raise HTTPException(status_code=500, detail="ADMIN_KEY não configurada no ambiente")
    key = request.headers.get("x-admin-key")
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="ADMIN_KEY inválida")


def require_api_key(x_api_key: Optional[str]):
    """Valida API_KEY via header X-API-KEY (opcional se API_KEY estiver vazia)."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="API_KEY inválida")


def parse_bool(v: Any) -> bool:
    s = str(v).strip().lower()
    return s in ("true", "1", "sim", "yes", "y")


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# -----------------------------
# Models
# -----------------------------
class MarmitaIn(BaseModel):
    id: Optional[int] = None
    nome: str
    categoria: str = ""
    ativo: bool = True
    ordem: int = 9999


class CardapioSemanaIn(BaseModel):
    semana_id: str = Field(..., description="YYYY-MM-DD")
    titulo: str = "Cardápio da Semana"
    marmita_ids: List[int] = Field(default_factory=list)


class PedidoIn(BaseModel):
    semana_id: str
    nome: str
    whatsapp: str
    obs: str = ""
    quantidades: Dict[str, int] = Field(default_factory=dict)


# -----------------------------
# Health / Version
# -----------------------------
@app.get("/version")
def version():
    return {"version": "marmitas-1.0.0"}


@app.get("/health")
def health():
    return {"ok": True}


# -----------------------------
# Admin - Marmitas
# -----------------------------
@app.get("/api/admin/marmitas")
def listar_marmitas_admin(request: Request):
    require_admin(request)

    ws = get_sheet(WORKSHEET_MARMITAS)
    rows = ws.get_all_records()

    itens = []
    for r in rows:
        try:
            mid = int(r.get("id") or 0)
        except:
            continue
        itens.append(
            {
                "id": mid,
                "nome": str(r.get("nome") or "").strip(),
                "categoria": str(r.get("categoria") or "").strip(),
                "ativo": parse_bool(r.get("ativo", "")),
                "ordem": int(r.get("ordem") or 9999),
            }
        )

    itens.sort(key=lambda x: (x["ativo"] is False, x["ordem"], x["categoria"], x["nome"]))
    return {"ok": True, "itens": itens}


@app.post("/api/admin/marmita")
def upsert_marmita(m: MarmitaIn, request: Request):
    require_admin(request)

    nome = (m.nome or "").strip()
    if not nome:
        raise HTTPException(status_code=400, detail="nome é obrigatório")

    ws = get_sheet(WORKSHEET_MARMITAS)
    rows = ws.get_all_records()

    # id
    if m.id is None:
        max_id = 0
        for r in rows:
            try:
                max_id = max(max_id, int(r.get("id") or 0))
            except:
                pass
        m_id = max_id + 1
    else:
        m_id = int(m.id)

    # acha linha para update
    found_row = None
    for i, r in enumerate(rows, start=2):  # records começam na linha 2
        try:
            if int(r.get("id") or 0) == m_id:
                found_row = i
                break
        except:
            pass

    values = [m_id, nome, (m.categoria or "").strip(), bool(m.ativo), int(m.ordem)]

    if found_row:
        ws.update(f"A{found_row}:E{found_row}", [values])
    else:
        ws.append_row(values, value_input_option="USER_ENTERED")

    return {"ok": True, "id": m_id}


@app.delete("/api/admin/marmita/{m_id}")
def desativar_marmita(m_id: int, request: Request):
    require_admin(request)

    ws = get_sheet(WORKSHEET_MARMITAS)
    rows = ws.get_all_records()

    for i, r in enumerate(rows, start=2):
        try:
            if int(r.get("id") or 0) == int(m_id):
                # coluna D = ativo
                ws.update(f"D{i}", "FALSE")
                return {"ok": True}
        except:
            pass

    raise HTTPException(status_code=404, detail="Marmita não encontrada")


# -----------------------------
# Admin - Cardápio da Semana
# -----------------------------
@app.post("/api/admin/cardapio-semana")
def salvar_cardapio_semana(payload: CardapioSemanaIn, request: Request):
    require_admin(request)

    semana_id = (payload.semana_id or "").strip()
    if not DATE_RE.match(semana_id):
        raise HTTPException(status_code=400, detail="semana_id inválido. Use YYYY-MM-DD")

    marmita_ids = payload.marmita_ids or []
    if not marmita_ids:
        raise HTTPException(status_code=400, detail="Selecione ao menos 1 marmita")

    titulo = (payload.titulo or "").strip() or "Cardápio da Semana"

    ws_semana = get_sheet(WORKSHEET_CARDAPIO_SEMANA)
    ws_itens = get_sheet(WORKSHEET_CARDAPIO_ITENS)
    ws_marm = get_sheet(WORKSHEET_MARMITAS)

    # valida se IDs existem e estão ativas
    marm_rows = ws_marm.get_all_records()
    marm_ativas = set()
    for r in marm_rows:
        try:
            mid = int(r.get("id") or 0)
            if mid and parse_bool(r.get("ativo", "")):
                marm_ativas.add(mid)
        except:
            pass

    invalid = [mid for mid in marmita_ids if mid not in marm_ativas]
    if invalid:
        raise HTTPException(status_code=400, detail=f"IDs inválidos/inativos no cardápio: {invalid}")

    # 1) inativa todas semanas (modelo de 1 cardápio ativo por vez)
    semana_rows = ws_semana.get_all_records()
    for i, _r in enumerate(semana_rows, start=2):
        ws_semana.update(f"C{i}", "FALSE")

    # 2) upsert linha da semana
    found_row = None
    for i, r in enumerate(semana_rows, start=2):
        if str(r.get("semana_id") or "").strip() == semana_id:
            found_row = i
            break

    values = [semana_id, titulo, True, now_str()]
    if found_row:
        ws_semana.update(f"A{found_row}:D{found_row}", [values])
    else:
        ws_semana.append_row(values, value_input_option="USER_ENTERED")

    # 3) remove itens antigos dessa semana (de trás para frente)
    itens_rows = ws_itens.get_all_records()
    to_delete = []
    for i, r in enumerate(itens_rows, start=2):
        if str(r.get("semana_id") or "").strip() == semana_id:
            to_delete.append(i)
    for row_idx in reversed(to_delete):
        ws_itens.delete_rows(row_idx)

    # 4) grava itens novos com ordem
    ordem = 1
    for mid in marmita_ids:
        ws_itens.append_row([semana_id, int(mid), ordem], value_input_option="USER_ENTERED")
        ordem += 1

    link_cliente = f"https://leticiaxs.github.io/marmitas-site/pedido.html?semana={semana_id}"
    return {"ok": True, "semana_id": semana_id, "link_cliente": link_cliente}


# -----------------------------
# Público - Cardápio (Cliente)
# -----------------------------
@app.get("/api/cardapio/{semana_id}")
def obter_cardapio(semana_id: str):
    semana_id = (semana_id or "").strip()
    if not DATE_RE.match(semana_id):
        raise HTTPException(status_code=400, detail="semana_id inválido. Use YYYY-MM-DD")

    ws_semana = get_sheet(WORKSHEET_CARDAPIO_SEMANA)
    ws_itens = get_sheet(WORKSHEET_CARDAPIO_ITENS)
    ws_marm = get_sheet(WORKSHEET_MARMITAS)

    semana_rows = ws_semana.get_all_records()
    semana = next((r for r in semana_rows if str(r.get("semana_id") or "").strip() == semana_id), None)
    if not semana:
        raise HTTPException(status_code=404, detail="Semana não encontrada")

    # coleta ids do cardápio
    itens_rows = ws_itens.get_all_records()
    ids = []
    for r in itens_rows:
        if str(r.get("semana_id") or "").strip() == semana_id:
            try:
                ids.append(int(r.get("marmita_id") or 0))
            except:
                pass

    if not ids:
        return {
            "ok": True,
            "semana_id": semana_id,
            "titulo": str(semana.get("titulo") or "Cardápio da Semana"),
            "itens": [],
        }

    # mapa marmitas ativas
    marm_rows = ws_marm.get_all_records()
    marm_map = {}
    for r in marm_rows:
        try:
            mid = int(r.get("id") or 0)
        except:
            continue
        if not mid:
            continue
        if not parse_bool(r.get("ativo", "")):
            continue
        marm_map[mid] = {
            "id": mid,
            "nome": str(r.get("nome") or "").strip(),
            "categoria": str(r.get("categoria") or "").strip(),
            "ordem": int(r.get("ordem") or 9999),
        }

    itens = [marm_map[mid] for mid in ids if mid in marm_map]
    itens.sort(key=lambda x: (x["ordem"], x["categoria"], x["nome"]))

    return {
        "ok": True,
        "semana_id": semana_id,
        "titulo": str(semana.get("titulo") or "Cardápio da Semana"),
        "itens": itens,
    }


# -----------------------------
# Público - Pedido (Cliente)
# -----------------------------
@app.post("/api/pedido")
def criar_pedido(p: PedidoIn, x_api_key: Optional[str] = Header(default=None)):
    # 1) Segurança
    require_api_key(x_api_key)

    # 2) Validação básica
    semana_id = (p.semana_id or "").strip()
    if not DATE_RE.match(semana_id):
        raise HTTPException(status_code=400, detail="semana_id inválido. Use YYYY-MM-DD")

    nome = (p.nome or "").strip()
    whatsapp = (p.whatsapp or "").strip()
    if not nome:
        raise HTTPException(status_code=400, detail="nome é obrigatório")
    if not whatsapp:
        raise HTTPException(status_code=400, detail="whatsapp é obrigatório")

    if not p.quantidades:
        raise HTTPException(status_code=400, detail="Selecione ao menos 1 item")

    # 3) Regra de negócio: validar itens contra o cardápio da semana
    card = obter_cardapio(semana_id)
    allowed_names = {it["nome"] for it in card.get("itens", [])}
    if not allowed_names:
        raise HTTPException(status_code=400, detail="Cardápio está vazio para esta semana")

    itens_out = []
    total = 0

    for item_name, q in (p.quantidades or {}).items():
        if item_name not in allowed_names:
            # item não pertence ao cardápio -> rejeita
            raise HTTPException(status_code=400, detail=f"Item inválido no pedido: {item_name}")
        try:
            q = int(q or 0)
        except:
            raise HTTPException(status_code=400, detail=f"Quantidade inválida para: {item_name}")
        if q < 0:
            raise HTTPException(status_code=400, detail=f"Quantidade negativa para: {item_name}")
        if q > 0:
            itens_out.append(f"{item_name}:{q}")
            total += q

    if total <= 0:
        raise HTTPException(status_code=400, detail="Total deve ser maior que zero")

    # 4) Gravação
    ws = get_sheet(WORKSHEET_PEDIDOS)
    itens_txt = " | ".join(itens_out)
    ws.append_row(
        [now_str(), semana_id, nome, whatsapp, itens_txt, total, (p.obs or "").strip()],
        value_input_option="USER_ENTERED",
    )

    # 5) Retorno
    return {"ok": True, "total": total}
