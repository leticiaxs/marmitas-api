import os

JWT_SECRET = os.getenv("JWT_SECRET", "TROQUE_ESSA_CHAVE_EM_PRODUCAO")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN", "480"))  # 8h

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS_HASH = os.getenv("ADMIN_PASS_HASH", "")  # obrigatório em produção
