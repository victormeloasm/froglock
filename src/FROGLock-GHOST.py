#!/usr/bin/env python3
# FROGLock Argon 2025AK — Ghost (v5.3, single-file, Windows-focused)
# - Hybrid MANDATORY: AES-256-GCM (file) + Argon2id(pass) + ECCFrog522PP(KEM).
# - Cada recipient recebe um HYBRID WRAP (precisa de pass+KEM) — sem pass-only / KEM-only.
# - UI (Tk): File & Password, Key Management, Actions/Status. Design dark, responsivo, com tooltips.
# - Paranoid Mode (checkbox + F9): desativa Browse; favorece Manual Path; saída rand; sugere apagar original.
# - Windows hardening: SetErrorMode, IsDebuggerPresent, VirtualLock/Unlock, SecureZeroMemory, ACL owner-only (pywin32 se disponível).
# - Crypto: AES-256-GCM; KDF: Argon2id autotune; HKDF-SHA256 no ECDH → KEK base.
# - ECCFrog522PP: Jacobian + w-NAF (w=5); gmpy2 opcional (powmod/invert/sqrt_mod) p/ acelerar.
# - DEK: 32B fortes com whitening; mlock best-effort; zeroize.
# - Clipboard wipe no Encrypt; sem bytecode; leve anti-debug; limite de tentativas por arquivo.
# - NumPy opcional para XOR de buffers (micro ganho, seguro).
#
# v5.3 changes (GHOST-keep):
#   • SecureEntry (senha em bytearray, limpa após leitura)
#   • KEM paralelo p/ múltiplos recipients (limite dinâmico)
#   • Chunk adaptativo (até 4 MiB conforme RAM e tamanho do arquivo)
#   • mmap opcional p/ arquivos ≥ 1 GiB (ativado via env FROG_MMAP=1)

import os, sys
os.environ["PYTHONDONTWRITEBYTECODE"]="1"; sys.dont_write_bytecode=True

# -------------------- std --------------------
import json, base64, secrets, stat, time, hashlib, threading
from typing import Dict, List, Optional, Tuple
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

APP_NAME = "FROGLock Argon 2025AK — Ghost"
VERSION  = 5 + 0.3  # 5.3
APP_VERSION_MIN = 5
NONCE_SZ = 12
TAG_SZ   = 16
SALT_SZ  = 32

# mmap (opcional, desativado por padrão)
MMAP_ENABLED      = os.environ.get("FROG_MMAP", "0") == "1"
MMAP_MIN_BYTES    = int(os.environ.get("FROG_MMAP_MIN_MB", "1024")) * (1024*1024)  # 1 GiB padrão

# -------------------- runtime dir --------------------
def _runtime_dir()->str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
RUNTIME_DIR = _runtime_dir()

# -------------------- Windows low-level --------------------
import ctypes, ctypes.wintypes as wt
try: ctypes.windll.kernel32.SetErrorMode(0x0002)  # SEM_NOGPFAULTERRORBOX
except: pass

def _dbg():
    try:
        if ctypes.windll.kernel32.IsDebuggerPresent(): return True
        h=ctypes.windll.kernel32.GetCurrentProcess(); b=wt.BOOL()
        if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(h,ctypes.byref(b)): return bool(b.value)
    except: pass
    return False
if _dbg(): os._exit(0)

try:
    VirtualLock=ctypes.windll.kernel32.VirtualLock
    VirtualUnlock=ctypes.windll.kernel32.VirtualUnlock
    RtlSecureZeroMemory=ctypes.windll.kernel32.RtlSecureZeroMemory
    VirtualLock.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    VirtualUnlock.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    RtlSecureZeroMemory.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
except: VirtualLock=VirtualUnlock=RtlSecureZeroMemory=None

# optional ACL (Windows)
try:
    import win32security, ntsecuritycon as nts
    HAS_PYWIN32=True
except: HAS_PYWIN32=False

def set_owner_only_acl(path:str):
    if not HAS_PYWIN32:
        try: os.chmod(path, stat.S_IRUSR|stat.S_IWUSR)
        except: pass
        return
    try:
        user,_,_=win32security.LookupAccountName("",win32security.GetUserName())
        dacl=win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, nts.FILE_ALL_ACCESS, user)
        sd=win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorOwner(user,False)
        sd.SetSecurityDescriptorDacl(1,dacl,0)
        win32security.SetFileSecurity(
            path,
            win32security.DACL_SECURITY_INFORMATION|win32security.OWNER_SECURITY_INFORMATION,
            sd
        )
    except:
        try: os.chmod(path, stat.S_IRUSR|stat.S_IWUSR)
        except: pass

# -------------------- deps --------------------
try:
    import blake3
    def blake_hash(x:bytes)->bytes: return blake3.blake3(x).digest(32)
except:
    def blake_hash(x:bytes)->bytes: return hashlib.blake2b(x, digest_size=32).digest()

# aceleração opcional
try:
    import gmpy2 as _gmp
    _HAS_GMP = True
except Exception:
    _HAS_GMP = False

try:
    import numpy as _np
    _HAS_NP = True
except Exception:
    _HAS_NP = False

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw
from argon2 import Type as ArgonType

# -------------------- ECCFrog522PP --------------------
_p = int("20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000377",16)
_a = (-9) % _p
_b = int("7e3bceccfd45483334adf221158d1db7ff8456d746fe5f8844ce317ed31514d9c323c6adb78c10d36df0fb1111936e1be21d55444c49ace1168053242e5a2b87",16) % _p
_Gx = int("11483659870055913964623536371313631260976767098619949198405802655079012131788815900015100098140592301158799072401266653548293144687306675149107389798128134")
_Gy = int("3038694457428442024388132117370677943127343938512113463034318638709600451136325747025138610802391491914091276481105699353919202494902810686593030172286395020")
_n  = int("6864797660130609714981900799081393217269435300143305409394463459185543183397654707839930998069072437178898634323218419738245117910726080434907495541251156283")
_INF=(0,1,0)

if _HAS_GMP:
    _p_g=_gmp.mpz(_p); _a_g=_gmp.mpz(_a); _b_g=_gmp.mpz(_b)

def _to_int(x): return int(x) if _HAS_GMP else x

def _mod_inv(x:int)->int:
    if _HAS_GMP: return _to_int(_gmp.invert(_gmp.mpz(x), _p_g))
    return pow(x,_p-2,_p)

def _legendre(a:int)->int:
    if _HAS_GMP: return int(_gmp.powmod(_gmp.mpz(a), (_p_g-1)//2, _p_g))
    return pow(a,(_p-1)//2,_p)

def _is_on_curve(x:int,y:int)->bool:
    if x<0 or x>=_p or y<0 or y>=_p: return False
    return (y*y - (x*x*x + (_a*x)%_p + _b)) % _p == 0

def _dbl(P):
    X1,Y1,Z1=P
    if Z1==0 or Y1==0: return _INF
    S=(4*X1*Y1*Y1)%_p
    M=(3*X1*X1 + _a*pow(Z1,4,_p))%_p
    X3=(M*M - 2*S)%_p
    Y3=(M*(S-X3) - 8*pow(Y1,4,_p))%_p
    Z3=(2*Y1*Z1)%_p
    return (X3%_p, Y3%_p, Z3%_p)

def _add(P,Q):
    X1,Y1,Z1=P; X2,Y2,Z2=Q
    if Z1==0: return Q
    if Z2==0: return P
    Z1Z1=(Z1*Z1)%_p; Z2Z2=(Z2*Z2)%_p
    U1=(X1*Z2Z2)%_p; U2=(X2*Z1Z1)%_p
    S1=(Y1*Z2*Z2Z2)%_p; S2=(Y2*Z1*Z1Z1)%_p
    if U1==U2:
        if S1!=S2: return _INF
        return _dbl(P)
    H=(U2-U1)%_p; I=(4*H*H)%_p; J=(H*I)%_p; r=(2*(S2-S1))%_p
    V=(U1*I)%_p
    X3=(r*r - J - 2*V)%_p
    Y3=(r*(V - X3) - 2*S1*J)%_p
    Z3=((Z1+Z2)*(Z1+Z2) - Z1Z1 - Z2Z2)%_p
    Z3=(Z3*H)%_p
    return (X3%_p, Y3%_p, Z3%_p)

def _affine(P):
    X,Y,Z=P
    if Z==0: return (0,0)
    Zi=_mod_inv(Z); Zi2=(Zi*Zi)%_p; Zi3=(Zi2*Zi)%_p
    return ((X*Zi2)%_p, (Y*Zi3)%_p)

def _to_jac(x:int,y:int): return (x%_p,y%_p,1)
_GJ=_to_jac(_Gx,_Gy)

_COMP_LEN=1+66

def _int_to_be(x:int,l:int)->bytes: return x.to_bytes(l,'big')

def _be_to_int(b:bytes)->int: return int.from_bytes(b,'big')

def frog_compress(x:int,y:int)->bytes:
    # Use \x02 (even y) and \x03 (odd y) to avoid invisible control chars.
    return (b'\x03' if (y & 1) else b'\x02') + _int_to_be(x,66)

# sqrt modulo p (com gmp opcional)
def _tonelli(n:int)->Optional[int]:
    if n==0: return 0
    if _HAS_GMP:
        try:
            r=_gmp.sqrt_mod(_gmp.mpz(n), _p_g, all=False)
            if r is None: return None
            return int(r)
        except Exception:
            pass
    if _legendre(n)!=1: return None
    if _p%4==3: return pow(n,(_p+1)//4,_p)
    Q=_p-1; S=0
    while Q%2==0: Q//=2; S+=1
    z=2
    while _legendre(z)!=_p-1: z+=1
    M=S; c=pow(z,Q,_p); t=pow(n,Q,_p); R=pow(n,(Q+1)//2,_p)
    while t!=1:
        i=1; t2=(t*t)%_p
        while i<M and t2!=1: t2=(t2*t2)%_p; i+=1
        b=pow(c,1<<(M-i-1),_p)
        M=i; c=(b*b)%_p; t=(t*c)%_p; R=(R*b)%_p
    return R

def frog_decompress(enc:bytes)->Tuple[int,int]:
    if len(enc)!=_COMP_LEN or enc[0] not in (2,3): raise ValueError("Bad compressed")
    x=_be_to_int(enc[1:])
    rhs=(pow(x,3,_p)+(_a*x)%_p+_b)%_p
    y=_tonelli(rhs)
    if y is None: raise ValueError("No sqrt")
    if (y&1)!=(enc[0]&1): y=(_p-y)%_p
    if not _is_on_curve(x,y): raise ValueError("Not on curve")
    return (x,y)

# --------- w-NAF scalar multiplication (w=5) ---------
def _naf(k:int, w:int=5):
    if k==0: return [0]
    res=[]
    while k>0:
        if k & 1:
            zi = k & ((1<<w)-1)
            if zi > (1<<(w-1)): zi = zi - (1<<w)
            res.append(zi)
            k = k - zi
        else:
            res.append(0)
        k >>= 1
    return res

def _precompute_odd_multiples(P, w:int=5):
    odd=[P]
    twoP=_dbl(P)
    max_i = (1<<(w-1)) - 1
    for _ in range(1, max_i):
        odd.append(_add(odd[-1], twoP))
    return odd

def _scalar_mult(k:int,P)->Tuple[int,int,int]:
    if k%_n==0 or P[2]==0: return _INF
    W=5
    naf=_naf(k, W)
    table=_precompute_odd_multiples(P, W)
    R=_INF
    for di in reversed(naf):
        R=_dbl(R)
        if di!=0:
            idx = (abs(di)-1)//2
            T = table[idx]
            R = _add(R, T if di>0 else (T[0], (_p - T[1])%_p, T[2]))
    return R

def frog_privkey_generate()->bytes:
    while True:
        k=int.from_bytes(secrets.token_bytes(66),'big') % _n
        if 1<=k<_n: return _int_to_be(k,66)

def frog_pub_from_priv(sk:bytes)->bytes:
    k=_be_to_int(sk); P=_scalar_mult(k,_GJ)
    if P[2]==0: raise ValueError("Invalid scalar")
    x,y=_affine(P); return frog_compress(x,y)

def frog_validate_public(pub_b:bytes)->bool:
    try: x,y=frog_decompress(pub_b); return _is_on_curve(x,y)
    except: return False

def frog_ecdh(sk:bytes, peer_pub:bytes)->bytes:
    k=_be_to_int(sk); px,py=frog_decompress(peer_pub)
    P=_scalar_mult(k,_to_jac(px,py))
    if P[2]==0: raise ValueError("Invalid ECDH")
    x,y=_affine(P); shared=_int_to_be(x,66)+_int_to_be(y,66)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"AESCrypt|KEM|FROG522PP|v1").derive(shared)

def frog_kem_encap(recipient_pub:bytes)->Tuple[bytes,bytes]:
    eph_sk=frog_privkey_generate(); eph_pub=frog_pub_from_priv(eph_sk)
    kek=frog_ecdh(eph_sk,recipient_pub); return eph_pub,kek

def frog_kem_decap(sk:bytes, eph_pub:bytes)->bytes: return frog_ecdh(sk,eph_pub)

# -------------------- helpers --------------------
def _np_xor(a:bytes,b:bytes)->bytes:
    if not _HAS_NP:
        return bytes(x^y for x,y in zip(a,b))
    A=_np.frombuffer(a,dtype=_np.uint8); B=_np.frombuffer(b,dtype=_np.uint8)
    return (_np.bitwise_xor(A,B)).tobytes()

def sanitize_filepath(p:str)->str: return os.path.normpath(p)

def validate_file_path(p:str)->bool:
    try:
        if not p or len(p)>4096: return False
        if any(seg in (".","..") for seg in p.split(os.sep)): return False
        if any(s in p for s in ("..","~","//","\\\\")): return False
        return True
    except: return False

# mem disponível (MiB)
def _mem_available_mib()->int:
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_=[
                ("dwLength", wt.DWORD),
                ("dwMemoryLoad", wt.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        s=MEMORYSTATUSEX(); s.dwLength=ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s)):
            return int(s.ullAvailPhys // (1024*1024))
    except: pass
    return 2048  # fallback conservador

# -------------------- tmp/atomic --------------------
def create_tmp(dst:str)->str:
    tmp=dst+".tmp"; open(tmp,"wb").close(); set_owner_only_acl(tmp); return tmp

def atomic_replace(src_tmp:str,dst_final:str)->None:
    set_owner_only_acl(src_tmp); os.replace(src_tmp,dst_final); set_owner_only_acl(dst_final)

class SecureOp:
    def __init__(self,dst:str): self.dst=dst; self.tmp=None; self.fout=None
    def __enter__(self):
        self.tmp=create_tmp(self.dst); self.fout=open(self.tmp,"r+b",buffering=0); return self.fout
    def __exit__(self,et,e,tb):
        try:
            if self.fout: self.fout.flush(); os.fsync(self.fout.fileno()); self.fout.close()
        except: pass
        if et is None:
            try: atomic_replace(self.tmp,self.dst)
            except:
                try:
                    if self.tmp and os.path.exists(self.tmp): os.unlink(self.tmp)
                except: pass
                raise
        else:
            try:
                if self.tmp and os.path.exists(self.tmp): os.unlink(self.tmp)
            except: pass

# -------------------- mlock helpers --------------------
def lock_ba(ba:bytearray):
    if not VirtualLock or not ba: return (None,0)
    buf=(ctypes.c_char*len(ba)).from_buffer(ba)
    try:
        if VirtualLock(buf,len(ba)): return (buf,len(ba))
    except: pass
    return (None,0)

def unlock_ba(h):
    if not VirtualUnlock: return
    buf,ln=h
    try:
        if buf and ln: VirtualUnlock(buf,ln)
    except: pass

def zeroize_ba(ba:bytearray):
    try:
        if RtlSecureZeroMemory and ba:
            buf=(ctypes.c_char*len(ba)).from_buffer(ba); RtlSecureZeroMemory(buf,len(ba))
    except: pass
    for i in range(len(ba)): ba[i]=0
    del ba[:]

# -------------------- randomness --------------------
def secure_rand32()->bytes:
    # DEK ultra: 32B secrets + 32B urandom; HKDF mix + BLAKE3 whitening
    r1=secrets.token_bytes(32)
    r2=os.urandom(32)
    mix=HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"FROG|DEK|mix").derive(r1+r2)
    return blake_hash(r1+mix+r2)

# -------------------- Base64 helpers (CANÔNICOS) --------------------
def _b64_canon(s:str)->str:
    s = "".join(s.strip().split())            # remove espaços/CR/LF
    raw = base64.b64decode(s, validate=True)  # lança se ruim
    return base64.b64encode(raw).decode("ascii")

def _is_frog_pub_raw(b:bytes)->bool:
    return len(b)==(1+66) and b[0] in (2,3)

def _pub_bin_to_b64(pub_bin:bytes)->str:
    if not _is_frog_pub_raw(pub_bin): raise ValueError("Not a compressed FROG pubkey")
    # valida na curva
    if not frog_validate_public(pub_bin): raise ValueError("Curve validation failed")
    return base64.b64encode(pub_bin).decode("ascii")

# -------------------- KDF (pass) --------------------
def argon2id_autotune(pw:bytes, salt:bytes, target_mem_mib=256)->Dict:
    t=3; p=max(1,(os.cpu_count() or 2)//2)
    for m in [512,384,target_mem_mib,192,128,96,64]:
        try:
            _=hash_secret_raw(pw,salt,time_cost=t,memory_cost=(m<<10),parallelism=p,hash_len=32,type=ArgonType.ID)
            return {"t":t,"m":m,"p":p}
        except: continue
    m=32
    _=hash_secret_raw(pw,salt,time_cost=t,memory_cost=(m<<10),parallelism=p,hash_len=32,type=ArgonType.ID)
    return {"t":t,"m":m,"p":p}

def kdf_argon(pw:bytes, salt:bytes, pars:Dict, outlen=32)->bytes:
    return hash_secret_raw(pw,salt,time_cost=pars["t"],memory_cost=(pars["m"]<<10),
                           parallelism=pars["p"],hash_len=outlen,type=ArgonType.ID)

# -------------------- header --------------------
def make_header_base(nonce:bytes,pad:int,chunk:int)->Dict:
    return {"magic":"AESC","ver":VERSION,"min_reader_version":APP_VERSION_MIN,
            "aead":{"alg":"AES-256-GCM","nonce":base64.b64encode(nonce).decode("ascii"),"chunk":chunk},
            "padding_size":pad,"entries":[]}

def header_stub_bytes(h:Dict)->bytes:
    stub={k:h[k] for k in ("magic","ver","min_reader_version","aead","padding_size")}
    return json.dumps(stub,separators=(",",":"),sort_keys=True).encode("utf-8")

def serialize_header(h:Dict)->bytes:
    return json.dumps(h,separators=(",",":"),sort_keys=True).encode("utf-8")

def parse_header(raw:bytes)->Dict: return json.loads(raw.decode("utf-8"))

# -------------------- HYBRID (2-de-2) --------------------
def pass_params_make(password_ba:bytearray)->Dict:
    salt=secrets.token_bytes(SALT_SZ)
    pars=argon2id_autotune(bytes(password_ba),salt,256)
    return {"t":pars["t"],"m":pars["m"],"p":pars["p"],"salt":base64.b64encode(salt).decode("ascii"),
            "wrap_order":"kem_then_pass","alg_suite":"FROG-522PP|AES-256-GCM|Argon2id"}

def pass_kek_from_params(password_ba:bytearray, params:Dict)->bytes:
    salt=base64.b64decode(params["salt"])
    pars={"t":int(params["t"]),"m":int(params["m"]),"p":int(params["p"])}
    return kdf_argon(bytes(password_ba),salt,pars,32)

def hybrid_wrap_make(pk_b64:str, dek:bytes, stub:bytes, kek_pass:bytes)->Dict:
    pub=base64.b64decode(_b64_canon(pk_b64))
    if not frog_validate_public(pub): raise ValueError("Bad FROG pub")
    eph_pub,kek_kem=frog_kem_encap(pub)
    kek_final=blake_hash(kek_pass + kek_kem + stub)
    nonce=secrets.token_bytes(NONCE_SZ)
    enc=Cipher(algorithms.AES(kek_final),modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(stub)
    ct=enc.update(dek)+enc.finalize()
    blob=nonce+enc.tag+ct
    kid=blake_hash(pub)[:8].hex()
    return {"type":"hybrid-wrap-eccfrog522pp","kid":kid,
            "enc":base64.b64encode(eph_pub).decode("ascii"),
            "ct":base64.b64encode(blob).decode("ascii")}

def hybrid_wrap_make_parallel(recipients:List[str], dek:bytes, stub:bytes, kek_pass_bytes:bytes)->List[Dict]:
    if not recipients: return []
    def _wrap_single(pk):
        try: return hybrid_wrap_make(pk, dek, stub, kek_pass_bytes)
        except: return None
    max_workers=min(8, len(recipients))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results=list(ex.map(_wrap_single, recipients))
    return [r for r in results if r is not None]

def hybrid_wrap_try_open(entry:Dict, frog_sk:bytes, stub:bytes, kek_pass:bytes)->Optional[bytes]:
    if entry.get("type")!="hybrid-wrap-eccfrog522pp": return None
    eph=base64.b64decode(entry["enc"])
    blob=base64.b64decode(entry["ct"])
    nonce,tag,ct=blob[:NONCE_SZ],blob[NONCE_SZ:NONCE_SZ+TAG_SZ],blob[NONCE_SZ+TAG_SZ:]
    kek_kem=frog_kem_decap(frog_sk,eph)
    kek_final=blake_hash(kek_pass + kek_kem + stub)
    dec=Cipher(algorithms.AES(kek_final),modes.GCM(nonce,tag)).decryptor()
    dec.authenticate_additional_data(stub)
    try:
        dek=dec.update(ct)+dec.finalize()
        return dek if len(dek)==32 else None
    except: return None

# -------------------- chunk rules (adaptativo) --------------------
def get_chunk(sz:int)->int:
    MiB=1024*1024
    avail=_mem_available_mib()
    # base pelo tamanho
    if sz < 10*MiB: base = 64*1024
    elif sz < 100*MiB: base = 512*1024
    else: base = 1*MiB
    # upgrades conforme RAM/tamanho
    if sz >= 100*MiB and avail >= 8192: base = max(base, 2*MiB)
    if sz >= 500*MiB and avail >= 16384: base = max(base, 4*MiB)
    return base

# -------------------- anti-bruteforce por arquivo --------------------
class AttemptTracker:
    def __init__(self,max_attempts=5,window=300):
        self.attempts=defaultdict(list); self.max=max_attempts; self.win=window
    def record(self,ident:str)->bool:
        now=time.time(); L=[t for t in self.attempts[ident] if now-t<self.win]
        if len(L)>=self.max: return False
        L.append(now); self.attempts[ident]=L; return True
attempt_tracker=AttemptTracker()

# -------------------- encrypt/decrypt --------------------
def _write_encrypted_stream(fin, fout, dek:bytes, pnonce:bytes, hbytes:bytes, fsz:int, CHUNK:int, pad:int, progress_cb=None):
    enc=Cipher(algorithms.AES(dek),modes.GCM(pnonce)).encryptor(); enc.authenticate_additional_data(hbytes)
    processed=0
    while True:
        chunk=fin.read(CHUNK)
        if not chunk: break
        fout.write(enc.update(chunk)); processed+=len(chunk)
        if progress_cb and fsz>0: progress_cb(min(100.0,(processed/fsz)*100.0))
    if pad: fout.write(enc.update(secrets.token_bytes(pad)))
    fout.write(enc.finalize()); fout.write(enc.tag)

def _write_encrypted_mmap(in_path:str, fout, dek:bytes, pnonce:bytes, hbytes:bytes, fsz:int, pad:int, progress_cb=None):
    import mmap
    CHUNK_SIZE = 16 * 1024 * 1024  # 16 MiB fixo para mmap
    enc=Cipher(algorithms.AES(dek),modes.GCM(pnonce)).encryptor(); enc.authenticate_additional_data(hbytes)
    processed=0
    with open(in_path, "rb") as fin:
        with mmap.mmap(fin.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            off=0; ln=len(mm)
            while off < ln:
                end=min(off+CHUNK_SIZE, ln)
                fout.write(enc.update(mm[off:end]))
                processed += (end-off); off=end
                if progress_cb and fsz>0: progress_cb(min(100.0,(processed/fsz)*100.0))
    if pad: fout.write(enc.update(secrets.token_bytes(pad)))
    fout.write(enc.finalize()); fout.write(enc.tag)

def encrypt_stream(in_path:str,out_path:str,password_ba:bytearray,
                   recipients_frog:List[str],progress_cb=None):
    if not validate_file_path(in_path): raise ValueError("Invalid path.")
    if not os.path.exists(in_path): raise FileNotFoundError("Input not found.")
    if os.path.dirname(out_path)!=os.path.dirname(in_path): raise ValueError("Output must be same folder.")
    if not recipients_frog: raise ValueError("Hybrid is mandatory: add at least one FROG recipient.")
    fsz=os.path.getsize(in_path); CHUNK=get_chunk(fsz)
    pad=secrets.randbelow(CHUNK+1)
    dek=secure_rand32()
    pnonce=secrets.token_bytes(NONCE_SZ)

    header_base=make_header_base(pnonce,pad,CHUNK)
    stub=header_stub_bytes(header_base)

    hlock=lock_ba(password_ba)
    pass_params=pass_params_make(password_ba)
    kek_pass=pass_kek_from_params(password_ba, pass_params)
    zeroize_ba(password_ba); unlock_ba(hlock)

    entries=[{"type":"pass-params","params":pass_params}]
    wraps = hybrid_wrap_make_parallel(recipients_frog, dek, stub, kek_pass)
    if not wraps: raise ValueError("No valid FROG recipients. Check the public keys.")
    entries.extend(wraps)

    header=dict(header_base); header["entries"]=entries; hbytes=serialize_header(header)

    with SecureOp(out_path) as fout:
        fout.write(len(hbytes).to_bytes(4,"big")); fout.write(hbytes)
        if MMAP_ENABLED and fsz >= MMAP_MIN_BYTES:
            _write_encrypted_mmap(in_path, fout, dek, pnonce, hbytes, fsz, pad, progress_cb)
        else:
            with open(in_path,"rb") as fin:
                _write_encrypted_stream(fin, fout, dek, pnonce, hbytes, fsz, CHUNK, pad, progress_cb)

    try:
        ba=bytearray(dek); h=lock_ba(ba); zeroize_ba(ba); unlock_ba(h)
    except: pass

def decrypt_stream(in_path:str,out_path:str,password_ba:bytearray,
                   frog_sk:Optional[bytes],progress_cb=None):
    if not validate_file_path(in_path): raise ValueError("Invalid path.")
    if not os.path.exists(in_path): raise ValueError("File not found.")
    if not attempt_tracker.record(in_path): raise ValueError("Too many attempts. Wait a bit.")
    if os.path.dirname(out_path)!=os.path.dirname(in_path): raise ValueError("Output must be same folder.")
    if not frog_sk: raise ValueError("Hybrid is mandatory: missing FROG secret key (.sk).")

    with open(in_path,"rb") as fin:
        hl=int.from_bytes(fin.read(4),"big"); hbytes=fin.read(hl); hdr=parse_header(hbytes)
        if hdr.get("magic")!="AESC" or int(hdr.get("ver",0))<APP_VERSION_MIN: raise ValueError("Bad format/version.")
        if int(hdr.get("min_reader_version",0))>VERSION: raise ValueError("Reader too old.")
        aead=hdr["aead"]
        if aead.get("alg")!="AES-256-GCM": raise ValueError("Unsupported AEAD.")
        pnonce=base64.b64decode(aead["nonce"]); CHUNK=int(aead.get("chunk",1<<20))
        pad=int(hdr.get("padding_size",0)); entries=hdr.get("entries",[])
        if not entries: raise ValueError("No key entries.")

        stub=header_stub_bytes({"magic":hdr["magic"],"ver":hdr["ver"],"min_reader_version":hdr["min_reader_version"],
                                "aead":hdr["aead"],"padding_size":hdr["padding_size"],"entries":[]})

        pass_params=None; wraps=[]
        for e in entries:
            t=e.get("type")
            if t=="pass-params": pass_params=e.get("params")
            elif t=="hybrid-wrap-eccfrog522pp": wraps.append(e)
        if not pass_params or not wraps:
            raise ValueError("Hybrid metadata missing or no wraps.")

        try:
            hlock=lock_ba(password_ba)
            kek_pass=pass_kek_from_params(password_ba, pass_params)
        finally:
            zeroize_ba(password_ba); unlock_ba(hlock)

        dek=None
        for e in wraps:
            d=hybrid_wrap_try_open(e, frog_sk, stub, kek_pass)
            if d:
                dek=d; break
        if dek is None: raise ValueError("Hybrid unlock failed (password or FROG key mismatch).")

        fin.seek(0,os.SEEK_END); total=fin.tell()
        fin.seek(4+len(hbytes),os.SEEK_SET)
        clen=total-(4+len(hbytes))-TAG_SZ
        if clen<0: raise ValueError("Truncated file.")

        processed=0
        with SecureOp(out_path) as fout:
            dec=Cipher(algorithms.AES(dek),modes.GCM(pnonce)).decryptor(); dec.authenticate_additional_data(hbytes)
            rem=clen
            while rem>0:
                toread=CHUNK if rem>=CHUNK else rem
                data=fin.read(toread)
                if not data: raise ValueError("Truncated during read.")
                fout.write(dec.update(data)); rem-=toread; processed+=len(data)
                if progress_cb and clen>0: progress_cb(min(100.0,(processed/clen)*100.0))
            tag=fin.read(TAG_SZ)
            if len(tag)!=TAG_SZ: raise ValueError("Missing tag.")
            dec.finalize_with_tag(tag)
            if pad:
                fout.seek(0,os.SEEK_END); plen=fout.tell()
                if pad>plen: raise ValueError("Padding inconsistency.")
                fout.truncate(plen-pad)

        try:
            ba=bytearray(dek); h=lock_ba(ba); zeroize_ba(ba); unlock_ba(h)
        except: pass

# -------------------- UI theme --------------------
COL_BG="#111318"; COL_CARD_BG="#171A21"; COL_INPUT_BG="#1F2430"
COL_FG="#EAEFF7"; COL_MUTED="#A9B4C2"; COL_ACCENT="#64FFDA"; COL_BTN_BG="#2B3242"
COL_OK="#2e7d32"; COL_OK_H="#256628"; COL_BAD="#b3261e"; COL_BAD_H="#8f1f19"

def set_theme(style:ttk.Style):
    style.theme_use("clam")
    style.configure(".", font=("Segoe UI",10))
    style.configure("App.TFrame", background=COL_BG)
    style.configure("Card.TFrame", background=COL_CARD_BG)
    style.configure("TLabel", background=COL_CARD_BG, foreground=COL_FG)
    style.configure("Muted.TLabel", background=COL_CARD_BG, foreground=COL_MUTED, font=("Segoe UI",9))
    style.configure("TEntry", fieldbackground=COL_INPUT_BG, foreground=COL_FG, padding=6, insertcolor=COL_ACCENT)
    style.configure("TButton", padding=(10,6))
    style.configure("Encrypt.TButton", background=COL_OK, foreground="white")
    style.map("Encrypt.TButton", background=[('active',COL_OK_H)])
    style.configure("Decrypt.TButton", background=COL_BAD, foreground="white")
    style.map("Decrypt.TButton", background=[('active',COL_BAD_H)])
    style.configure("Horizontal.TProgressbar", troughcolor="#293042", background="#5b9bd5")

def secure_clear_clipboard():
    try:
        junk = secrets.token_hex(64)
        root.clipboard_clear(); root.clipboard_append(junk); root.update()
        root.after(60, lambda:(root.clipboard_clear(), root.update()))
    except: pass

# -------------------- key files em runtime dir --------------------
FROG_SK_PATH  = os.path.join(RUNTIME_DIR,"frog522pp.sk")
FROG_PUB_PATH = os.path.join(RUNTIME_DIR,"frog522pp.pub")  # texto (Base64 canônico, 1 linha)

def _write_private_atomic(path:str,data:bytes):
    tmp=path+".tmp"
    with open(tmp,"wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
    set_owner_only_acl(tmp); os.replace(tmp,path); set_owner_only_acl(path)

def _write_text_atomic(path:str, text:str, newline=True):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write((text.rstrip() + "\n") if newline else text)
        f.flush(); os.fsync(f.fileno())
    set_owner_only_acl(tmp); os.replace(tmp, path); set_owner_only_acl(path)

def load_optional(path:str)->Optional[bytes]:
    try:
        with open(path,"rb") as f: b=f.read()
        return b if b else None
    except: return None

def secure_delete(path:str):
    try:
        if not os.path.exists(path): return
        if os.path.islink(path):
            os.remove(path); return
        sz=os.path.getsize(path)
        if sz<=0: os.remove(path); return
        with open(path,"r+b") as f:
            for _ in range(2):
                f.seek(0); f.write(os.urandom(sz)); f.flush(); os.fsync(f.fileno())
                f.seek(0); f.write(b"\x00"*sz); f.flush(); os.fsync(f.fileno())
        os.remove(path)
    except:
        try: os.remove(path)
        except: pass

# -------------------- key mgmt (FROG only) --------------------
RECIPIENTS_FROG:List[str]=[]

def _read_pub_any()->Optional[str]:
    """
    Lê FROG_PUB_PATH e retorna Base64 canônico (texto). Aceita:
    - arquivo antigo binário (67 bytes) → converte para Base64
    - arquivo texto (Base64 possivelmente com quebras) → canoniza
    """
    try:
        with open(FROG_PUB_PATH, "rb") as f:
            data=f.read()
        # caso binário antigo
        if _is_frog_pub_raw(data):
            b64=_pub_bin_to_b64(data)
            _write_text_atomic(FROG_PUB_PATH, b64, newline=True)
            return b64
        # caso texto
        try:
            s=data.decode("utf-8", errors="strict")
        except:
            # fallback: trata como Base64 sem UTF-8 válido
            s=base64.b64encode(data).decode("ascii")
        return _b64_canon(s)
    except:
        return None

def generate_frog_keypair_ui():
    try:
        sk=frog_privkey_generate()
        pub=frog_pub_from_priv(sk)
        _write_private_atomic(FROG_SK_PATH,sk)
        # .pub passa a ser SEMPRE Base64 canônico (texto, 1 linha)
        pk_b64 = _pub_bin_to_b64(pub)
        _write_text_atomic(FROG_PUB_PATH, pk_b64, newline=True)
        set_owner_only_acl(FROG_PUB_PATH)

        try:
            root.clipboard_clear(); root.clipboard_append(pk_b64); root.update()
        except: pass

        add_now=messagebox.askyesno(
            "FROG Keypair",
            f"Keypair created in:\n{RUNTIME_DIR}\n\nPublic key (Base64, compressed) copied to clipboard.\nAdd to Recipients now?"
        )
        if add_now:
            if pk_b64 not in RECIPIENTS_FROG: RECIPIENTS_FROG.append(pk_b64)
            messagebox.showinfo("Recipients","Public key added for this session.")
    except Exception as e:
        messagebox.showerror("Keypair error", str(e))

def upload_frog_sk_ui():
    fp=filedialog.askopenfilename(filetypes=[("Secret Key (*.sk)","*.sk"),("All files","*.*")])
    if not fp: return
    try:
        with open(fp,"rb") as src:
            data=src.read()
            if not data or len(data)<32: raise ValueError("Invalid .sk file.")
        _write_private_atomic(FROG_SK_PATH,data)
        messagebox.showinfo("FROG Secret Key", f"Imported to:\n{FROG_SK_PATH}\n\n(Warning: wiped on exit.)")
    except Exception as e:
        messagebox.showerror("Import error", str(e))

def show_pubkey_ui():
    try:
        b64 = _read_pub_any()
        if not b64: raise FileNotFoundError
        root.clipboard_clear(); root.clipboard_append(b64); root.update()
        messagebox.showinfo("Public Key", "Public key (Base64) copied to clipboard.")
    except:
        messagebox.showwarning("Public Key","frog522pp.pub not found or invalid. Generate a keypair first.")

def open_keys_folder():
    try: os.startfile(RUNTIME_DIR)
    except: messagebox.showwarning("Keys folder", f"Folder: {RUNTIME_DIR}")

def recipients_manager():
    win=tk.Toplevel(root); win.title("Recipients (FROG)"); win.resizable(False,False)
    frm=ttk.Frame(win,padding=12); frm.grid()
    ttk.Label(frm,text="ECCFrog522PP public keys (compressed Base64), one per line:").grid(row=0,column=0,sticky="w")
    t=tk.Text(frm,width=92,height=12); t.grid(row=1,column=0,sticky="ew",pady=(6,10))
    t.insert("1.0","\n".join(RECIPIENTS_FROG))

    def paste_local_pub():
        b64=_read_pub_any()
        if not b64:
            messagebox.showwarning("Public Key","frog522pp.pub not found. Generate or place one.")
            return
        existing=t.get("1.0","end-1c")
        t.insert("end", ("\n" if existing else "") + b64)

    def save():
        RECIPIENTS_FROG.clear()
        lines = [ln.strip() for ln in t.get("1.0","end").splitlines() if ln.strip()]
        ok=0; bad=0
        added=set()
        for s in lines:
            try:
                c=_b64_canon(s)
                if not frog_validate_public(base64.b64decode(c)):
                    bad+=1; continue
                if c not in added:
                    RECIPIENTS_FROG.append(c); added.add(c); ok+=1
            except:
                bad+=1
        msg = f"Saved {ok} recipients"
        if bad: msg += f" — {bad} invalid line(s) skipped"
        messagebox.showinfo("Recipients", msg); win.destroy()

    btns=ttk.Frame(frm); btns.grid(row=2,column=0,sticky="e")
    ttk.Button(btns,text="Paste Local .pub", command=paste_local_pub).grid(row=0,column=0,padx=(0,8))
    ttk.Button(btns,text="Save",command=save).grid(row=0,column=1)

# -------------------- UI helpers --------------------
def set_progress(p:float):
    progress["value"]=p; progress_label.config(text=f"{p:4.1f}%")

def effective_input_path()->str:
    mp=manual_var.get().strip()
    if is_paranoid() and mp: return sanitize_filepath(mp)
    fp=file_var.get().strip()
    return sanitize_filepath(mp or fp)

def random_out_name(inp:str):
    d=os.path.dirname(inp) or "."
    return os.path.join(d, f"file_{secrets.token_hex(4)}.aesc")

def clear_all():
    try:
        file_var.set(""); manual_var.set(""); password_entry.delete(0,tk.END)
        set_progress(0.0); secure_clear_clipboard()
        RECIPIENTS_FROG.clear()
        messagebox.showinfo("Cleared","All fields and recipients cleared for this session.")
    except: pass

# -------------------- Paranoid Mode --------------------
BROWSE_ENABLED_IN_PARANOID = False

def is_paranoid()->bool:
    try: return bool(PARANOID_STATE.get())
    except: return True

def browse_file():
    if is_paranoid() and not BROWSE_ENABLED_IN_PARANOID:
        messagebox.showwarning("Paranoid Mode","Browse is disabled. Use Manual Path to avoid shell MRU."); return
    fp=filedialog.askopenfilename(filetypes=[("All files","*.*")])
    if fp:
        file_var.set(sanitize_filepath(fp)); manual_var.set(sanitize_filepath(fp))

def _apply_mode_to_ui():
    try:
        browse_btn.config(state=('normal' if (not is_paranoid() or BROWSE_ENABLED_IN_PARANOID) else 'disabled'))
    except: pass
    mode="Paranoid" if is_paranoid() else "Standard"
    root.title(f"{APP_NAME} (v{VERSION}) — {mode}")
    SUBTITLE_VAR.set(
        "Paranoid Mode ON: no logs, prefer Manual Path, random output name, delete original."
        if is_paranoid() else "Standard Mode: full features (Browse enabled)."
    )

# -------------------- SecureEntry (senha em bytearray) --------------------
class SecureEntry(ttk.Entry):
    def secure_get(self) -> bytearray:
        try:
            s = super().get()
            ba = bytearray(s.encode('utf-8'))
        except Exception:
            ba = bytearray()
        try:
            self.delete(0, tk.END)
        except: pass
        return ba
    def secure_clear(self):
        try:
            self.delete(0, tk.END)
        except: pass

# -------------------- worker --------------------
def perform_action_threaded(action):
    path=effective_input_path()
    if not path:
        messagebox.showwarning("Input","Provide a file path."); return
    if not validate_file_path(path):
        messagebox.showwarning("Path","Invalid path."); return
    if action=="encrypt" and not RECIPIENTS_FROG:
        messagebox.showwarning("Hybrid","Add at least one recipient public key (FROG)."); return

    # exigir senha nos dois fluxos (hybrid é 2-de-2)
    has_pwd = bool(password_entry.get())
    if not has_pwd:
        messagebox.showwarning("Hybrid","Password is required (hybrid mandatory)."); return

    if action=="decrypt":
        if not path.endswith(".aesc"):
            messagebox.showwarning("Format","Select a .aesc file."); return
        if not os.path.exists(FROG_SK_PATH):
            messagebox.showwarning("Hybrid","Missing FROG secret key (.sk). Import or generate one."); return

    def progress_cb(p): root.after(0, lambda: set_progress(p))

    def worker():
        try:
            for b in (encrypt_btn,decrypt_btn,browse_btn,keyboard_btn,gen_btn,copy_btn,
                      rec_btn,keypair_btn,upload_frog_btn,show_pub_btn,open_keys_btn,clear_btn):
                b.config(state='disabled')
            for e in (file_entry,manual_entry,password_entry): e.config(state='disabled')
            progress["value"]=0; set_progress(0.0)

            # pega senha como bytearray e já limpa o campo
            pwd_ba = password_entry.secure_get()

            if action=="encrypt":
                secure_clear_clipboard()
                out_path = random_out_name(path) if is_paranoid() else (path+".aesc")
                out_path = os.path.join(os.path.dirname(path), os.path.basename(out_path))
                try:
                    encrypt_stream(path,out_path,pwd_ba,RECIPIENTS_FROG,progress_cb)
                    if not keep_original_var.get():
                        try: os.remove(path)
                        except: pass
                    messagebox.showinfo("Success", f"Encrypted:\n{out_path}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

            elif action=="decrypt":
                cand=path[:-5]; out_path=cand if not os.path.exists(cand) else (cand+".dec")
                out_path=os.path.join(os.path.dirname(path), os.path.basename(out_path))
                frog_sk=load_optional(FROG_SK_PATH)
                try:
                    decrypt_stream(path,out_path,pwd_ba,frog_sk,progress_cb)
                    messagebox.showinfo("Success", f"Decrypted:\n{out_path}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        finally:
            # pwd_ba é zerado dentro dos fluxos após derivar KEK; aqui só reabilita UI
            for b in (encrypt_btn,decrypt_btn,browse_btn,keyboard_btn,gen_btn,copy_btn,
                      rec_btn,keypair_btn,upload_frog_btn,show_pub_btn,open_keys_btn,clear_btn):
                b.config(state='normal')
            for e in (file_entry,manual_entry,password_entry): e.config(state='normal')

    threading.Thread(target=worker,daemon=True).start()

# -------------------- Build UI --------------------
root = tk.Tk()
root.title(f"{APP_NAME} (v{VERSION}) — Paranoid")
root.geometry("940x680"); root.minsize(940,680); root.resizable(False, False)

# Disable Minimize/Maximize (keep Close)
try:
    hwnd = root.winfo_id()
    GWL_STYLE = -16; WS_MINIMIZEBOX = 0x00020000; WS_MAXIMIZEBOX = 0x00010000
    GetWindowLong = ctypes.windll.user32.GetWindowLongW
    SetWindowLong = ctypes.windll.user32.SetWindowLongW
    style = GetWindowLong(hwnd, GWL_STYLE)
    style &= ~(WS_MINIMIZEBOX | WS_MAXIMIZEBOX)
    SetWindowLong(hwnd, GWL_STYLE, style)
    SWP_NOMOVE=0x0002; SWP_NOSIZE=0x0001; SWP_NOZORDER=0x0004; SWP_FRAMECHANGED=0x0020
    ctypes.windll.user32.SetWindowPos(hwnd, None, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED)
except: pass

try: os.umask(0o177)
except: pass

style = ttk.Style(); set_theme(style); root.configure(bg=COL_BG)

# --- Tooltips helper ---
class _ToolTip:
    def __init__(self, widget, text:str, delay_ms:int=500):
        self.widget=widget; self.text=text; self.delay=delay_ms
        self.tip=None; self._job=None
        widget.bind("<Enter>", self._enter)
        widget.bind("<Leave>", self._leave)
    def _enter(self, _=None):
        self._cancel()
        self._job=self.widget.after(self.delay, self._show)
    def _leave(self, _=None):
        self._cancel(); self._hide()
    def _cancel(self):
        try:
            if self._job: self.widget.after_cancel(self._job)
        except: pass
        self._job=None
        
    def _show(self):
        if self.tip: return
        x=self.widget.winfo_rootx()+20
        y=self.widget.winfo_rooty()+self.widget.winfo_height()+8
        self.tip=tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl=tk.Label(self.tip, text=self.text, justify="left",
                     background="#333842", foreground="#EAEFF7",
                     relief="solid", borderwidth=1, font=("Segoe UI",9))
        lbl.pack(ipadx=6, ipady=4)
    def _hide(self):
        try:
            if self.tip: self.tip.destroy()
        except: pass
        self.tip=None

def add_tip(w, text): 
    try: _ToolTip(w, text)
    except: pass

# --- Tk variables ---
PARANOID_STATE = tk.BooleanVar(master=root, value=True)
TITLE_VAR     = tk.StringVar(master=root, value=APP_NAME)
SUBTITLE_VAR  = tk.StringVar(master=root, value="")

container = ttk.Frame(root, style="App.TFrame", padding=16)
container.grid(row=0, column=0, sticky="nsew")
root.grid_rowconfigure(0, weight=1); root.grid_columnconfigure(0, weight=1)

# Header
header = ttk.Frame(container, style="Card.TFrame", padding=(16,14))
header.grid(row=0, column=0, sticky="ew", pady=(0,10))
header.grid_columnconfigure(0, weight=1); header.grid_columnconfigure(1, weight=0); header.grid_columnconfigure(2, weight=1)

title = ttk.Label(header, textvariable=TITLE_VAR, font=("Segoe UI Semibold", 18))
title.grid(row=0, column=1)

paranoid_chk = ttk.Checkbutton(header, text="Paranoid Mode",
                               variable=PARANOID_STATE,
                               command=lambda: _apply_mode_to_ui())
paranoid_chk.grid(row=0, column=2, sticky="e")
add_tip(paranoid_chk, "Desativa Browse, favorece Manual Path, saída com nome randômico e sugere apagar original. (F9 alterna)")

subtitle = ttk.Label(header, textvariable=SUBTITLE_VAR, style="Muted.TLabel")
subtitle.grid(row=1, column=1, pady=(6,0))

# Card 1: File & Password
card1 = ttk.Frame(container, style="Card.TFrame", padding=16)
card1.grid(row=1, column=0, sticky="ew", pady=(0,10))
card1.grid_columnconfigure(1, weight=1)

ttk.Label(card1, text="File (dialog):").grid(row=0, column=0, padx=(0,10), pady=6, sticky="e")
file_var = tk.StringVar(master=root)
file_entry = ttk.Entry(card1, textvariable=file_var)
file_entry.grid(row=0, column=1, padx=(0,10), pady=6, sticky="ew")
browse_btn = ttk.Button(card1, text="Browse", command=browse_file)
browse_btn.grid(row=0, column=2, pady=6, sticky="w")
add_tip(browse_btn, "Abrir diálogo de arquivo (desativado no Paranoid).")

ttk.Label(card1, text="Manual Path:").grid(row=1, column=0, padx=(0,10), pady=6, sticky="e")
manual_var = tk.StringVar(master=root)
manual_entry = ttk.Entry(card1, textvariable=manual_var)
manual_entry.grid(row=1, column=1, padx=(0,10), pady=6, sticky="ew")
ttk.Label(card1, text="Tip: Manual Path avoids shell MRU (fewer traces).", style="Muted.TLabel")\
   .grid(row=1, column=2, pady=6, sticky="w")
add_tip(manual_entry, "Cole o caminho completo do arquivo para reduzir rastros de shell.")

ttk.Label(card1, text="Password (hybrid):").grid(row=2, column=0, padx=(0,10), pady=6, sticky="e")
password_entry = SecureEntry(card1, show="*")
password_entry.grid(row=2, column=1, padx=(0,10), pady=6, sticky="ew")

def _toggle_pw(): password_entry.config(show="" if password_entry.cget("show")=="*" else "*")
toggle_button = ttk.Button(card1, text="Show", command=_toggle_pw)
toggle_button.grid(row=2, column=2, pady=6, sticky="w")
add_tip(password_entry, "Será usado no Argon2id para derivar parte do KEK (2-de-2 com KEM).")
add_tip(toggle_button, "Mostrar/Ocultar senha.")

# tools row
tools = ttk.Frame(card1, style="Card.TFrame")
tools.grid(row=3, column=0, columnspan=3, pady=(4,2), sticky="ew")
for c in range(5): tools.grid_columnconfigure(c, weight=1)

# Teclado virtual (insere direto na Entry)
def show_virtual_keyboard():
    kb=tk.Toplevel(root); kb.title("Virtual Keyboard")
    kb.geometry("700x330"); kb.resizable(False,False); kb.configure(bg=COL_BG)
    rows=[
        ["1","2","3","4","5","6","7","8","9","0","-","=","Backspace"],
        ["q","w","e","r","t","y","u","i","o","p","[","]","\\"],
        ["a","s","d","f","g","h","j","k","l",";","'","Enter"],
        ["z","x","c","v","b","n","m",",",".","/","Shift"],
        ["`","~","{","}",";",":","!","@","#","$","%","&","*","()"],
        ["Space","Shift"]
    ]
    shift={"on":False}
    def press(k):
        cur=password_entry.get()
        if k=='Space': password_entry.insert(tk.END,' ')
        elif k=='Backspace':
            if cur: password_entry.delete(len(cur)-1,tk.END)
        elif k=='Shift': shift["on"]=not shift["on"]; draw()
        elif k=='Enter': password_entry.insert(tk.END,'\n')
        else:
            ch=k.upper() if (shift["on"] and k.isalpha()) else k
            password_entry.insert(tk.END,ch)
    def draw():
        for w in kb.winfo_children(): w.destroy()
        for r,row in enumerate(rows):
            for c,key in enumerate(row):
                label=key.upper() if (shift["on"] and key.isalpha()) else key
                b=tk.Button(kb,text=label,width=5,height=2,font=('Segoe UI',11),
                            bg=COL_BTN_BG,fg=COL_FG,activebackground=COL_BTN_BG,
                            command=lambda K=key: press(K))
                b.grid(row=r,column=c,padx=4,pady=4)
    draw()

keyboard_btn = ttk.Button(tools, text="Virtual Keyboard", command=show_virtual_keyboard); keyboard_btn.grid(row=0, column=1, padx=6)
add_tip(keyboard_btn, "Teclado virtual simples para inserir senha.")

# Gerar senha
def _gen_pwd():
    import string
    password_entry.delete(0, tk.END)
    password_entry.insert(0, ''.join(secrets.choice(string.ascii_letters+string.digits+string.punctuation) for _ in range(45)))

gen_btn = ttk.Button(tools, text="Generate Password", command=_gen_pwd); gen_btn.grid(row=0, column=2, padx=6)
add_tip(gen_btn, "Gera uma senha forte (45 chars).")

# Copiar senha
def _copy_pwd():
    root.clipboard_clear(); root.clipboard_append(password_entry.get()); root.update()
    messagebox.showinfo("Clipboard","Password copied. It will be cleared on Encrypt.")

copy_btn = ttk.Button(tools, text="Copy Password", command=_copy_pwd); copy_btn.grid(row=0, column=3, padx=6)
add_tip(copy_btn, "Copia a senha para a área de transferência (limpa automaticamente no Encrypt).")

ttk.Label(card1, text="Clipboard is cleared on Encrypt (best-effort).", style="Muted.TLabel")\
   .grid(row=4, column=0, columnspan=3, sticky="w", pady=(8,0))
keep_original_var = tk.BooleanVar(master=root, value=False)
ttk.Checkbutton(card1, text="Keep original after encrypt", variable=keep_original_var)\
   .grid(row=5, column=0, columnspan=3, sticky="w", pady=(6,0))
# (tooltip para o checkbutton precisa de handle do widget; criando abaixo)
_keep_cb = card1.grid_slaves(row=5, column=0)[0]
add_tip(_keep_cb, "Se desmarcado, tenta apagar o original após criptografar (melhor privacidade).")

# Card 2: Key Management (FROG only)
card2 = ttk.Frame(container, style="Card.TFrame", padding=16)
card2.grid(row=2, column=0, sticky="ew", pady=(0,10))
for c in range(6): card2.grid_columnconfigure(c, weight=1)
rec_btn         = ttk.Button(card2, text="Recipients…", command=lambda: recipients_manager());        rec_btn.grid(row=0, column=0, sticky="w")
keypair_btn     = ttk.Button(card2, text="Generate FROG Keypair", command=generate_frog_keypair_ui);  keypair_btn.grid(row=0, column=2, sticky="e", padx=(0,8))
upload_frog_btn = ttk.Button(card2, text="Upload FROG .sk…", command=upload_frog_sk_ui);             upload_frog_btn.grid(row=0, column=3, sticky="e", padx=(0,8))
show_pub_btn    = ttk.Button(card2, text="Copy Public Key", command=show_pubkey_ui);                  show_pub_btn.grid(row=0, column=4, sticky="e", padx=(0,8))
open_keys_btn   = ttk.Button(card2, text="Open Keys Folder", command=open_keys_folder);               open_keys_btn.grid(row=0, column=5, sticky="e")

add_tip(rec_btn, "Gerencie a lista de destinatários (cole chaves públicas FROG em Base64).")
add_tip(keypair_btn, "Gera um par de chaves FROG e salva no diretório do app.")
add_tip(upload_frog_btn, "Importa seu arquivo de chave secreta FROG (.sk) para o app.")
add_tip(show_pub_btn, "Copia a sua chave pública FROG (Base64 canônica) para a área de transferência.")
add_tip(open_keys_btn, "Abre a pasta onde ficam frog522pp.sk e frog522pp.pub.")

ttk.Label(card2, text="On exit, the app securely wipes frog522pp.sk in the app folder. Keep your backup!",
          style="Muted.TLabel").grid(row=1, column=0, columnspan=6, sticky="w", pady=(8,0))

# Card 3: Actions & Status
card3 = ttk.Frame(container, style="Card.TFrame", padding=16)
card3.grid(row=3, column=0, sticky="ew")
card3.grid_columnconfigure(0, weight=1); card3.grid_columnconfigure(1, weight=1); card3.grid_columnconfigure(2, weight=0)

encrypt_btn = ttk.Button(card3, text="Encrypt", style="Encrypt.TButton",
                         command=lambda: perform_action_threaded("encrypt"))
decrypt_btn = ttk.Button(card3, text="Decrypt", style="Decrypt.TButton",
                         command=lambda: perform_action_threaded("decrypt"))
clear_btn   = ttk.Button(card3, text="Clear All", command=clear_all)
encrypt_btn.grid(row=0, column=0, padx=(0,8), sticky="ew")
decrypt_btn.grid(row=0, column=1, padx=(8,8), sticky="ew")
clear_btn.grid(row=0, column=2, sticky="e")
add_tip(encrypt_btn, "Criptografa o arquivo: AES-256-GCM com DEK protegido via Hybrid (pass + KEM).")
add_tip(decrypt_btn, "Descriptografa: requer senha correta e sua FROG .sk correspondente.")
add_tip(clear_btn, "Limpa campos e destinatários desta sessão.")

status = ttk.Frame(container, style="Card.TFrame", padding=16)
status.grid(row=4, column=0, sticky="ew", pady=(10,0))
status.grid_columnconfigure(0, weight=1)
progress = ttk.Progressbar(status, orient='horizontal', mode='determinate', maximum=100, length=100)
progress.grid(row=0, column=0, sticky="ew")
progress_label = ttk.Label(status, text="0.0%", style="TLabel"); progress_label.grid(row=0, column=1, padx=(10,0), sticky="e")

# Watermark
wm = tk.Label(root, text="🔒 HYBRID MODE (pass + FROG) REQUIRED", fg=COL_ACCENT, bg=COL_BG, font=("Segoe UI",9))
wm.place(relx=1.0, rely=0.0, anchor="ne", x=-12, y=10)

# Auto-clear password after inactivity
def _schedule_auto_clear():
    global _auto_clear_job
    try: root.after_cancel(_auto_clear_job)
    except: pass
    def do_clear():
        try:
            if password_entry.get(): password_entry.delete(0, tk.END)
        except: pass
    _auto_clear_job = root.after(5*60*1000, do_clear)

for w in (password_entry, manual_entry, file_entry):
    w.bind("<Key>", lambda e: _schedule_auto_clear())
    w.bind("<Button-1>", lambda e: _schedule_auto_clear())
_schedule_auto_clear()

# Hotkey F9 toggles Paranoid
def _toggle_paranoid(event=None):
    PARANOID_STATE.set(not PARANOID_STATE.get()); _apply_mode_to_ui()
root.bind("<F9>", _toggle_paranoid)

_apply_mode_to_ui()

# On Exit: secure wipe frog522pp.sk
def _on_exit():
    try:
        if os.path.exists(FROG_SK_PATH): secure_delete(FROG_SK_PATH)
    finally:
        try: root.destroy()
        except: os._exit(0)
root.protocol("WM_DELETE_WINDOW", _on_exit)

root.mainloop()
