#!/usr/bin/env python3
# ethictool.py — MVP آمن للأغراض التعليمية للاختبار الأخلاقي (notes + passive recon)
# Requirements: pip install cryptography requests

import argparse, os, json, uuid, datetime, getpass, sys, base64, socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import requests

HOME = os.path.expanduser("~")
DATA_FILE = os.path.join(HOME, ".ethictool.db")
SALT_FILE = os.path.join(HOME, ".ethictool.salt")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150_000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_salt():
    if not os.path.exists(SALT_FILE):
        return None
    return open(SALT_FILE,"rb").read()

def write_salt(salt: bytes):
    with open(SALT_FILE,"wb") as f:
        f.write(salt)

def encrypt_db(obj: dict, f: Fernet):
    raw = json.dumps(obj, ensure_ascii=False).encode()
    token = f.encrypt(raw)
    with open(DATA_FILE,"wb") as fh:
        fh.write(token)

def decrypt_db(f: Fernet):
    if not os.path.exists(DATA_FILE):
        return {"notes": []}
    token = open(DATA_FILE,"rb").read()
    try:
        raw = f.decrypt(token)
    except Exception:
        raise ValueError("فشل فك التشفير — كلمة السر خاطئة أو الملف تالف.")
    return json.loads(raw.decode())

def init_cmd(args):
    if os.path.exists(DATA_FILE):
        print("قاعدة بيانات موجودة بالفعل.")
        return
    pw = getpass.getpass("اكتب كلمة سر جديدة للأداة: ")
    pw2 = getpass.getpass("أعد كلمة السر: ")
    if pw != pw2:
        print("كلمتا السر ما تطابقوا.")
        return
    salt = os.urandom(16)
    write_salt(salt)
    key = derive_key(pw, salt)
    f = Fernet(key)
    encrypt_db({"notes": []}, f)
    print("تم تهيئة EthicTool بنجاح.")

def get_fernet():
    salt = load_salt()
    if not salt:
        print("الأداة غير مُهيّئة. شغّل: python ethictool.py init")
        sys.exit(1)
    pw = getpass.getpass("ادخل كلمة السر: ")
    key = derive_key(pw, salt)
    return Fernet(key)

def add_cmd(args):
    f = get_fernet()
    db = decrypt_db(f)
    nid = str(uuid.uuid4())[:8]
    now = datetime.datetime.utcnow().isoformat() + "Z"
    content = args.content if args.content else ""
    if not content:
        print("اكتب المحتوى، انهِ الكتابة بسطر يحتوي فقط: .save")
        lines=[]
        while True:
            line = input()
            if line.strip()==".save":
                break
            lines.append(line)
        content = "\n".join(lines)
    note = {"id": nid, "title": args.title, "content": content, "tags": (args.tags or "").split(",") if args.tags else [], "created_at": now}
    db["notes"].append(note)
    encrypt_db(db, f)
    print("تم إضافة الملاحظة id=", nid)

def list_cmd(args):
    f = get_fernet()
    db = decrypt_db(f)
    for n in db.get("notes",[]):
        print(f"{n['id']}\t{n['title']}\t{','.join(n.get('tags',[]))}\t{n['created_at']}")

def view_cmd(args):
    f = get_fernet()
    db = decrypt_db(f)
    note = next((n for n in db["notes"] if n["id"]==args.id), None)
    if not note:
        print("ما لقيت ملاحظة بالمعرّف.")
        return
    print("="*40)
    print("عنوان:", note["title"])
    print("الوسوم:", ",".join(note.get("tags",[])))
    print("تاريخ:", note["created_at"])
    print("-"*20)
    print(note["content"])
    print("="*40)

def search_cmd(args):
    f = get_fernet()
    db = decrypt_db(f)
    q = args.query.lower()
    results = [n for n in db["notes"] if q in n["title"].lower() or q in n["content"].lower() or any(q in t.lower() for t in n.get("tags",[]))]
    if not results:
        print("ما في نتائج.")
        return
    for n in results:
        print(f"{n['id']}\t{n['title']}")

def export_cmd(args):
    f = get_fernet()
    db = decrypt_db(f)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(db, fh, ensure_ascii=False, indent=2)
    print("تم التصدير إلى", args.output)

# ---- Passive recon (آمن فقط) ----
def dns_cmd(args):
    try:
        infos = socket.getaddrinfo(args.domain, None)
        ips = sorted({i[4][0] for i in infos})
        print("IPs:", ", ".join(ips))
    except Exception as e:
        print("فشل تحويل النطاق:", e)

def headers_cmd(args):
    try:
        r = requests.head(args.url, allow_redirects=True, timeout=8)
        print("Status:", r.status_code)
        for k,v in r.headers.items():
            print(f"{k}: {v}")
    except Exception as e:
        print("فشل جلب رؤوس الاستجابة:", e)

def robots_cmd(args):
    try:
        base = args.url.rstrip("/")
        if not base.startswith("http"):
            base = "http://" + base
        u = base + "/robots.txt"
        r = requests.get(u, timeout=8)
        if r.status_code == 200:
            print(r.text)
        else:
            print("robots.txt غير موجود (status {})".format(r.status_code))
    except Exception as e:
        print("فشل جلب robots.txt:", e)

def main():
    p = argparse.ArgumentParser(prog="ethictool", description="EthicTool — MVP للتعلّم والاختبار الأخلاقي (آمن)")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("init")

    a_add = sub.add_parser("add"); a_add.add_argument("title"); a_add.add_argument("--tags", default=""); a_add.add_argument("--content", default=None)
    sub.add_parser("list")
    a_view = sub.add_parser("view"); a_view.add_argument("id")
    a_search = sub.add_parser("search"); a_search.add_argument("query")
    a_export = sub.add_parser("export"); a_export.add_argument("output")

    a_dns = sub.add_parser("dns"); a_dns.add_argument("domain")
    a_headers = sub.add_parser("headers"); a_headers.add_argument("url")
    a_robots = sub.add_parser("robots"); a_robots.add_argument("url")

    args = p.parse_args()
    if not args.cmd:
        p.print_help(); return

    if args.cmd=="init": init_cmd(args)
    elif args.cmd=="add": add_cmd(args)
    elif args.cmd=="list": list_cmd(args)
    elif args.cmd=="view": view_cmd(args)
    elif args.cmd=="search": search_cmd(args)
    elif args.cmd=="export": export_cmd(args)
    elif args.cmd=="dns": dns_cmd(args)
    elif args.cmd=="headers": headers_cmd(args)
    elif args.cmd=="robots": robots_cmd(args)
    else: print("أمر غير معروف.")

if __name__=="__main__":
    main()
