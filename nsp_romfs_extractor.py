#!/usr/bin/env python3
"""
nsp_romfs_extractor.py - Extrai a pasta "romfs" de um arquivo .nsp do Nintendo Switch.

Feito para preparar os arquivos do DOOM (2016) para o port Android, que exige a pasta
"romfs" dentro da pasta do jogo. Funciona com qualquer NSP de jogo base (NCA3).

Requisitos:
  * Python 3.8+
  * cryptography  (pip install cryptography   |  Termux: pkg install python-cryptography)
    ou pycryptodome (pip install pycryptodome)
  * prod.keys extraído do SEU PRÓPRIO console (Lockpick_RCM). Nenhuma chave vem junto.

Uso:
  python3 nsp_romfs_extractor.py DOOM.nsp -k prod.keys -o "DOOM Mobile"
  python3 nsp_romfs_extractor.py DOOM.nsp -k prod.keys --list
"""

import argparse
import os
import re
import struct
import sys
import time

# --------------------------------------------------------------------------------------
# Criptografia (cryptography ou pycryptodome)
# --------------------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _ecb_decryptor(key):
        return Cipher(algorithms.AES(key), modes.ECB()).decryptor().update

    def _ecb_encryptor(key):
        return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update

    def aes_ctr_decrypt(key, counter, data):
        return Cipher(algorithms.AES(key), modes.CTR(counter)).decryptor().update(data)

except ImportError:  # pragma: no cover
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
    except ImportError:
        sys.exit("ERRO: instale 'cryptography' (pip install cryptography) "
                 "ou 'pycryptodome' (pip install pycryptodome).")

    def _ecb_decryptor(key):
        return AES.new(key, AES.MODE_ECB).decrypt

    def _ecb_encryptor(key):
        return AES.new(key, AES.MODE_ECB).encrypt

    def aes_ctr_decrypt(key, counter, data):
        ctr = Counter.new(128, initial_value=int.from_bytes(counter, "big"))
        return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(data)


def aes_ecb_decrypt(key, data):
    return _ecb_decryptor(key)(data)


def _xts_mul_alpha(t):
    t = int.from_bytes(t, "little") << 1
    if t >> 128:
        t = (t & ((1 << 128) - 1)) ^ 0x87
    return t.to_bytes(16, "little")


def aes_xts_decrypt_nintendo(key32, data, sector=0, sector_size=0x200):
    """AES-128-XTS com tweak big-endian (variante usada pela Nintendo)."""
    dec = _ecb_decryptor(key32[:16])
    enc_tweak = _ecb_encryptor(key32[16:])
    out = bytearray()
    for off in range(0, len(data), sector_size):
        tweak = enc_tweak(sector.to_bytes(16, "big"))
        block = data[off:off + sector_size]
        for b in range(0, len(block), 16):
            c = block[b:b + 16]
            x = bytes(i ^ j for i, j in zip(c, tweak))
            p = dec(x)
            out += bytes(i ^ j for i, j in zip(p, tweak))
            tweak = _xts_mul_alpha(tweak)
        sector += 1
    return bytes(out)


# --------------------------------------------------------------------------------------
# Chaves
# --------------------------------------------------------------------------------------

class KeyError_(Exception):
    pass


def load_keys(path):
    keys = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            m = re.match(r"^([A-Za-z0-9_]+)\s*[=,]\s*([0-9A-Fa-f]+)$", line)
            if m:
                keys[m.group(1).lower()] = bytes.fromhex(m.group(2))
    if "header_key" not in keys:
        raise KeyError_("'header_key' não encontrada em %s. Use um prod.keys completo "
                        "gerado pelo Lockpick_RCM." % path)
    return keys


def load_title_keys(path):
    """title.keys: rights_id = titlekey"""
    tk = {}
    if not path or not os.path.isfile(path):
        return tk
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"^\s*([0-9A-Fa-f]{32})\s*[=,]\s*([0-9A-Fa-f]{32})", line)
            if m:
                tk[m.group(1).lower()] = bytes.fromhex(m.group(2))
    return tk


def get_key(keys, name):
    k = keys.get(name)
    if k is None:
        raise KeyError_("Chave '%s' não encontrada no prod.keys. Seu prod.keys é antigo "
                        "demais para este jogo: atualize o firmware do console e gere o "
                        "prod.keys de novo com o Lockpick_RCM." % name)
    return k


# --------------------------------------------------------------------------------------
# PFS0 (container do NSP)
# --------------------------------------------------------------------------------------

class PFS0:
    def __init__(self, f, base=0):
        self.f = f
        self.base = base
        f.seek(base)
        hdr = f.read(0x10)
        if hdr[:4] != b"PFS0":
            raise ValueError("Não é um NSP/PFS0 válido (magic = %r). Arquivos .nsz/.xci "
                             "não são suportados: converta para .nsp primeiro." % hdr[:4])
        n, strsize = struct.unpack_from("<II", hdr, 4)
        entries = f.read(0x18 * n)
        strtab = f.read(strsize)
        data_start = base + 0x10 + 0x18 * n + strsize
        self.files = []
        for i in range(n):
            off, size, name_off = struct.unpack_from("<QQI", entries, i * 0x18)
            end = strtab.index(b"\0", name_off)
            name = strtab[name_off:end].decode("utf-8", "replace")
            self.files.append((name, data_start + off, size))

    def read(self, name):
        for n, off, size in self.files:
            if n == name:
                self.f.seek(off)
                return self.f.read(size)
        raise FileNotFoundError(name)


# --------------------------------------------------------------------------------------
# Ticket
# --------------------------------------------------------------------------------------

SIG_SIZES = {  # tipo -> tamanho de assinatura + padding
    0x010000: 0x200 + 0x3C, 0x010001: 0x100 + 0x3C, 0x010002: 0x3C + 0x40,
    0x010003: 0x200 + 0x3C, 0x010004: 0x100 + 0x3C, 0x010005: 0x3C + 0x40,
}


def parse_ticket(data):
    sig_type = struct.unpack_from("<I", data, 0)[0]
    if sig_type not in SIG_SIZES:
        raise ValueError("Tipo de assinatura de ticket desconhecido: 0x%X" % sig_type)
    d = 4 + SIG_SIZES[sig_type]
    title_key_block = data[d + 0x40:d + 0x40 + 0x100]
    key_type = data[d + 0x141]
    rights_id = data[d + 0x160:d + 0x170]
    return rights_id, key_type, title_key_block[:16]


# --------------------------------------------------------------------------------------
# NCA
# --------------------------------------------------------------------------------------

CONTENT_TYPES = {0: "Program", 1: "Meta", 2: "Control", 3: "Manual", 4: "Data", 5: "PublicData"}
FS_TYPES = {0: "RomFS", 1: "PFS0"}
ENC_TYPES = {0: "Auto", 1: "Nenhuma", 2: "XTS", 3: "CTR", 4: "BKTR", 5: "CTR-Ex", 6: "BKTR-Ex"}


class NCASection:
    def __init__(self, nca, idx, start, end, fsh):
        self.nca = nca
        self.idx = idx
        self.start = start
        self.end = end
        self.fsh = fsh
        self.version, self.fs_type, self.hash_type, self.enc_type = struct.unpack_from("<HBBB", fsh, 0)
        self.upper_ctr = fsh[0x140:0x148]
        # Offset/tamanho dos dados reais (último nível do IVFC ou PFS0 da SHA256 hierárquica)
        self.data_off, self.data_size = 0, end - start
        if self.hash_type == 3 and fsh[0x8:0xC] == b"IVFC":
            nlevels = struct.unpack_from("<I", fsh, 0x14)[0]
            last = min(nlevels, 7) - 2  # 6 níveis de dados, o último é o conteúdo
            lo, ls = struct.unpack_from("<QQ", fsh, 0x18 + last * 0x18)
            self.data_off, self.data_size = lo, ls
        elif self.hash_type == 2:
            # HierarchicalSha256: 0x20 hash, u32 block size, u32 layer count, layers...
            layer_count = struct.unpack_from("<I", fsh, 0x8 + 0x24)[0]
            lo, ls = struct.unpack_from("<QQ", fsh, 0x8 + 0x28 + (layer_count - 1) * 0x10)
            self.data_off, self.data_size = lo, ls

    @property
    def name(self):
        return FS_TYPES.get(self.fs_type, "?%d" % self.fs_type)

    def _counter(self, abs_off):
        ctr = bytearray(16)
        ctr[0:8] = self.upper_ctr[::-1]
        ctr[8:16] = (abs_off >> 4).to_bytes(8, "big")
        return bytes(ctr)

    def read(self, off, size):
        """Lê 'size' bytes a partir de 'off' (relativo ao início dos dados da seção)."""
        abs_off = self.start + self.data_off + off
        f = self.nca.f
        if self.enc_type == 1:
            f.seek(abs_off)
            return f.read(size)
        if self.enc_type != 3:
            raise NotImplementedError(
                "Criptografia da seção %d = %s não suportada (somente CTR). NSPs de update "
                "(BKTR) não servem: use o NSP do jogo base."
                % (self.idx, ENC_TYPES.get(self.enc_type, self.enc_type)))
        aligned = abs_off & ~0xF
        skip = abs_off - aligned
        f.seek(aligned)
        raw = f.read(size + skip + 0xF & ~0xF)
        dec = aes_ctr_decrypt(self.nca.ctr_key, self._counter(aligned), raw)
        return dec[skip:skip + size]


class NCA:
    def __init__(self, f, base, size, keys, title_keys, name=""):
        self.f = SubFile(f, base, size)
        self.name = name
        self.f.seek(0)
        enc_hdr = self.f.read(0xC00)
        hdr = aes_xts_decrypt_nintendo(get_key(keys, "header_key"), enc_hdr, 0)
        self.magic = hdr[0x200:0x204]
        if self.magic != b"NCA3":
            if self.magic in (b"NCA2", b"NCA0"):
                raise NotImplementedError("Formato %s (antigo) não suportado." % self.magic.decode())
            raise ValueError("Falha ao descriptografar o cabeçalho de %s (magic=%r). "
                             "O header_key do prod.keys está errado?" % (name, self.magic))
        self.hdr = hdr
        self.content_type = hdr[0x205]
        self.kaek_index = hdr[0x207]
        self.title_id = struct.unpack_from("<Q", hdr, 0x210)[0]
        key_gen = max(hdr[0x206], hdr[0x220])
        self.key_gen = key_gen - 1 if key_gen > 0 else 0
        self.rights_id = hdr[0x230:0x240]

        # Chave CTR
        if any(self.rights_id):
            rid = self.rights_id.hex()
            if rid not in title_keys and "__manual__" in title_keys:
                title_keys[rid] = title_keys["__manual__"]
            if rid not in title_keys:
                raise KeyError_("Titlekey para rights id %s não encontrada (o NSP não "
                                "tem ticket .tik?). Use --titlekey ou --title-keys." % rid)
            kek = get_key(keys, "titlekek_%02x" % self.key_gen)
            self.ctr_key = aes_ecb_decrypt(kek, title_keys[rid])
        else:
            kaek_name = ("key_area_key_application_%02x", "key_area_key_ocean_%02x",
                         "key_area_key_system_%02x")[self.kaek_index] % self.key_gen
            kaek = get_key(keys, kaek_name)
            key_area = aes_ecb_decrypt(kaek, hdr[0x300:0x340])
            self.ctr_key = key_area[0x20:0x30]

        self.sections = []
        for i in range(4):
            s, e = struct.unpack_from("<II", hdr, 0x240 + i * 0x10)
            if s == 0 and e == 0:
                continue
            fsh = hdr[0x400 + i * 0x200:0x600 + i * 0x200]
            self.sections.append(NCASection(self, i, s * 0x200, e * 0x200, fsh))

    @property
    def type_name(self):
        return CONTENT_TYPES.get(self.content_type, "?%d" % self.content_type)


class SubFile:
    """Janela de leitura dentro de um arquivo maior."""

    def __init__(self, f, base, size):
        self.f, self.base, self.size, self.pos = f, base, size, 0

    def seek(self, pos):
        self.pos = pos

    def read(self, n):
        n = max(0, min(n, self.size - self.pos))
        self.f.seek(self.base + self.pos)
        d = self.f.read(n)
        self.pos += len(d)
        return d


# --------------------------------------------------------------------------------------
# RomFS
# --------------------------------------------------------------------------------------

INVALID = 0xFFFFFFFF


class RomFS:
    def __init__(self, section):
        self.s = section
        hdr = section.read(0, 0x50)
        (self.header_size, _, _, dir_meta_off, dir_meta_size, _, _,
         file_meta_off, file_meta_size, self.file_data_off) = struct.unpack("<10Q", hdr)
        if self.header_size != 0x50:
            raise ValueError("Cabeçalho RomFS inválido (descriptografia errada? "
                             "verifique se o prod.keys corresponde ao firmware).")
        self.dir_meta = section.read(dir_meta_off, dir_meta_size)
        self.file_meta = section.read(file_meta_off, file_meta_size)

    def _dir(self, off):
        parent, sibling, child_dir, child_file, _h, nlen = struct.unpack_from("<6I", self.dir_meta, off)
        name = self.dir_meta[off + 0x18:off + 0x18 + nlen].decode("utf-8", "replace")
        return sibling, child_dir, child_file, name

    def _file(self, off):
        parent, sibling, data_off, size, _h, nlen = struct.unpack_from("<IIQQII", self.file_meta, off)
        name = self.file_meta[off + 0x20:off + 0x20 + nlen].decode("utf-8", "replace")
        return sibling, data_off, size, name

    def walk(self):
        """Gera (caminho_relativo, offset, tamanho) para cada arquivo."""
        stack = [(0, "")]
        while stack:
            doff, path = stack.pop()
            _sib, child_dir, child_file, _name = self._dir(doff)
            fo = child_file
            while fo != INVALID:
                sib, data_off, size, name = self._file(fo)
                yield (path + "/" + name).lstrip("/"), data_off, size
                fo = sib
            co = child_dir
            while co != INVALID:
                sib, _cd, _cf, name = self._dir(co)
                stack.append((co, path + "/" + name))
                co = sib

    def extract_file(self, data_off, size, dest, progress, chunk=8 << 20):
        with open(dest, "wb") as out:
            pos = 0
            while pos < size:
                n = min(chunk, size - pos)
                out.write(self.s.read(self.file_data_off + data_off + pos, n))
                pos += n
                progress(n)


def safe_join(root, rel):
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return os.path.join(root, *parts)


# --------------------------------------------------------------------------------------
# Programa principal
# --------------------------------------------------------------------------------------

def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%.1f %s" % (n, u) if u != "B" else "%d B" % n
        n /= 1024.0


def main():
    ap = argparse.ArgumentParser(description="Extrai a pasta romfs de um NSP do Nintendo Switch.")
    ap.add_argument("nsp", help="arquivo .nsp do jogo base")
    ap.add_argument("-k", "--keys", default=None,
                    help="prod.keys (padrão: ./prod.keys ou ~/.switch/prod.keys)")
    ap.add_argument("-o", "--out", default=".",
                    help="pasta do jogo; a pasta 'romfs' é criada dentro dela (padrão: .)")
    ap.add_argument("--title-keys", default=None, help="arquivo title.keys opcional")
    ap.add_argument("--titlekey", default=None,
                    help="titlekey em hex (32 caracteres), se o NSP não tiver ticket")
    ap.add_argument("--list", action="store_true", help="só lista o conteúdo, não extrai")
    ap.add_argument("--exefs", action="store_true", help="também extrai a pasta exefs")
    ap.add_argument("--include-control", action="store_true",
                    help="também extrai o romfs do NCA Control (ícones/nome do jogo)")
    args = ap.parse_args()

    keys_path = args.keys
    if not keys_path:
        for p in ("prod.keys", os.path.expanduser("~/.switch/prod.keys")):
            if os.path.isfile(p):
                keys_path = p
                break
    if not keys_path or not os.path.isfile(keys_path):
        sys.exit("ERRO: prod.keys não encontrado. Informe com -k caminho/prod.keys")

    try:
        keys = load_keys(keys_path)
    except KeyError_ as e:
        sys.exit("ERRO: %s" % e)
    title_keys = load_title_keys(args.title_keys)

    with open(args.nsp, "rb") as f:
        try:
            pfs = PFS0(f)
        except ValueError as e:
            sys.exit("ERRO: %s" % e)

        print("Conteúdo do NSP:")
        for name, off, size in pfs.files:
            print("  %-48s %10s" % (name, human(size)))

        # Tickets -> titlekeys
        for name, off, size in pfs.files:
            if name.lower().endswith(".tik"):
                rid, ktype, tkey = parse_ticket(pfs.read(name))
                if ktype != 0:
                    print("AVISO: ticket %s é personalizado (não é common); não dá para "
                          "usar sem as chaves do console. Use --titlekey." % name)
                    continue
                title_keys.setdefault(rid.hex(), tkey)
        if args.titlekey:
            title_keys["__manual__"] = bytes.fromhex(args.titlekey)

        ncas = []
        for name, off, size in pfs.files:
            low = name.lower()
            if low.endswith(".ncz"):
                print("AVISO: %s é comprimido (NCZ). Descomprima o NSZ para NSP antes." % name)
                continue
            if not low.endswith(".nca"):
                continue
            try:
                nca = NCA(f, off, size, keys, title_keys, name)
            except KeyError_ as e:
                sys.exit("ERRO em %s: %s" % (name, e))
            except (ValueError, NotImplementedError) as e:
                sys.exit("ERRO em %s: %s" % (name, e))
            ncas.append(nca)
            secs = ", ".join("%d:%s/%s" % (s.idx, s.name, ENC_TYPES.get(s.enc_type, s.enc_type))
                             for s in nca.sections)
            print("NCA %s -> tipo %s, TitleID %016X, keygen %d, seções [%s]"
                  % (name, nca.type_name, nca.title_id, nca.key_gen, secs))

        wanted = {0, 4, 5} | ({2} if args.include_control else set())
        romfs_sections = [(n, s) for n in ncas if n.content_type in wanted
                          for s in n.sections if s.fs_type == 0]
        if not romfs_sections:
            sys.exit("ERRO: nenhuma seção RomFS encontrada no NSP.")

        out_root = os.path.join(args.out, "romfs")
        total_files, total_bytes = 0, 0
        jobs = []
        for nca, sec in romfs_sections:
            try:
                rfs = RomFS(sec)
            except (ValueError, NotImplementedError) as e:
                sys.exit("ERRO lendo RomFS de %s: %s" % (nca.name, e))
            files = list(rfs.walk())
            jobs.append((nca, rfs, files))
            total_files += len(files)
            total_bytes += sum(s for _p, _o, s in files)

        print("\nRomFS: %d arquivos, %s" % (total_files, human(total_bytes)))
        if args.list:
            for _nca, _rfs, files in jobs:
                for p, _o, s in files:
                    print("  %-70s %10s" % (p, human(s)))
            return

        print("Extraindo para: %s\n" % out_root)
        done = [0]
        t0 = time.time()
        last = [0.0]

        def progress(n):
            done[0] += n
            now = time.time()
            if now - last[0] > 0.5 or done[0] == total_bytes:
                last[0] = now
                pct = 100.0 * done[0] / total_bytes if total_bytes else 100.0
                speed = done[0] / max(now - t0, 1e-6)
                sys.stdout.write("\r  %5.1f%%  %s / %s  (%s/s)      "
                                 % (pct, human(done[0]), human(total_bytes), human(speed)))
                sys.stdout.flush()

        for _nca, rfs, files in jobs:
            for rel, data_off, size in files:
                dest = safe_join(out_root, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                rfs.extract_file(data_off, size, dest, progress)
        progress(0)

        if args.exefs:
            for nca in ncas:
                if nca.content_type != 0:
                    continue
                for sec in nca.sections:
                    if sec.fs_type != 1 or sec.idx != 0:
                        continue
                    exefs_dir = os.path.join(args.out, "exefs")
                    os.makedirs(exefs_dir, exist_ok=True)
                    hdr = sec.read(0, 0x10)
                    n, strsize = struct.unpack_from("<II", hdr, 4)
                    meta = sec.read(0, 0x10 + 0x18 * n + strsize)
                    data_start = 0x10 + 0x18 * n + strsize
                    strtab = meta[0x10 + 0x18 * n:]
                    for i in range(n):
                        o, s, no = struct.unpack_from("<QQI", meta, 0x10 + i * 0x18)
                        nm = strtab[no:strtab.index(b"\0", no)].decode()
                        with open(safe_join(exefs_dir, nm), "wb") as out:
                            out.write(sec.read(data_start + o, s))
                    print("\nexefs extraído em %s" % exefs_dir)

        print("\n\nPronto! %d arquivos em %.0f s." % (total_files, time.time() - t0))
        print("Copie a pasta que contém 'romfs' para o telefone, por exemplo:")
        print("  /storage/emulated/0/Download/DOOM Mobile/romfs")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nCancelado.")
