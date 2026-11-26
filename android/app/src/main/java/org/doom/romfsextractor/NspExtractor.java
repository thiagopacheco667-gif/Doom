package org.doom.romfsextractor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Extrai a pasta romfs de um NSP (PFS0 com NCA3). Não depende de APIs do Android:
 * recebe um FileChannel do NSP, o texto do prod.keys e uma pasta de destino.
 */
public final class NspExtractor {

    public interface Listener {
        void log(String msg);

        void progress(long done, long total);

        boolean isCancelled();
    }

    public static final class ExtractException extends Exception {
        public ExtractException(String m) {
            super(m);
        }
    }

    private static final long INVALID = 0xFFFFFFFFL;
    private static final int CHUNK = 4 << 20;
    private static final String[] CONTENT_TYPES = {"Program", "Meta", "Control", "Manual", "Data", "PublicData"};

    private final FileChannel ch;
    private final Map<String, byte[]> keys;
    private final Map<String, byte[]> titleKeys = new HashMap<>();
    private final Listener l;
    private byte[] manualTitleKey;

    public NspExtractor(FileChannel nsp, Map<String, byte[]> keys, Listener l) {
        this.ch = nsp;
        this.keys = keys;
        this.l = l;
    }

    public void setManualTitleKey(byte[] k) {
        manualTitleKey = k;
    }

    // ------------------------------------------------------------------ chaves

    public static Map<String, byte[]> parseKeys(InputStream in) throws IOException, ExtractException {
        Map<String, byte[]> m = new HashMap<>();
        Pattern p = Pattern.compile("^([A-Za-z0-9_]+)\\s*[=,]\\s*([0-9A-Fa-f]+)$");
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            int h = line.indexOf('#');
            if (h >= 0) line = line.substring(0, h);
            Matcher mt = p.matcher(line.trim());
            if (mt.matches() && mt.group(2).length() % 2 == 0) {
                m.put(mt.group(1).toLowerCase(Locale.ROOT), hex(mt.group(2)));
            }
        }
        if (!m.containsKey("header_key")) {
            throw new ExtractException("'header_key' não encontrada no prod.keys. Use um prod.keys "
                    + "completo gerado pelo Lockpick_RCM.");
        }
        return m;
    }

    private byte[] key(String name) throws ExtractException {
        byte[] k = keys.get(name);
        if (k == null) {
            throw new ExtractException("Chave '" + name + "' não encontrada no prod.keys. Ele é antigo "
                    + "demais para este jogo: atualize o firmware do console e gere o prod.keys de novo.");
        }
        return k;
    }

    public static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    // ------------------------------------------------------------------ crypto

    static byte[] ecbDecrypt(byte[] key, byte[] data) throws ExtractException {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(data);
        } catch (Exception e) {
            throw new ExtractException("AES-ECB: " + e);
        }
    }

    /** AES-128-XTS com tweak big-endian (variante Nintendo). */
    static byte[] xtsDecrypt(byte[] key32, byte[] data, long sector) throws ExtractException {
        try {
            byte[] k1 = new byte[16], k2 = new byte[16];
            System.arraycopy(key32, 0, k1, 0, 16);
            System.arraycopy(key32, 16, k2, 0, 16);
            Cipher dec = Cipher.getInstance("AES/ECB/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k1, "AES"));
            Cipher enc = Cipher.getInstance("AES/ECB/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k2, "AES"));
            byte[] out = new byte[data.length];
            byte[] blk = new byte[16];
            for (int off = 0; off < data.length; off += 0x200, sector++) {
                byte[] tw = new byte[16];
                for (int i = 0; i < 8; i++) tw[15 - i] = (byte) (sector >>> (8 * i));
                tw = enc.doFinal(tw);
                int end = Math.min(off + 0x200, data.length);
                for (int b = off; b < end; b += 16) {
                    for (int i = 0; i < 16; i++) blk[i] = (byte) (data[b + i] ^ tw[i]);
                    byte[] p = dec.doFinal(blk);
                    for (int i = 0; i < 16; i++) out[b + i] = (byte) (p[i] ^ tw[i]);
                    // tw *= alpha (little-endian GF(2^128))
                    int carry = 0;
                    for (int i = 0; i < 16; i++) {
                        int v = ((tw[i] & 0xFF) << 1) | carry;
                        carry = (tw[i] & 0x80) != 0 ? 1 : 0;
                        tw[i] = (byte) v;
                    }
                    if (carry != 0) tw[0] ^= (byte) 0x87;
                }
            }
            return out;
        } catch (Exception e) {
            throw new ExtractException("AES-XTS: " + e);
        }
    }

    // ------------------------------------------------------------------ IO

    private byte[] readAt(long pos, int len) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(len);
        while (bb.hasRemaining()) {
            int n = ch.read(bb, pos + bb.position());
            if (n < 0) break;
        }
        return bb.array();
    }

    private static ByteBuffer le(byte[] b) {
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
    }

    // ------------------------------------------------------------------ PFS0

    static final class Entry {
        final String name;
        final long off, size;

        Entry(String n, long o, long s) {
            name = n;
            off = o;
            size = s;
        }
    }

    private List<Entry> readPfs0() throws IOException, ExtractException {
        byte[] h = readAt(0, 0x10);
        if (h[0] != 'P' || h[1] != 'F' || h[2] != 'S' || h[3] != '0') {
            throw new ExtractException("Não é um NSP válido. Arquivos .nsz/.xci não são suportados: "
                    + "converta para .nsp primeiro.");
        }
        ByteBuffer hb = le(h);
        int n = hb.getInt(4), strSize = hb.getInt(8);
        byte[] ents = readAt(0x10, 0x18 * n);
        byte[] str = readAt(0x10 + 0x18L * n, strSize);
        long dataStart = 0x10 + 0x18L * n + strSize;
        List<Entry> out = new ArrayList<>();
        ByteBuffer eb = le(ents);
        for (int i = 0; i < n; i++) {
            long off = eb.getLong(i * 0x18), size = eb.getLong(i * 0x18 + 8);
            int no = eb.getInt(i * 0x18 + 16), e = no;
            while (e < str.length && str[e] != 0) e++;
            out.add(new Entry(new String(str, no, e - no, StandardCharsets.UTF_8), dataStart + off, size));
        }
        return out;
    }

    // ------------------------------------------------------------------ ticket

    private void readTicket(Entry e) throws IOException {
        byte[] t = readAt(e.off, (int) Math.min(e.size, 0x400));
        int sig = le(t).getInt(0);
        int d;
        switch (sig) {
            case 0x10000: case 0x10003: d = 4 + 0x200 + 0x3C; break;
            case 0x10001: case 0x10004: d = 4 + 0x100 + 0x3C; break;
            case 0x10002: case 0x10005: d = 4 + 0x3C + 0x40; break;
            default:
                l.log("AVISO: ticket " + e.name + " com assinatura desconhecida, ignorado.");
                return;
        }
        if (t.length < d + 0x170) return;
        if (t[d + 0x141] != 0) {
            l.log("AVISO: ticket " + e.name + " é personalizado; informe a titlekey manualmente.");
            return;
        }
        byte[] tk = new byte[16], rid = new byte[16];
        System.arraycopy(t, d + 0x40, tk, 0, 16);
        System.arraycopy(t, d + 0x160, rid, 0, 16);
        titleKeys.put(toHex(rid), tk);
    }

    // ------------------------------------------------------------------ NCA

    final class Section {
        final int idx, fsType, hashType, encType;
        final long start;
        long dataOff, dataSize;
        final byte[] upper = new byte[8];
        final byte[] ctrKey;

        Section(int idx, long start, long end, byte[] fsh, byte[] ctrKey) {
            this.idx = idx;
            this.start = start;
            this.ctrKey = ctrKey;
            ByteBuffer b = le(fsh);
            fsType = fsh[2] & 0xFF;
            hashType = fsh[3] & 0xFF;
            encType = fsh[4] & 0xFF;
            System.arraycopy(fsh, 0x140, upper, 0, 8);
            dataOff = 0;
            dataSize = end - start;
            if (hashType == 3 && fsh[8] == 'I' && fsh[9] == 'V' && fsh[10] == 'F' && fsh[11] == 'C') {
                int levels = Math.min(b.getInt(0x14), 7);
                int last = levels - 2;
                dataOff = b.getLong(0x18 + last * 0x18);
                dataSize = b.getLong(0x18 + last * 0x18 + 8);
            } else if (hashType == 2) {
                int layers = b.getInt(0x8 + 0x24);
                dataOff = b.getLong(0x8 + 0x28 + (layers - 1) * 0x10);
                dataSize = b.getLong(0x8 + 0x28 + (layers - 1) * 0x10 + 8);
            }
        }

        private Cipher ctr(long absAligned) throws ExtractException {
            byte[] iv = new byte[16];
            for (int i = 0; i < 8; i++) iv[i] = upper[7 - i];
            long blk = absAligned >>> 4;
            for (int i = 0; i < 8; i++) iv[15 - i] = (byte) (blk >>> (8 * i));
            try {
                Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(ctrKey, "AES"), new IvParameterSpec(iv));
                return c;
            } catch (Exception e) {
                throw new ExtractException("AES-CTR: " + e);
            }
        }

        /** Lê 'len' bytes no offset 'off' relativo aos dados da seção (descriptografado). */
        byte[] read(long ncaBase, long off, int len) throws IOException, ExtractException {
            long abs = start + dataOff + off;
            if (encType == 1) return readAt(ncaBase + abs, len);
            if (encType != 3) {
                throw new ExtractException("Criptografia da seção " + idx + " (tipo " + encType
                        + ") não suportada. NSPs de update (BKTR) não servem: use o jogo base.");
            }
            long aligned = abs & ~0xFL;
            int skip = (int) (abs - aligned);
            int rl = (len + skip + 15) & ~15;
            byte[] raw = readAt(ncaBase + aligned, rl);
            byte[] dec = ctr(aligned).update(raw);
            if (skip == 0 && rl == len) return dec;
            byte[] o = new byte[len];
            System.arraycopy(dec, skip, o, 0, len);
            return o;
        }
    }

    final class Nca {
        final String name;
        final long base;
        final int contentType;
        final List<Section> sections = new ArrayList<>();

        Nca(Entry e) throws IOException, ExtractException {
            name = e.name;
            base = e.off;
            byte[] hdr = xtsDecrypt(key("header_key"), readAt(base, 0xC00), 0);
            String magic = new String(hdr, 0x200, 4, StandardCharsets.ISO_8859_1);
            if (!magic.equals("NCA3")) {
                if (magic.equals("NCA2") || magic.equals("NCA0"))
                    throw new ExtractException("Formato " + magic + " (antigo) não suportado.");
                throw new ExtractException("Falha ao descriptografar " + name + ". O header_key do "
                        + "prod.keys está errado?");
            }
            ByteBuffer b = le(hdr);
            contentType = hdr[0x205] & 0xFF;
            int kaekIdx = hdr[0x207] & 0xFF;
            int kg = Math.max(hdr[0x206] & 0xFF, hdr[0x220] & 0xFF);
            kg = kg > 0 ? kg - 1 : 0;
            byte[] rid = new byte[16];
            System.arraycopy(hdr, 0x230, rid, 0, 16);
            boolean hasRid = false;
            for (byte x : rid) hasRid |= x != 0;

            byte[] ctrKey;
            String kgs = String.format(Locale.ROOT, "%02x", kg);
            if (hasRid) {
                byte[] tk = titleKeys.get(toHex(rid));
                if (tk == null) tk = manualTitleKey;
                if (tk == null) {
                    throw new ExtractException("Titlekey do rights id " + toHex(rid) + " não encontrada "
                            + "(o NSP não tem ticket .tik). Informe a titlekey manualmente.");
                }
                ctrKey = ecbDecrypt(key("titlekek_" + kgs), tk);
            } else {
                String[] names = {"key_area_key_application_", "key_area_key_ocean_", "key_area_key_system_"};
                if (kaekIdx > 2) throw new ExtractException("Índice de key area inválido: " + kaekIdx);
                byte[] ka = new byte[0x40];
                System.arraycopy(hdr, 0x300, ka, 0, 0x40);
                byte[] dk = ecbDecrypt(key(names[kaekIdx] + kgs), ka);
                ctrKey = new byte[16];
                System.arraycopy(dk, 0x20, ctrKey, 0, 16);
            }
            for (int i = 0; i < 4; i++) {
                long s = b.getInt(0x240 + i * 0x10) & 0xFFFFFFFFL;
                long en = b.getInt(0x244 + i * 0x10) & 0xFFFFFFFFL;
                if (s == 0 && en == 0) continue;
                byte[] fsh = new byte[0x200];
                System.arraycopy(hdr, 0x400 + i * 0x200, fsh, 0, 0x200);
                sections.add(new Section(i, s * 0x200, en * 0x200, fsh, ctrKey));
            }
            l.log(String.format(Locale.ROOT, "NCA %s: %s, TitleID %016X, keygen %d, %d seções",
                    name, contentType < CONTENT_TYPES.length ? CONTENT_TYPES[contentType] : "?",
                    b.getLong(0x210), kg, sections.size()));
        }
    }

    // ------------------------------------------------------------------ RomFS

    static final class RFile {
        final String path;
        final long off, size;

        RFile(String p, long o, long s) {
            path = p;
            off = o;
            size = s;
        }
    }

    final class RomFs {
        final Nca nca;
        final Section s;
        final long fileDataOff;
        final byte[] dirMeta, fileMeta;
        final List<RFile> files = new ArrayList<>();

        RomFs(Nca nca, Section s) throws IOException, ExtractException {
            this.nca = nca;
            this.s = s;
            ByteBuffer h = le(s.read(nca.base, 0, 0x50));
            if (h.getLong(0) != 0x50) {
                throw new ExtractException("Cabeçalho RomFS inválido em " + nca.name
                        + " (descriptografia errada? verifique o prod.keys).");
            }
            dirMeta = s.read(nca.base, h.getLong(24), (int) h.getLong(32));
            fileMeta = s.read(nca.base, h.getLong(56), (int) h.getLong(64));
            fileDataOff = h.getLong(72);
            walk();
        }

        private String name(byte[] m, int off, int len) {
            return new String(m, off, len, StandardCharsets.UTF_8);
        }

        private void walk() {
            ByteBuffer d = le(dirMeta), f = le(fileMeta);
            ArrayList<long[]> stack = new ArrayList<>();
            ArrayList<String> paths = new ArrayList<>();
            stack.add(new long[]{0});
            paths.add("");
            while (!stack.isEmpty()) {
                int doff = (int) stack.remove(stack.size() - 1)[0];
                String path = paths.remove(paths.size() - 1);
                long childDir = d.getInt(doff + 8) & 0xFFFFFFFFL;
                long fo = d.getInt(doff + 12) & 0xFFFFFFFFL;
                while (fo != INVALID) {
                    int o = (int) fo;
                    long sib = f.getInt(o + 4) & 0xFFFFFFFFL;
                    long dataOff = f.getLong(o + 8), size = f.getLong(o + 16);
                    int nl = f.getInt(o + 28);
                    files.add(new RFile(path + "/" + name(fileMeta, o + 32, nl), dataOff, size));
                    fo = sib;
                }
                long co = childDir;
                while (co != INVALID) {
                    int o = (int) co;
                    long sib = d.getInt(o + 4) & 0xFFFFFFFFL;
                    int nl = d.getInt(o + 20);
                    stack.add(new long[]{o});
                    paths.add(path + "/" + name(dirMeta, o + 24, nl));
                    co = sib;
                }
            }
        }
    }

    private static File safeFile(File root, String rel) {
        File f = root;
        for (String p : rel.replace('\\', '/').split("/")) {
            if (p.isEmpty() || p.equals(".") || p.equals("..")) continue;
            f = new File(f, p);
        }
        return f;
    }

    // ------------------------------------------------------------------ principal

    /**
     * @param gameDir pasta do jogo; "romfs" é criada dentro dela.
     * @return número de arquivos extraídos
     */
    public int extract(File gameDir, boolean listOnly) throws IOException, ExtractException {
        List<Entry> entries = readPfs0();
        l.log("Conteúdo do NSP:");
        for (Entry e : entries) l.log("  " + e.name + "  (" + human(e.size) + ")");
        for (Entry e : entries) if (e.name.toLowerCase(Locale.ROOT).endsWith(".tik")) readTicket(e);

        List<RomFs> romfs = new ArrayList<>();
        for (Entry e : entries) {
            String n = e.name.toLowerCase(Locale.ROOT);
            if (n.endsWith(".ncz")) {
                l.log("AVISO: " + e.name + " é comprimido (NCZ). Descomprima o NSZ antes.");
                continue;
            }
            if (!n.endsWith(".nca")) continue;
            Nca nca = new Nca(e);
            if (nca.contentType != 0 && nca.contentType != 4 && nca.contentType != 5) continue;
            for (Section s : nca.sections) if (s.fsType == 0) romfs.add(new RomFs(nca, s));
        }
        if (romfs.isEmpty()) throw new ExtractException("Nenhuma seção RomFS encontrada no NSP.");

        long total = 0;
        int count = 0;
        for (RomFs r : romfs) {
            count += r.files.size();
            for (RFile f : r.files) total += f.size;
        }
        l.log("RomFS: " + count + " arquivos, " + human(total));
        if (listOnly) {
            for (RomFs r : romfs) for (RFile f : r.files) l.log("  " + f.path + "  (" + human(f.size) + ")");
            return count;
        }

        File root = new File(gameDir, "romfs");
        l.log("Extraindo para: " + root.getAbsolutePath());
        long done = 0;
        for (RomFs r : romfs) {
            for (RFile f : r.files) {
                File dest = safeFile(root, f.path);
                File parent = dest.getParentFile();
                if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                    throw new IOException("Não consegui criar a pasta " + parent);
                }
                try (OutputStream out = new FileOutputStream(dest)) {
                    long pos = 0;
                    while (pos < f.size) {
                        if (l.isCancelled()) throw new ExtractException("Cancelado.");
                        int n = (int) Math.min(CHUNK, f.size - pos);
                        out.write(r.s.read(r.nca.base, r.fileDataOff + f.off + pos, n));
                        pos += n;
                        done += n;
                        l.progress(done, total);
                    }
                }
            }
        }
        l.progress(total, total);
        return count;
    }

    public static String human(long n) {
        if (n < 1024) return n + " B";
        double v = n;
        String[] u = {"KB", "MB", "GB", "TB"};
        int i = -1;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format(Locale.ROOT, "%.1f %s", v, u[i]);
    }

    /** Uso no PC: java NspExtractor jogo.nsp prod.keys pastaDoJogo [--list] */
    public static void main(String[] a) throws Exception {
        Map<String, byte[]> k;
        try (InputStream in = new java.io.FileInputStream(a[1])) {
            k = parseKeys(in);
        }
        try (FileChannel c = new java.io.RandomAccessFile(a[0], "r").getChannel()) {
            NspExtractor x = new NspExtractor(c, k, new Listener() {
                public void log(String m) {
                    System.out.println(m);
                }

                public void progress(long d, long t) {
                }

                public boolean isCancelled() {
                    return false;
                }
            });
            int n = x.extract(new File(a[2]), a.length > 3 && a[3].equals("--list"));
            System.out.println("OK: " + n + " arquivos");
        }
    }
}
