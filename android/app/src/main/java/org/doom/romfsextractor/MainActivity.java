package org.doom.romfsextractor;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends Activity {

    private static final int REQ_NSP = 1, REQ_KEYS = 2, REQ_PERM = 3;
    private static final String DEFAULT_OUT =
            Environment.getExternalStorageDirectory().getAbsolutePath() + "/Download/DOOM Mobile";

    private final Handler ui = new Handler(Looper.getMainLooper());
    private Uri nspUri, keysUri;
    private TextView nspLabel, keysLabel, logView, progressLabel;
    private EditText outEdit, titleKeyEdit;
    private Button permBtn, extractBtn, listBtn, cancelBtn;
    private ProgressBar bar;
    private ScrollView logScroll;
    private volatile boolean cancelled, running;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        int pad = dp(16);
        ScrollView root = new ScrollView(this);
        root.setFillViewport(true);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(pad, pad, pad, pad);
        root.addView(col);

        TextView title = new TextView(this);
        title.setText("Extrator de romfs (NSP)");
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        col.addView(title);
        col.addView(text("Extrai a pasta romfs do NSP do jogo base para a pasta do port. "
                + "Use o prod.keys do seu próprio console (Lockpick_RCM)."));

        permBtn = button("Permitir acesso aos arquivos", v -> requestStorage());
        col.addView(permBtn);

        col.addView(button("1. Escolher o arquivo .nsp", v -> pick(REQ_NSP)));
        nspLabel = text("Nenhum NSP escolhido");
        col.addView(nspLabel);

        col.addView(button("2. Escolher o prod.keys", v -> pick(REQ_KEYS)));
        keysLabel = text("Nenhum prod.keys escolhido");
        col.addView(keysLabel);

        col.addView(text("3. Pasta do jogo (a pasta romfs será criada dentro dela):"));
        outEdit = new EditText(this);
        outEdit.setSingleLine(true);
        outEdit.setText(DEFAULT_OUT);
        col.addView(outEdit);

        col.addView(text("Titlekey (opcional, só se o NSP não tiver o .tik):"));
        titleKeyEdit = new EditText(this);
        titleKeyEdit.setSingleLine(true);
        titleKeyEdit.setHint("32 caracteres hexadecimais");
        titleKeyEdit.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        col.addView(titleKeyEdit);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        listBtn = button("Só listar", v -> start(true));
        extractBtn = button("Extrair romfs", v -> start(false));
        cancelBtn = button("Cancelar", v -> cancelled = true);
        cancelBtn.setEnabled(false);
        for (Button bt : new Button[]{listBtn, extractBtn, cancelBtn}) {
            row.addView(bt, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        }
        col.addView(row);

        bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(1000);
        col.addView(bar);
        progressLabel = text("");
        col.addView(progressLabel);

        logScroll = new ScrollView(this);
        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(11);
        logView.setTextIsSelectable(true);
        logView.setPadding(dp(8), dp(8), dp(8), dp(8));
        logView.setBackgroundColor(Color.argb(40, 255, 255, 255));
        logScroll.addView(logView);
        col.addView(logScroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(320)));

        setContentView(root);
        if (b != null) {
            String n = b.getString("nsp"), k = b.getString("keys");
            if (n != null) setNsp(Uri.parse(n));
            if (k != null) setKeys(Uri.parse(k));
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle o) {
        super.onSaveInstanceState(o);
        if (nspUri != null) o.putString("nsp", nspUri.toString());
        if (keysUri != null) o.putString("keys", keysUri.toString());
    }

    @Override
    protected void onResume() {
        super.onResume();
        permBtn.setVisibility(hasStorage() ? View.GONE : View.VISIBLE);
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    private TextView text(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setPadding(0, dp(6), 0, dp(6));
        return t;
    }

    private Button button(String s, View.OnClickListener l) {
        Button bt = new Button(this);
        bt.setText(s);
        bt.setAllCaps(false);
        bt.setOnClickListener(l);
        return bt;
    }

    // ---------------------------------------------------------------- permissões

    private boolean hasStorage() {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        if (Build.VERSION.SDK_INT >= 23) {
            return checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    == PackageManager.PERMISSION_GRANTED;
        }
        return true;
    }

    private void requestStorage() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
        } else if (Build.VERSION.SDK_INT >= 23) {
            requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE,
                    Manifest.permission.READ_EXTERNAL_STORAGE}, REQ_PERM);
        }
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] p, int[] r) {
        permBtn.setVisibility(hasStorage() ? View.GONE : View.VISIBLE);
    }

    // ---------------------------------------------------------------- seleção

    private void pick(int req) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i, req);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (res != RESULT_OK || data == null || data.getData() == null) return;
        Uri u = data.getData();
        try {
            getContentResolver().takePersistableUriPermission(u, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (Exception ignored) {
        }
        if (req == REQ_NSP) setNsp(u);
        else if (req == REQ_KEYS) setKeys(u);
    }

    private void setNsp(Uri u) {
        nspUri = u;
        nspLabel.setText("NSP: " + displayName(u));
    }

    private void setKeys(Uri u) {
        keysUri = u;
        keysLabel.setText("Chaves: " + displayName(u));
    }

    private String displayName(Uri u) {
        try (Cursor c = getContentResolver().query(u, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int n = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                int s = c.getColumnIndex(OpenableColumns.SIZE);
                String name = n >= 0 ? c.getString(n) : u.getLastPathSegment();
                if (s >= 0 && !c.isNull(s)) name += "  (" + NspExtractor.human(c.getLong(s)) + ")";
                return name;
            }
        } catch (Exception ignored) {
        }
        return u.toString();
    }

    // ---------------------------------------------------------------- extração

    private void log(String s) {
        ui.post(() -> {
            logView.append(s + "\n");
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void setRunning(boolean r) {
        running = r;
        ui.post(() -> {
            extractBtn.setEnabled(!r);
            listBtn.setEnabled(!r);
            cancelBtn.setEnabled(r);
            if (r) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        });
    }

    private void start(boolean listOnly) {
        if (running) return;
        if (nspUri == null || keysUri == null) {
            log("Escolha o NSP e o prod.keys primeiro.");
            return;
        }
        if (!listOnly && !hasStorage()) {
            log("Permita o acesso aos arquivos (botão no topo) para gravar a pasta romfs.");
            requestStorage();
            return;
        }
        String tkHex = titleKeyEdit.getText().toString().trim();
        if (!tkHex.isEmpty() && !tkHex.matches("[0-9A-Fa-f]{32}")) {
            log("Titlekey inválida: precisa ter 32 caracteres hexadecimais.");
            return;
        }
        final File out = new File(outEdit.getText().toString().trim());
        logView.setText("");
        bar.setProgress(0);
        progressLabel.setText("");
        cancelled = false;
        setRunning(true);

        new Thread(() -> {
            PowerManager.WakeLock wl = ((PowerManager) getSystemService(POWER_SERVICE))
                    .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "romfsextractor:extract");
            wl.acquire(6 * 60 * 60 * 1000L);
            long t0 = SystemClock.elapsedRealtime();
            try {
                Map<String, byte[]> keys;
                try (InputStream in = getContentResolver().openInputStream(keysUri)) {
                    keys = NspExtractor.parseKeys(in);
                }
                try (ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(nspUri, "r");
                     FileInputStream fis = new FileInputStream(pfd.getFileDescriptor());
                     FileChannel ch = fis.getChannel()) {
                    NspExtractor x = new NspExtractor(ch, keys, new NspExtractor.Listener() {
                        long last;

                        @Override
                        public void log(String m) {
                            MainActivity.this.log(m);
                        }

                        @Override
                        public void progress(long done, long total) {
                            long now = SystemClock.elapsedRealtime();
                            if (now - last < 300 && done != total) return;
                            last = now;
                            double secs = Math.max((now - t0) / 1000.0, 0.001);
                            String s = String.format(Locale.ROOT, "%.1f%%  %s / %s  (%s/s)",
                                    total == 0 ? 100.0 : 100.0 * done / total,
                                    NspExtractor.human(done), NspExtractor.human(total),
                                    NspExtractor.human((long) (done / secs)));
                            int p = total == 0 ? 1000 : (int) (1000 * done / total);
                            ui.post(() -> {
                                bar.setProgress(p);
                                progressLabel.setText(s);
                            });
                        }

                        @Override
                        public boolean isCancelled() {
                            return cancelled;
                        }
                    });
                    if (!tkHex.isEmpty()) x.setManualTitleKey(NspExtractor.hex(tkHex));
                    int n = x.extract(out, listOnly);
                    if (!listOnly) {
                        log(String.format(Locale.ROOT, "\nPronto! %d arquivos em %d s.", n,
                                (SystemClock.elapsedRealtime() - t0) / 1000));
                        log("No port, escolha a pasta: " + out.getAbsolutePath());
                    }
                }
            } catch (NspExtractor.ExtractException e) {
                log("ERRO: " + e.getMessage());
            } catch (Throwable e) {
                log("ERRO: " + e);
            } finally {
                if (wl.isHeld()) wl.release();
                setRunning(false);
            }
        }, "extract").start();
    }
}
