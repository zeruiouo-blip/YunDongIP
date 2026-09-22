package com.yundongip.client;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.File;

public class MainActivity extends Activity {
    private Process backend;
    private WebView webView;
    private final Handler handler = new Handler();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        webView = new WebView(this);
        setContentView(webView);
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        webView.setWebViewClient(new WebViewClient());
        startBackend();
        loadWhenReady(0);
    }

    private void startBackend() {
        try {
            String nativeDir = getApplicationInfo().nativeLibraryDir;
            File exe = new File(nativeDir, "libyundongip.so");
            ProcessBuilder pb = new ProcessBuilder(
                exe.getAbsolutePath(), "-host", "127.0.0.1", "-port", "13335", "-open-browser=false"
            );
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);
            backend = pb.start();
        } catch (Exception e) {
            webView.loadData("<h3>YunDongIP 后端启动失败</h3><pre>"+e.toString()+"</pre>", "text/html", "UTF-8");
        }
    }

    private void loadWhenReady(final int attempt) {
        handler.postDelayed(() -> {
            if (backend != null && backend.isAlive()) {
                webView.loadUrl("http://127.0.0.1:13335/");
            } else if (attempt < 20) {
                loadWhenReady(attempt + 1);
            }
        }, attempt == 0 ? 900 : 400);
    }

    @Override protected void onDestroy() {
        if (backend != null) backend.destroy();
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
