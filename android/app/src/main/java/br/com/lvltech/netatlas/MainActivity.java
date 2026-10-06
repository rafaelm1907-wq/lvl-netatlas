package br.com.lvltech.netatlas;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.GeolocationPermissions;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.net.URI;

public class MainActivity extends Activity {
    private static final String PREFS = "netatlas_settings";
    private static final String SERVER_URL = "server_url";
    private static final int FILE_CHOOSER_REQUEST = 81;
    private static final int LOCATION_REQUEST = 82;

    private WebView webView;
    private ProgressBar progress;
    private ValueCallback<Uri[]> fileCallback;
    private String pendingGeolocationOrigin;
    private GeolocationPermissions.Callback pendingGeolocationCallback;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildWebView();
        String savedUrl = preferences().getString(SERVER_URL, "");
        if (savedUrl.isEmpty()) showServerDialog(true);
        else webView.loadUrl(savedUrl);
    }

    private SharedPreferences preferences() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    private void buildWebView() {
        FrameLayout root = new FrameLayout(this);
        webView = new WebView(this);
        root.addView(webView, new FrameLayout.LayoutParams(-1, -1));

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        root.addView(progress, new FrameLayout.LayoutParams(-1, dp(3), Gravity.TOP));

        Button settingsButton = new Button(this);
        settingsButton.setText("⚙");
        settingsButton.setTextSize(20);
        settingsButton.setTextColor(Color.WHITE);
        settingsButton.setBackgroundColor(Color.argb(215, 8, 25, 46));
        settingsButton.setContentDescription("Configurar servidor do NetAtlas");
        settingsButton.setPadding(0, 0, 0, 0);
        settingsButton.setOnClickListener(v -> showServerDialog(false));
        FrameLayout.LayoutParams buttonParams = new FrameLayout.LayoutParams(dp(48), dp(48), Gravity.END | Gravity.BOTTOM);
        buttonParams.setMargins(0, 0, dp(14), dp(18));
        root.addView(settingsButton, buttonParams);
        setContentView(root);
        configureWebView();
    }

    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setGeolocationEnabled(true);
        settings.setAllowContentAccess(true);
        settings.setAllowFileAccess(true);
        settings.setMediaPlaybackRequiresUserGesture(false);
        settings.setUseWideViewPort(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String scheme = uri.getScheme();
                if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) return false;
                try { startActivity(new Intent(Intent.ACTION_VIEW, uri)); }
                catch (Exception ignored) { Toast.makeText(MainActivity.this, "Não há aplicativo para abrir este link.", Toast.LENGTH_SHORT).show(); }
                return true;
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override public void onProgressChanged(WebView view, int value) {
                progress.setProgress(value);
                progress.setVisibility(value < 100 ? View.VISIBLE : View.GONE);
            }

            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                try { startActivityForResult(params.createIntent(), FILE_CHOOSER_REQUEST); }
                catch (Exception error) {
                    fileCallback = null;
                    Toast.makeText(MainActivity.this, "Não foi possível abrir os arquivos.", Toast.LENGTH_LONG).show();
                    return false;
                }
                return true;
            }

            @Override public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
                if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                    callback.invoke(origin, true, false);
                } else {
                    pendingGeolocationOrigin = origin;
                    pendingGeolocationCallback = callback;
                    requestPermissions(new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, LOCATION_REQUEST);
                }
            }
        });
    }

    private void showServerDialog(boolean mandatory) {
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(22), dp(8), dp(22), 0);
        TextView help = new TextView(this);
        help.setText("Informe o endereço completo do servidor, incluindo http:// ou https:// e a porta quando necessária.");
        help.setTextSize(15);
        help.setPadding(0, 0, 0, dp(12));
        body.addView(help);
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("http://192.168.1.10:20050");
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        input.setText(preferences().getString(SERVER_URL, ""));
        body.addView(input, new LinearLayout.LayoutParams(-1, -2));

        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle(mandatory ? "Configurar LVL - NetAtlas" : "Servidor do NetAtlas")
                .setView(body).setPositiveButton("Salvar e abrir", null)
                .setNegativeButton(mandatory ? "Sair" : "Cancelar", (d, which) -> { if (mandatory) finish(); })
                .setCancelable(!mandatory);
        if (!mandatory) builder.setNeutralButton("Permissões", (d, which) -> startActivity(
                new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + getPackageName()))));
        AlertDialog dialog = builder.create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String url = normalizeUrl(input.getText().toString());
            if (!isValidServerUrl(url)) {
                input.setError("Use um endereço válido começando com http:// ou https://");
                return;
            }
            preferences().edit().putString(SERVER_URL, url).apply();
            dialog.dismiss();
            webView.loadUrl(url);
        }));
        dialog.show();
    }

    private String normalizeUrl(String value) {
        String result = value == null ? "" : value.trim();
        while (result.endsWith("/")) result = result.substring(0, result.length() - 1);
        return result;
    }

    private boolean isValidServerUrl(String value) {
        try {
            URI uri = new URI(value);
            return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) && uri.getHost() != null;
        } catch (Exception ignored) { return false; }
    }

    @Override public void onBackPressed() {
        if (webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_CHOOSER_REQUEST && fileCallback != null) {
            fileCallback.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(resultCode, data));
            fileCallback = null;
        }
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == LOCATION_REQUEST && pendingGeolocationCallback != null) {
            boolean allowed = results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED;
            pendingGeolocationCallback.invoke(pendingGeolocationOrigin, allowed, false);
            pendingGeolocationCallback = null;
            pendingGeolocationOrigin = null;
        }
    }

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
}
