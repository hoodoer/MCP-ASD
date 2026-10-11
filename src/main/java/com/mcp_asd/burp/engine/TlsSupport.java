package com.mcp_asd.burp.engine;

import burp.api.montoya.MontoyaApi;
import com.mcp_asd.burp.GlobalSettings;
import com.mcp_asd.burp.ui.ConnectionConfiguration;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * TLS and proxy setup for the streaming transports (SSE, WebSocket), which can't use
 * Burp's HTTP API and so still use OkHttp.
 *
 * - When routed through Burp's proxy listener, only Burp's own CA is trusted. Burp then
 *   applies its own upstream TLS settings and client TLS certificates.
 * - When connecting directly, the JVM's normal certificate validation applies unless the
 *   user has explicitly enabled "ignore TLS errors" in the settings.
 */
final class TlsSupport {
    // Burp CA per proxy listener ("host:port"), fetched once from http://burp/cert
    private static final Map<String, X509TrustManager> BURP_CA_CACHE = new ConcurrentHashMap<>();

    private TlsSupport() {}

    static void configure(OkHttpClient.Builder builder, MontoyaApi api, GlobalSettings settings,
                          ConnectionConfiguration config, String transportName) {
        Proxy burpProxy = burpProxy(settings);
        if (burpProxy != null) {
            api.logging().logToOutput(transportName + ": Using proxy " + burpProxy.address());
            builder.proxy(burpProxy);
            if (config.isUseMtls()) {
                api.logging().logToOutput(transportName + ": Traffic is routed through Burp, so the client certificate "
                        + "must be configured in Burp (Settings > Network > TLS > Client TLS certificates) to reach the server.");
            }
            try {
                X509TrustManager burpCa = BURP_CA_CACHE.computeIfAbsent(
                        settings.getProxyHost() + ":" + settings.getProxyPort(), k -> fetchBurpCa(burpProxy));
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{burpCa}, new SecureRandom());
                builder.sslSocketFactory(sslContext.getSocketFactory(), burpCa);
                // The chain must be issued by the local Burp CA, i.e. this is Burp's listener
                // presenting a certificate it generated; Burp enforces its own upstream checks.
                builder.hostnameVerifier((hostname, session) -> true);
            } catch (Exception e) {
                api.logging().logToError(transportName + ": Could not load Burp's CA certificate from the proxy listener ("
                        + e.getMessage() + "). Check the proxy host/port in MCP-ASD settings.");
            }
            return;
        }

        KeyManager[] keyManagers = config.isUseMtls() ? loadClientCertificate(api, config, transportName) : null;
        try {
            X509TrustManager trustManager = settings != null && settings.isIgnoreTlsErrorsEnabled()
                    ? new TrustAllManager()
                    : defaultTrustManager();
            if (trustManager instanceof TrustAllManager) {
                api.logging().logToOutput(transportName + ": TLS certificate validation disabled by user setting.");
                builder.hostnameVerifier((hostname, session) -> true);
            }
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, new TrustManager[]{trustManager}, new SecureRandom());
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        } catch (Exception e) {
            api.logging().logToError(transportName + ": Failed to configure TLS: " + e.getMessage());
        }
    }

    private static Proxy burpProxy(GlobalSettings settings) {
        if (settings == null || !settings.isProxyTrafficEnabled()) return null;
        String host = settings.getProxyHost();
        int port = settings.getProxyPort();
        if (host == null || host.isEmpty() || port <= 0) return null;
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    }

    private static X509TrustManager fetchBurpCa(Proxy burpProxy) {
        OkHttpClient client = new OkHttpClient.Builder()
                .proxy(burpProxy)
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        try (Response response = client.newCall(new Request.Builder().url("http://burp/cert").build()).execute()) {
            if (!response.isSuccessful() || response.body() == null) {
                throw new IllegalStateException("HTTP " + response.code() + " from http://burp/cert");
            }
            X509Certificate ca = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(response.body().bytes()));

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("burp-ca", ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            return firstX509(tmf.getTrustManagers());
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        } finally {
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
    }

    private static X509TrustManager defaultTrustManager() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        return firstX509(tmf.getTrustManagers());
    }

    private static X509TrustManager firstX509(TrustManager[] managers) {
        for (TrustManager tm : managers) {
            if (tm instanceof X509TrustManager x509) return x509;
        }
        throw new IllegalStateException("No X509TrustManager available");
    }

    private static KeyManager[] loadClientCertificate(MontoyaApi api, ConnectionConfiguration config, String transportName) {
        try {
            char[] password = config.getClientCertPassword().toCharArray();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(config.getClientCertPath())) {
                keyStore.load(fis, password);
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password);
            return kmf.getKeyManagers();
        } catch (Exception e) {
            api.logging().logToError(transportName + ": Failed to configure mTLS: " + e.getMessage());
            return null;
        }
    }

    /** Only used when the user explicitly opts in to ignoring TLS errors on direct connections. */
    private static final class TrustAllManager implements X509TrustManager {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
