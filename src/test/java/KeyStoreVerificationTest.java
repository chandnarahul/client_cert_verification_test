import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KeyStoreVerificationTest {

    @Test
    public void should_inject_clientcert_and_return_200_after_ignoring_truststore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        String keyStorePassword = "badssl.com";
        keyStore.load(new FileInputStream("badssl.com-client.p12"), keyStorePassword.toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyStorePassword.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        SSLSocketFactory sslSocketFactory = ctx.getSocketFactory();

        URL url = new URL("https://client.badssl.com/");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslSocketFactory);
        BufferedReader br = new BufferedReader(new InputStreamReader((connection.getInputStream())));
        StringBuilder sb = new StringBuilder();
        String output;
        while ((output = br.readLine()) != null) {
            sb.append(output);
        }
        assertEquals(200, connection.getResponseCode());
        assertTrue(sb.length() > 0);
    }
}
