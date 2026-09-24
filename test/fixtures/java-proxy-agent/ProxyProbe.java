// Test fixture for test/sandbox/java-proxy-agent.test.ts. Run with the JDK's
// single-file source launcher (`java ProxyProbe.java <mode> ...`) so no
// separate compile step is needed.
//
//   props           print the proxy-related system properties and what the
//                   default Authenticator answers for the given endpoint
//   connect <url>   open <url> with HttpURLConnection through the default
//                   ProxySelector; print the response code or the exception
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URL;

public class ProxyProbe {
  public static void main(String[] args) throws Exception {
    if (args[0].equals("props")) {
      for (String k : new String[] {
          "https.proxyHost", "https.proxyPort", "http.proxyHost", "http.proxyPort",
          "http.nonProxyHosts", "jdk.http.auth.tunneling.disabledSchemes"}) {
        System.out.println(k + "=" + System.getProperty(k));
      }
      String host = args[1];
      int port = Integer.parseInt(args[2]);
      PasswordAuthentication pa = Authenticator.requestPasswordAuthentication(
          host, null, port, "https", "", null, new URI("https://" + host + ":" + port).toURL(),
          Authenticator.RequestorType.PROXY);
      System.out.println("auth.proxy=" + (pa == null ? "null" : pa.getUserName() + ":" + new String(pa.getPassword())));
      // The pre-1.60 gRPC-Java overload reports RequestorType.SERVER.
      pa = Authenticator.requestPasswordAuthentication(host, null, port, "https", "", null);
      System.out.println("auth.server=" + (pa == null ? "null" : pa.getUserName()));
      pa = Authenticator.requestPasswordAuthentication("example.invalid", null, 443, "https", "", null);
      System.out.println("auth.other=" + (pa == null ? "null" : pa.getUserName()));
      System.out.println("select.https=" + ProxySelector.getDefault().select(new URI("https://example.invalid/")));
      System.out.println("select.localhost=" + ProxySelector.getDefault().select(new URI("http://localhost:1/")));
      System.out.println("select.private=" + ProxySelector.getDefault().select(new URI("http://172.20.0.1/")));
    } else {
      HttpURLConnection c = (HttpURLConnection) new URI(args[1]).toURL().openConnection();
      c.setConnectTimeout(5000);
      c.setReadTimeout(5000);
      try {
        System.out.println("code=" + c.getResponseCode());
      } catch (Exception e) {
        System.out.println("error=" + e);
      }
    }
  }
}
