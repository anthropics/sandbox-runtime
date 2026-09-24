package com.anthropic.srt;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/**
 * JVM agent injected by sandbox-runtime via {@code JAVA_TOOL_OPTIONS=-javaagent:...}.
 *
 * <p>The JVM does not read {@code HTTPS_PROXY} / {@code NO_PROXY}: proxy selection comes from the
 * {@code https.proxyHost} family of system properties, and proxy credentials can only be supplied
 * through {@link Authenticator}. Neither can be expressed as an environment variable, so JVM tools
 * (Bazel's remote cache over gRPC, Gradle, Maven, ...) either dial the target directly (and fail,
 * because the sandbox has no route out) or reach the proxy without the credential it requires.
 *
 * <p>This agent bridges the gap at JVM start-up. From the proxy env vars sandbox-runtime already
 * sets it:
 *
 * <ul>
 *   <li>sets {@code http[s].proxyHost} / {@code http[s].proxyPort} (unless the property was given
 *       explicitly as a {@code -D} JVM argument, which wins),
 *   <li>sets {@code http.nonProxyHosts} from {@code NO_PROXY} (same rule),
 *   <li>re-enables Basic auth for CONNECT tunnels ({@code jdk.http.auth.tunneling.disabledSchemes},
 *       which the JDK defaults to {@code Basic}), and
 *   <li>installs a default {@link Authenticator} that answers the proxy's challenge with the
 *       credential from the URL, and delegates everything else to any previously installed one.
 * </ul>
 *
 * <p>Nothing here is specific to sandbox-runtime's proxy beyond reading the standard env vars, and
 * every step is a no-op when the corresponding env var is absent or unparsable. The agent must stay
 * dependency-free and Java 8 compatible; it is compiled with {@code --release 8}.
 */
public final class ProxyAgent {

  private ProxyAgent() {}

  /** Entry point for {@code -javaagent}. */
  public static void premain(String args, Instrumentation inst) {
    install();
  }

  /** Entry point for dynamic attach; identical behaviour. */
  public static void agentmain(String args, Instrumentation inst) {
    install();
  }

  /** Runs the full configuration against the process environment. Idempotent. */
  static void install() {
    try {
      install(System.getenv("HTTPS_PROXY"), System.getenv("https_proxy"),
          System.getenv("HTTP_PROXY"), System.getenv("http_proxy"),
          System.getenv("NO_PROXY"), System.getenv("no_proxy"));
    } catch (RuntimeException e) {
      // A broken agent must never take the JVM down with it.
      System.err.println("[srt-proxy-agent] ignoring: " + e);
    }
  }

  static void install(String httpsUpper, String httpsLower, String httpUpper, String httpLower,
      String noProxyUpper, String noProxyLower) {
    ProxyUrl https = ProxyUrl.parse(first(httpsUpper, httpsLower));
    ProxyUrl http = ProxyUrl.parse(first(httpUpper, httpLower));
    if (https == null && http == null) {
      return;
    }
    // "Already set" is not a good enough reason to yield: on macOS the JVM seeds the proxy
    // properties from the OS network settings at start-up, and inside the sandbox that system
    // proxy is unreachable — only the sandbox proxy is. So the properties are overwritten unless
    // the user passed them explicitly as -D arguments (command line or JAVA_TOOL_OPTIONS).
    Set<String> explicit = explicitSystemProperties();
    Properties props = System.getProperties();
    if (https != null) {
      setUnlessExplicit(props, explicit, "https.proxyHost", https.host);
      setUnlessExplicit(props, explicit, "https.proxyPort", Integer.toString(https.port));
    }
    if (http != null) {
      setUnlessExplicit(props, explicit, "http.proxyHost", http.host);
      setUnlessExplicit(props, explicit, "http.proxyPort", Integer.toString(http.port));
    }
    String nonProxyHosts = toNonProxyHosts(first(noProxyUpper, noProxyLower));
    if (nonProxyHosts != null) {
      setUnlessExplicit(props, explicit, "http.nonProxyHosts", nonProxyHosts);
    }
    // HttpURLConnection refuses to send Basic on a CONNECT unless this is cleared. Only matters
    // when the proxy needs a credential, but harmless otherwise, and JVM-global either way.
    setUnlessExplicit(props, explicit, "jdk.http.auth.tunneling.disabledSchemes", "");

    List<ProxyUrl> withCreds = new ArrayList<ProxyUrl>();
    if (https != null && https.user != null) {
      withCreds.add(https);
    }
    if (http != null && http.user != null && !http.sameEndpoint(https)) {
      withCreds.add(http);
    }
    if (!withCreds.isEmpty()) {
      Authenticator.setDefault(new ProxyAuthenticator(withCreds, currentDefault()));
    }
  }

  private static void setUnlessExplicit(Properties props, Set<String> explicit, String key,
      String value) {
    if (!explicit.contains(key)) {
      props.setProperty(key, value);
    }
  }

  /**
   * Names of system properties passed as {@code -Dname=value} JVM arguments (command line and
   * JAVA_TOOL_OPTIONS both show up in the runtime MXBean's input arguments). Distinguishes a
   * deliberate override from the values the JVM seeds itself. Reflection because java.management
   * is optional in jlink'd runtimes; when it is missing nothing is treated as explicit.
   */
  static Set<String> explicitSystemProperties() {
    Set<String> names = new HashSet<String>();
    try {
      Class<?> mf = Class.forName("java.lang.management.ManagementFactory");
      Object runtime = mf.getMethod("getRuntimeMXBean").invoke(null);
      // Invoke through the public interface: the implementation class lives in a non-exported
      // package and reflecting on it directly is an IllegalAccessException on 9+.
      Class<?> mxBean = Class.forName("java.lang.management.RuntimeMXBean");
      @SuppressWarnings("unchecked")
      List<String> args = (List<String>) mxBean.getMethod("getInputArguments").invoke(runtime);
      for (String arg : args) {
        if (arg.startsWith("-D")) {
          int eq = arg.indexOf('=');
          names.add(eq < 0 ? arg.substring(2) : arg.substring(2, eq));
        }
      }
    } catch (ReflectiveOperationException e) {
      // no java.management, or an inaccessible MXBean: fall through
    } catch (RuntimeException e) {
      // fall through
    }
    return names;
  }

  /**
   * {@code Authenticator.getDefault()} is Java 9+; on 8 there is no way to read the current default,
   * so it is treated as absent (at premain time nothing has had the chance to install one anyway).
   */
  private static Authenticator currentDefault() {
    try {
      return (Authenticator) Authenticator.class.getMethod("getDefault").invoke(null);
    } catch (ReflectiveOperationException e) {
      return null;
    } catch (RuntimeException e) {
      return null;
    }
  }

  private static String first(String a, String b) {
    if (a != null && !a.isEmpty()) {
      return a;
    }
    return b;
  }

  /**
   * Answers proxy-authentication challenges for the configured proxy endpoint(s) and delegates
   * everything else. Matches on host+port rather than {@code RequestorType}: gRPC-Java pre-1.60
   * asks through the overload that reports {@code SERVER}, and the endpoint match already pins the
   * credential to the proxy — it is never offered to any other host.
   */
  static final class ProxyAuthenticator extends Authenticator {
    private final List<ProxyUrl> proxies;
    private final Authenticator previous;

    ProxyAuthenticator(List<ProxyUrl> proxies, Authenticator previous) {
      this.proxies = proxies;
      this.previous = previous;
    }

    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
      String host = getRequestingHost();
      int port = getRequestingPort();
      if (host != null) {
        for (ProxyUrl p : proxies) {
          if (p.port == port && p.host.equalsIgnoreCase(host)) {
            return new PasswordAuthentication(p.user, p.password.toCharArray());
          }
        }
      }
      if (previous != null) {
        // requestPasswordAuthenticationInstance is Java 9+ (and `previous` can only be non-null
        // on 9+, see currentDefault()); reflection keeps the class loadable on 8.
        try {
          Method m = Authenticator.class.getMethod("requestPasswordAuthenticationInstance",
              String.class, InetAddress.class, int.class, String.class, String.class,
              String.class, URL.class, RequestorType.class);
          return (PasswordAuthentication) m.invoke(previous, getRequestingHost(),
              getRequestingSite(), getRequestingPort(), getRequestingProtocol(),
              getRequestingPrompt(), getRequestingScheme(), getRequestingURL(),
              getRequestorType());
        } catch (ReflectiveOperationException e) {
          return null;
        }
      }
      return null;
    }
  }

  /** {@code scheme://[user[:password]@]host[:port][/...]}, credentials percent-decoded. */
  static final class ProxyUrl {
    final String host;
    final int port;
    final String user; // null when the URL carries no userinfo
    final String password; // "" when userinfo has no ':' part

    private ProxyUrl(String host, int port, String user, String password) {
      this.host = host;
      this.port = port;
      this.user = user;
      this.password = password;
    }

    boolean sameEndpoint(ProxyUrl o) {
      return o != null && o.port == port && o.host.equalsIgnoreCase(host);
    }

    static ProxyUrl parse(String url) {
      if (url == null) {
        return null;
      }
      String s = url.trim();
      int schemeEnd = s.indexOf("://");
      String scheme = "http";
      if (schemeEnd >= 0) {
        scheme = s.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
        s = s.substring(schemeEnd + 3);
      }
      // Only HTTP CONNECT proxies map onto https.proxyHost; a socks5h:// URL
      // would need socksProxyHost, which is a different (and for JVM clients
      // far rarer) code path. Leave those alone.
      if (!scheme.equals("http") && !scheme.equals("https")) {
        return null;
      }
      int slash = s.indexOf('/');
      if (slash >= 0) {
        s = s.substring(0, slash);
      }
      String user = null;
      String password = "";
      int at = s.lastIndexOf('@');
      if (at >= 0) {
        String userinfo = s.substring(0, at);
        s = s.substring(at + 1);
        int colon = userinfo.indexOf(':');
        if (colon >= 0) {
          user = pctDecode(userinfo.substring(0, colon));
          password = pctDecode(userinfo.substring(colon + 1));
        } else {
          user = pctDecode(userinfo);
        }
      }
      String host;
      int port = scheme.equals("https") ? 443 : 80;
      if (s.startsWith("[")) {
        int close = s.indexOf(']');
        if (close < 0) {
          return null;
        }
        host = s.substring(1, close);
        String rest = s.substring(close + 1);
        if (rest.startsWith(":")) {
          port = parsePort(rest.substring(1));
        } else if (!rest.isEmpty()) {
          return null;
        }
      } else {
        int colon = s.lastIndexOf(':');
        if (colon >= 0) {
          host = s.substring(0, colon);
          port = parsePort(s.substring(colon + 1));
        } else {
          host = s;
        }
      }
      if (host.isEmpty() || port <= 0 || port > 65535) {
        return null;
      }
      return new ProxyUrl(host, port, user, password);
    }

    private static int parsePort(String p) {
      try {
        return Integer.parseInt(p);
      } catch (NumberFormatException e) {
        return -1;
      }
    }
  }

  /**
   * RFC 3986 percent-decoding of a userinfo component. Unlike {@code URLDecoder} this leaves
   * {@code +} alone (it is a literal in userinfo) and passes malformed escapes through unchanged.
   */
  static String pctDecode(String s) {
    if (s.indexOf('%') < 0) {
      return s;
    }
    byte[] in = s.getBytes(StandardCharsets.UTF_8);
    byte[] out = new byte[in.length];
    int n = 0;
    for (int i = 0; i < in.length; i++) {
      byte b = in[i];
      if (b == '%' && i + 2 < in.length) {
        int hi = Character.digit(in[i + 1], 16);
        int lo = Character.digit(in[i + 2], 16);
        if (hi >= 0 && lo >= 0) {
          out[n++] = (byte) ((hi << 4) | lo);
          i += 2;
          continue;
        }
      }
      out[n++] = b;
    }
    return new String(out, 0, n, StandardCharsets.UTF_8);
  }

  /**
   * Translate a {@code NO_PROXY} list into Java's {@code http.nonProxyHosts} syntax
   * ({@code |}-separated, {@code *} wildcard only at the start or end of an entry). Java's built-in
   * loopback defaults are re-added because setting the property replaces them. IPv4 CIDR entries
   * are expanded into the equivalent dotted-prefix wildcards when the prefix falls on a byte
   * boundary or covers a small range; anything that does not fit the syntax is dropped rather than
   * mistranslated. Returns null when there is nothing to set.
   */
  static String toNonProxyHosts(String noProxy) {
    if (noProxy == null || noProxy.trim().isEmpty()) {
      return null;
    }
    List<String> out = new ArrayList<String>();
    // Java's own defaults for the property, kept so localhost stays direct.
    add(out, "localhost");
    add(out, "127.*");
    add(out, "[::1]");
    add(out, "0.0.0.0");
    add(out, "[::0]");
    for (String raw : noProxy.split(",")) {
      String e = raw.trim();
      if (e.isEmpty()) {
        continue;
      }
      if (e.equals("*")) {
        return "*";
      }
      // Strip a :port suffix on plain hosts (curl accepts host:port); keep
      // bracketed IPv6 as-is.
      if (!e.startsWith("[") && e.indexOf(':') >= 0 && e.indexOf(':') == e.lastIndexOf(':')) {
        e = e.substring(0, e.indexOf(':'));
      }
      int slash = e.indexOf('/');
      if (slash >= 0) {
        for (String w : cidrToWildcards(e.substring(0, slash), e.substring(slash + 1))) {
          add(out, w);
        }
        continue;
      }
      if (e.startsWith("*.")) {
        add(out, e); // "*.example.com": already Java syntax
      } else if (e.startsWith(".")) {
        add(out, "*" + e); // ".example.com" -> "*.example.com"
      } else if (e.startsWith("[") && e.endsWith("]")) {
        add(out, e);
      } else if (e.indexOf(':') >= 0) {
        add(out, "[" + e + "]"); // bare IPv6 literal
      } else {
        add(out, e);
      }
    }
    return join(out);
  }

  private static void add(List<String> out, String entry) {
    if (!out.contains(entry)) {
      out.add(entry);
    }
  }

  private static String join(List<String> parts) {
    StringBuilder sb = new StringBuilder();
    for (String p : parts) {
      if (sb.length() > 0) {
        sb.append('|');
      }
      sb.append(p);
    }
    return sb.toString();
  }

  /** IPv4 CIDR to dotted-prefix wildcards; empty when the range cannot be expressed. */
  static List<String> cidrToWildcards(String addr, String prefixStr) {
    List<String> out = new ArrayList<String>();
    String[] octets = addr.split("\\.");
    int prefix;
    try {
      prefix = Integer.parseInt(prefixStr);
    } catch (NumberFormatException e) {
      return out;
    }
    if (octets.length != 4 || prefix < 0 || prefix > 32) {
      return out;
    }
    int[] o = new int[4];
    for (int i = 0; i < 4; i++) {
      try {
        o[i] = Integer.parseInt(octets[i]);
      } catch (NumberFormatException e) {
        return out;
      }
      if (o[i] < 0 || o[i] > 255) {
        return out;
      }
    }
    if (prefix == 32) {
      out.add(addr);
      return out;
    }
    if (prefix == 0) {
      out.add("*");
      return out;
    }
    int fullOctets = prefix / 8;
    int bits = prefix % 8;
    if (bits == 0) {
      out.add(prefixString(o, fullOctets) + "*");
      return out;
    }
    // Partial octet: enumerate the values it can take (2^(8-bits) of them),
    // e.g. 172.16.0.0/12 -> 172.16.* ... 172.31.*. Bounded to keep the
    // property readable; ranges wider than /4-in-octet are dropped.
    int span = 1 << (8 - bits);
    if (span > 16) {
      return out;
    }
    int base = o[fullOctets] & ~(span - 1);
    for (int v = base; v < base + span; v++) {
      out.add(prefixString(o, fullOctets) + v + (fullOctets < 3 ? ".*" : ""));
    }
    return out;
  }

  private static String prefixString(int[] o, int count) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < count; i++) {
      sb.append(o[i]).append('.');
    }
    return sb.toString();
  }
}
