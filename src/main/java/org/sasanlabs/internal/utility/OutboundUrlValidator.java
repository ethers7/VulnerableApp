package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Validates the destination of server side outbound requests to prevent SSRF (CWE-918). */
public final class OutboundUrlValidator {

    // Blocks schemes like file, ftp, gopher, jar and netdoc which must never be fetched.
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    // Allowlist of the destinations this application is allowed to fetch content from.
    private static final Set<String> ALLOWED_HOSTS =
            Set.of("github.com", "gist.githubusercontent.com", "raw.githubusercontent.com");

    private static final Pattern IPV4_LITERAL = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    private OutboundUrlValidator() {}

    /** Returns the parsed URL only when it points to an allowlisted outbound destination. */
    public static Optional<URL> parseAllowedUrl(String candidateUrl) {
        if (candidateUrl == null) {
            return Optional.empty();
        }
        URL parsedUrl;
        try {
            parsedUrl = new URL(candidateUrl);
            parsedUrl.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            return Optional.empty();
        }
        if (!isAllowedDestination(parsedUrl)) {
            return Optional.empty();
        }
        return Optional.of(parsedUrl);
    }

    private static boolean isAllowedDestination(URL url) {
        String scheme = url.getProtocol();
        if (scheme == null) {
            return false;
        }
        if (!ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            return false;
        }
        String host = normalizeHost(url.getHost());
        if (host.isEmpty()) {
            return false;
        }
        if (isInternalAddressLiteral(host)) {
            return false;
        }
        return ALLOWED_HOSTS.contains(host);
    }

    private static String normalizeHost(String host) {
        if (host == null) {
            return "";
        }
        String normalizedHost = host.trim().toLowerCase(Locale.ROOT);
        // A trailing dot resolves to the same host, hence it is removed before the comparison.
        while (normalizedHost.endsWith(".")) {
            normalizedHost = normalizedHost.substring(0, normalizedHost.length() - 1);
        }
        return normalizedHost;
    }

    // Rejects hosts which are literal addresses of the loopback, link local (like the
    // 169.254.169.254 cloud metadata endpoint), private or any other internal range.
    private static boolean isInternalAddressLiteral(String host) {
        String addressLiteral = host;
        if (addressLiteral.startsWith("[") && addressLiteral.endsWith("]")) {
            addressLiteral = addressLiteral.substring(1, addressLiteral.length() - 1);
        }
        boolean ipv4Literal = IPV4_LITERAL.matcher(addressLiteral).matches();
        boolean ipv6Literal = addressLiteral.indexOf(':') >= 0;
        if (!ipv4Literal && !ipv6Literal) {
            return false;
        }
        try {
            // Literal addresses are parsed without performing any name resolution.
            InetAddress address = InetAddress.getByName(addressLiteral);
            return address.isAnyLocalAddress()
                    || address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress()
                    || address.isMulticastAddress()
                    || isUniqueLocalAddress(address);
        } catch (UnknownHostException e) {
            // Fails closed when the literal address cannot be parsed.
            return true;
        }
    }

    private static boolean isUniqueLocalAddress(InetAddress address) {
        byte[] addressBytes = address.getAddress();
        // IPv6 unique local addresses, fc00::/7, are not routable on the internet.
        return addressBytes.length == 16 && (addressBytes[0] & 0xFE) == 0xFC;
    }
}
