package org.sasanlabs.internal.utility;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Locale;

/**
 * Utility for validating user supplied URLs before the server makes outbound requests to them
 * (SSRF protection).
 */
public final class SafeUrlUtils {

    private static final String HTTP = "http";
    private static final String HTTPS = "https";

    private SafeUrlUtils() {}

    /**
     * Parses the given value as an absolute http/https URL with a host and without embedded
     * credentials.
     *
     * @param value untrusted URL
     * @return the parsed URL
     * @throws MalformedURLException if the value is not an acceptable http/https URL
     */
    public static URL parseHttpUrl(String value) throws MalformedURLException {
        if (value == null) {
            throw new MalformedURLException("URL is missing");
        }
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            if (scheme == null
                    || !(HTTP.equals(scheme.toLowerCase(Locale.ROOT))
                            || HTTPS.equals(scheme.toLowerCase(Locale.ROOT)))) {
                throw new MalformedURLException("Only http and https URLs are allowed");
            }
            if (uri.getHost() == null || uri.getUserInfo() != null) {
                throw new MalformedURLException("URL must have a host and no user info");
            }
            return uri.toURL();
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new MalformedURLException("Invalid URL: " + e.getMessage());
        }
    }

    /**
     * Ensures every address the host of the URL resolves to is a public address, i.e. not
     * loopback, link-local (cloud metadata), private, multicast or wildcard.
     *
     * @param url URL whose host is to be checked
     * @throws IOException if the host cannot be resolved or resolves to a non public address
     */
    public static void assertPublicHost(URL url) throws IOException {
        for (InetAddress address : InetAddress.getAllByName(url.getHost())) {
            if (isNonPublic(address)) {
                throw new IOException("Requests to internal addresses are not allowed");
            }
        }
    }

    private static boolean isNonPublic(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] raw = address.getAddress();
        if (raw.length == 4) {
            // 100.64.0.0/10 (carrier grade NAT)
            return (raw[0] & 0xFF) == 100 && (raw[1] & 0xC0) == 64;
        }
        // fc00::/7 (unique local addresses)
        return raw.length == 16 && (raw[0] & 0xFE) == 0xFC;
    }
}
