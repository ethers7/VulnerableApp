package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;

/**
 * Utility to validate user supplied URLs before the server connects to them, so that user data can
 * not be used to reach internal, loopback, link-local or cloud metadata endpoints.
 */
public final class SafeUrlUtils {

    private SafeUrlUtils() {}

    /**
     * @param value user supplied URL
     * @return the parsed URL when it is http/https, has a host, has no user info and every address
     *     the host resolves to is publicly routable. Empty otherwise (including DNS failure).
     */
    public static Optional<URL> toSafeUrl(String value) {
        if (value == null || value.trim().isEmpty()) {
            return Optional.empty();
        }
        try {
            URL url = new URL(value);
            url.toURI();
            String protocol = url.getProtocol().toLowerCase(Locale.ROOT);
            if (!"http".equals(protocol) && !"https".equals(protocol)) {
                return Optional.empty();
            }
            String host = url.getHost();
            if (host == null || host.isEmpty() || url.getUserInfo() != null) {
                return Optional.empty();
            }
            InetAddress[] addresses = InetAddress.getAllByName(host);
            if (addresses.length == 0) {
                return Optional.empty();
            }
            for (InetAddress address : addresses) {
                if (isRestricted(address)) {
                    return Optional.empty();
                }
            }
            return Optional.of(url);
        } catch (MalformedURLException | URISyntaxException | UnknownHostException e) {
            return Optional.empty();
        }
    }

    private static boolean isRestricted(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            // 0.0.0.0/8 and carrier grade NAT 100.64.0.0/10
            return first == 0 || (first == 100 && second >= 64 && second <= 127);
        }
        // IPv6 unique local addresses fc00::/7 (includes fd00:ec2::254 metadata endpoint)
        return (bytes[0] & 0xFE) == 0xFC;
    }
}
