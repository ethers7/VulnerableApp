package org.sasanlabs.internal.utility;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;

/**
 * Utility to validate user supplied URLs before the server connects to them (SSRF protection).
 *
 * <p>Only http/https URLs with a host, without user info, whose host resolves exclusively to public
 * addresses are accepted. Loopback, any-local, link-local, private, multicast and cloud metadata
 * addresses are rejected. Callers must not follow redirects for the returned URL because a redirect
 * would bypass this validation.
 */
public final class SafeUrlUtils {

    private SafeUrlUtils() {}

    /**
     * @param candidate untrusted URL string
     * @return the parsed URL when it is safe to connect to, otherwise {@link Optional#empty()}
     *     (including when the host cannot be resolved).
     */
    public static Optional<URL> toSafeUrl(String candidate) {
        if (candidate == null || candidate.trim().isEmpty()) {
            return Optional.empty();
        }
        try {
            URI uri = new URI(candidate.trim());
            String scheme = uri.getScheme();
            if (scheme == null) {
                return Optional.empty();
            }
            scheme = scheme.toLowerCase(Locale.ROOT);
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return Optional.empty();
            }
            String host = uri.getHost();
            if (host == null || host.isEmpty() || uri.getRawUserInfo() != null) {
                return Optional.empty();
            }
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isRestricted(address)) {
                    return Optional.empty();
                }
            }
            return Optional.of(uri.toURL());
        } catch (URISyntaxException
                | MalformedURLException
                | UnknownHostException
                | IllegalArgumentException
                | SecurityException e) {
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
        byte[] raw = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = raw[0] & 0xFF;
            int second = raw[1] & 0xFF;
            // 0.0.0.0/8, 100.64.0.0/10 (carrier-grade NAT), 169.254.0.0/16 (metadata)
            return first == 0
                    || (first == 100 && (second & 0xC0) == 64)
                    || (first == 169 && second == 254);
        }
        if (address instanceof Inet6Address) {
            // fc00::/7 unique local addresses (includes fd00:ec2::254 AWS metadata)
            return (raw[0] & 0xFE) == 0xFC;
        }
        return false;
    }
}
