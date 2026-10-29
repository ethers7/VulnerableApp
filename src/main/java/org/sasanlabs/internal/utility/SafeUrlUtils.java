package org.sasanlabs.internal.utility;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Optional;

/**
 * Utility to validate user supplied URLs before the server connects to them (SSRF protection).
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public final class SafeUrlUtils {

    private SafeUrlUtils() {}

    /**
     * Converts the candidate into a {@link URL} only if it is safe to connect to: http/https only,
     * host required, no userinfo, and every address the host resolves to is a public address
     * (not loopback, link-local, private, multicast, any-local or cloud metadata).
     *
     * @param candidate untrusted URL
     * @return the validated URL or empty when the candidate is not safe or host can not be resolved
     */
    public static Optional<URL> toSafeUrl(String candidate) {
        if (candidate == null) {
            return Optional.empty();
        }
        try {
            URL url = new URL(candidate);
            url.toURI();
            String protocol = url.getProtocol();
            if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
                return Optional.empty();
            }
            String host = url.getHost();
            if (host == null || host.isEmpty() || url.getUserInfo() != null) {
                return Optional.empty();
            }
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isDisallowedAddress(address)) {
                    return Optional.empty();
                }
            }
            return Optional.of(url);
        } catch (MalformedURLException
                | URISyntaxException
                | UnknownHostException
                | SecurityException e) {
            return Optional.empty();
        }
    }

    private static boolean isDisallowedAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet6Address) {
            // unique local addresses fc00::/7
            return (bytes[0] & 0xfe) == 0xfc;
        }
        // shared address space 100.64.0.0/10 (includes some cloud metadata endpoints)
        return (bytes[0] & 0xff) == 100 && (bytes[1] & 0xc0) == 0x40;
    }
}
