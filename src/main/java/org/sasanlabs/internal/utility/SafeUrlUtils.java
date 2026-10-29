package org.sasanlabs.internal.utility;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Utility to validate user supplied URLs before the server connects to them (SSRF protection).
 *
 * <p>Only http/https URLs having a host, without user info and resolving exclusively to public
 * addresses are accepted.
 */
public final class SafeUrlUtils {

    private static final Set<String> ALLOWED_PROTOCOLS =
            new HashSet<>(Arrays.asList("http", "https"));

    private static final Set<String> METADATA_ADDRESSES =
            new HashSet<>(
                    Arrays.asList(
                            "169.254.169.254",
                            "169.254.170.2",
                            "fd00:ec2:0:0:0:0:0:254",
                            "0:0:0:0:0:0:a9fe:a9fe"));

    private SafeUrlUtils() {}

    /**
     * Validates the provided URL.
     *
     * @param candidate untrusted URL
     * @return the parsed URL if and only if it is safe to connect to, otherwise empty
     */
    public static Optional<URL> toSafeUrl(String candidate) {
        if (candidate == null) {
            return Optional.empty();
        }
        try {
            URL parsed = new URL(candidate);
            parsed.toURI();
            String protocol = parsed.getProtocol();
            String host = parsed.getHost();
            if (protocol == null
                    || !ALLOWED_PROTOCOLS.contains(protocol.toLowerCase())
                    || host == null
                    || host.isEmpty()
                    || parsed.getUserInfo() != null) {
                return Optional.empty();
            }
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (!isPublicAddress(address)) {
                    return Optional.empty();
                }
            }
            return Optional.of(parsed);
        } catch (MalformedURLException
                | java.net.URISyntaxException
                | UnknownHostException
                | SecurityException e) {
            return Optional.empty();
        }
    }

    private static boolean isPublicAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()
                || METADATA_ADDRESSES.contains(address.getHostAddress())) {
            return false;
        }
        byte[] raw = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = raw[0] & 0xFF;
            int second = raw[1] & 0xFF;
            // 0.0.0.0/8 and carrier-grade NAT 100.64.0.0/10
            return first != 0 && !(first == 100 && second >= 64 && second <= 127);
        }
        if (address instanceof Inet6Address) {
            // unique local addresses fc00::/7
            return (raw[0] & 0xFE) != 0xFC;
        }
        return true;
    }
}
