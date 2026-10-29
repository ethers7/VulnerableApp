package org.sasanlabs.internal.utility;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility for validating user supplied URLs before the server connects to them. Only http/https
 * URLs having a host which resolves exclusively to public addresses are accepted.
 */
public final class SafeUrlUtils {

    private static final transient Logger LOGGER = LogManager.getLogger(SafeUrlUtils.class);

    private static final String HTTP = "http";
    private static final String HTTPS = "https";
    private static final String AWS_METADATA_IP = "169.254.169.254";

    private SafeUrlUtils() {}

    /**
     * @param url user supplied url
     * @return the parsed URL when it uses http/https, has a host, has no user info and the host
     *     resolves only to public (non loopback, link-local, private, multicast, metadata)
     *     addresses. Empty otherwise, including when the host can not be resolved.
     */
    public static Optional<URL> toSafeUrl(String url) {
        if (url == null) {
            return Optional.empty();
        }
        URL parsed;
        try {
            parsed = new URL(url);
        } catch (MalformedURLException e) {
            LOGGER.error("Provided URL is not valid", e);
            return Optional.empty();
        }
        String protocol = parsed.getProtocol().toLowerCase(Locale.ROOT);
        if (!HTTP.equals(protocol) && !HTTPS.equals(protocol)) {
            return Optional.empty();
        }
        String host = parsed.getHost();
        if (host == null || host.isEmpty() || parsed.getUserInfo() != null) {
            return Optional.empty();
        }
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            if (addresses.length == 0) {
                return Optional.empty();
            }
            for (InetAddress address : addresses) {
                if (isRestricted(address)) {
                    return Optional.empty();
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.error("Unable to resolve host of the provided URL", e);
            return Optional.empty();
        }
        return Optional.of(parsed);
    }

    private static boolean isRestricted(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()
                || AWS_METADATA_IP.equals(address.getHostAddress())) {
            return true;
        }
        byte[] raw = address.getAddress();
        if (address instanceof Inet6Address) {
            // Unique local addresses fc00::/7
            return (raw[0] & 0xfe) == 0xfc;
        }
        // Carrier-grade NAT 100.64.0.0/10
        return (raw[0] & 0xff) == 100 && (raw[1] & 0xc0) == 0x40;
    }
}
