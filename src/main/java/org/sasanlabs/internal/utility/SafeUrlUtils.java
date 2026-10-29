package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility to validate user supplied URLs before the server makes an outbound request to them (SSRF
 * protection). Only http/https URLs whose host resolves exclusively to publicly routable addresses
 * are accepted. Loopback, link-local (cloud metadata), site-local/private, multicast and
 * unspecified addresses are rejected. The check fails closed: unresolvable hosts are rejected.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public final class SafeUrlUtils {

    private static final Logger LOGGER = LogManager.getLogger(SafeUrlUtils.class);

    private SafeUrlUtils() {}

    /**
     * @param rawUrl untrusted url
     * @return the parsed {@link URL} if it is safe to request, otherwise empty.
     */
    public static Optional<URL> toSafeUrl(String rawUrl) {
        if (rawUrl == null) {
            return Optional.empty();
        }
        try {
            URI uri = new URI(rawUrl.trim());
            String scheme = uri.getScheme();
            if (scheme == null
                    || !("http".equals(scheme.toLowerCase(Locale.ROOT))
                            || "https".equals(scheme.toLowerCase(Locale.ROOT)))) {
                return Optional.empty();
            }
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
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
                | IllegalArgumentException e) {
            LOGGER.error("Provided URL is not valid or not allowed", e);
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
            // 0.0.0.0/8 and 100.64.0.0/10 (carrier grade NAT)
            return first == 0 || (first == 100 && second >= 64 && second <= 127);
        }
        // fc00::/7 (unique local addresses)
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }
}
