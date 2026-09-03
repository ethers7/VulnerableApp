package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility to validate the user provided URLs before the application uses them to perform server
 * side requests, hence protecting against Server Side Request Forgery (CWE-918).
 *
 * <p>A URL is accepted only if it uses the http/https scheme and its host is part of the provided
 * allow list of approved hosts. Loopback, private, link local (like the cloud metadata services)
 * and the other internal addresses are rejected.
 *
 * <p>The returned URL is built using the approved scheme and host, hence the user provided data can
 * only influence the path and the query parameters of the request.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public final class UrlAllowListUtils {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlAllowListUtils.class);

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private static final Set<String> INTERNAL_HOST_NAMES =
            Set.of("localhost", "metadata", "metadata.google.internal", "instance-data");

    private static final Pattern IPV4_LITERAL_PATTERN =
            Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){3}$");

    private UrlAllowListUtils() {}

    /**
     * Validates the provided URL against the provided allow list of approved hosts.
     *
     * @param candidateUrl the user provided URL, can be null.
     * @param allowedHosts the hosts which the application is allowed to connect to.
     * @return the URL built using an approved scheme and host, empty if the provided URL is not
     *     valid or is not pointing to an approved host.
     */
    public static Optional<URL> parseIfHostAllowed(String candidateUrl, Set<String> allowedHosts) {
        if (candidateUrl == null || allowedHosts == null || allowedHosts.isEmpty()) {
            return Optional.empty();
        }
        URI candidateUri;
        try {
            candidateUri = new URI(candidateUrl);
        } catch (URISyntaxException e) {
            LOGGER.error("Provided URL is not valid, hence rejecting it.", e);
            return Optional.empty();
        }
        String scheme = findIgnoringCase(ALLOWED_SCHEMES, candidateUri.getScheme());
        String host = findIgnoringCase(allowedHosts, candidateUri.getHost());
        if (scheme == null || host == null || isInternalAddress(candidateUri.getHost())) {
            LOGGER.error("Provided URL is not pointing to an approved host, rejecting it.");
            return Optional.empty();
        }
        // Scheme and host are taken from the allow list and not from the user provided data,
        // hence the user can only influence the path and the query parameters of the request.
        int port = candidateUri.getPort();
        String file = buildFilePart(candidateUri);
        try {
            return Optional.of(new URL(scheme, host, port, file));
        } catch (MalformedURLException e) {
            LOGGER.error("Not able to build the approved URL, hence rejecting it.", e);
            return Optional.empty();
        }
    }

    private static String buildFilePart(URI uri) {
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        if (uri.getRawQuery() == null) {
            return path;
        }
        return path + "?" + uri.getRawQuery();
    }

    private static String findIgnoringCase(Set<String> approvedValues, String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        for (String approvedValue : approvedValues) {
            if (approvedValue.equalsIgnoreCase(value)) {
                return approvedValue;
            }
        }
        return null;
    }

    private static boolean isInternalAddress(String host) {
        String hostName = host.toLowerCase(Locale.ROOT);
        if (hostName.startsWith("[") && hostName.endsWith("]")) {
            hostName = hostName.substring(1, hostName.length() - 1);
        }
        if (INTERNAL_HOST_NAMES.contains(hostName)) {
            return true;
        }
        boolean ipLiteral =
                IPV4_LITERAL_PATTERN.matcher(hostName).matches() || hostName.indexOf(':') >= 0;
        if (!ipLiteral) {
            // Name resolution is not performed here because the host is already validated
            // against the allow list of approved hosts.
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(hostName);
            return address.isAnyLocalAddress()
                    || address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress()
                    || address.isMulticastAddress();
        } catch (UnknownHostException e) {
            LOGGER.error("Not able to parse the host of the provided URL, rejecting it.", e);
            return true;
        }
    }
}
