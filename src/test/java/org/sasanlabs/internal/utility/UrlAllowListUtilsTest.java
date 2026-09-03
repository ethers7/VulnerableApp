package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UrlAllowListUtilsTest {

    private static final String APPROVED_HOST = "gist.githubusercontent.com";

    private static final Set<String> ALLOWED_HOSTS = Set.of(APPROVED_HOST);

    private static Optional<URL> parse(String candidateUrl) {
        return UrlAllowListUtils.parseIfHostAllowed(candidateUrl, ALLOWED_HOSTS);
    }

    @Test
    @DisplayName("Should accept the URLs pointing to an approved host")
    void approvedHost_IsAccepted() {
        Optional<URL> url = parse("https://gist.githubusercontent.com/raw/gistId?param=value");

        assertTrue(url.isPresent());
        assertEquals("https", url.get().getProtocol());
        assertEquals(APPROVED_HOST, url.get().getHost());
        assertEquals("/raw/gistId?param=value", url.get().getFile());
    }

    @Test
    @DisplayName("Should compare the host of the provided URL ignoring the case")
    void approvedHostWithAnotherCase_IsAccepted() {
        Optional<URL> url = parse("HTTPS://GIST.GITHUBUSERCONTENT.COM/raw/gistId");

        assertTrue(url.isPresent());
        assertEquals("https", url.get().getProtocol());
        assertEquals(APPROVED_HOST, url.get().getHost());
    }

    @Test
    @DisplayName("Should reject the URLs pointing to a host which is not approved")
    void hostWhichIsNotApproved_IsRejected() {
        assertTrue(parse("https://evil.com/payload").isEmpty());
    }

    @Test
    @DisplayName("Should reject the URLs where the approved host is the user information")
    void approvedHostAsUserInformation_IsRejected() {
        assertTrue(parse("https://gist.githubusercontent.com@evil.com/payload").isEmpty());
    }

    @Test
    @DisplayName("Should reject the schemes which are neither http nor https")
    void schemeWhichIsNotHttpOrHttps_IsRejected() {
        assertTrue(parse("file:///etc/passwd").isEmpty());
    }

    @Test
    @DisplayName("Should reject the invalid and the null URLs")
    void invalidUrl_IsRejected() {
        assertTrue(parse("invalidUrl").isEmpty());
        assertTrue(parse(null).isEmpty());
    }

    @Test
    @DisplayName("Should reject every URL when the allow list is empty")
    void emptyAllowList_RejectsEveryUrl() {
        String candidateUrl = "https://gist.githubusercontent.com/raw/gistId";

        assertTrue(UrlAllowListUtils.parseIfHostAllowed(candidateUrl, Set.of()).isEmpty());
        assertTrue(UrlAllowListUtils.parseIfHostAllowed(candidateUrl, null).isEmpty());
    }

    @Test
    @DisplayName("Should reject the cloud metadata and the other internal addresses")
    void internalAddress_IsRejected() {
        String metadataIpv6Host = "[::ffff:169.254.169.254]";

        assertTrue(parseInternal("http://169.254.169.254/1.0", "169.254.169.254"));
        assertTrue(parseInternal("http://[::ffff:169.254.169.254]/1.0", metadataIpv6Host));
        assertTrue(parseInternal("http://127.0.0.1/admin", "127.0.0.1"));
        assertTrue(parseInternal("http://10.0.0.1/admin", "10.0.0.1"));
        assertTrue(parseInternal("http://localhost/admin", "localhost"));
    }

    /** Returns true when the URL is rejected even though its host is part of the allow list. */
    private static boolean parseInternal(String candidateUrl, String host) {
        return UrlAllowListUtils.parseIfHostAllowed(candidateUrl, Set.of(host)).isEmpty();
    }
}
