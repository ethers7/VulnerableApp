package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class OutboundUrlValidatorTest {

    private static Stream<String> allowedUrls() {
        return Stream.of(
                "https://github.com/SasanLabs/VulnerableApp",
                "https://gist.githubusercontent.com/raw/someGistId",
                "https://raw.githubusercontent.com/SasanLabs/VulnerableApp/main/README.md",
                "https://GitHub.com/SasanLabs",
                "https://github.com./SasanLabs",
                "http://github.com/SasanLabs");
    }

    @ParameterizedTest
    @MethodSource("allowedUrls")
    @DisplayName("Should allow the destinations which are part of the allowlist")
    void shouldAllowAllowlistedDestinations(String url) {
        assertTrue(OutboundUrlValidator.parseAllowedUrl(url).isPresent());
    }

    private static Stream<String> blockedUrls() {
        return Stream.of(
                // Cloud metadata endpoints, also through their IPv4 mapped IPv6 representation
                "http://169.254.169.254/latest/meta-data",
                "http://[::ffff:169.254.169.254]/latest/meta-data",
                "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data",
                "http://169.254.170.2/",
                // Loopback, wildcard, private and IPv6 unique local addresses
                "http://127.0.0.1:8080/",
                "http://127.1.2.3/",
                "http://[::1]/",
                "http://0.0.0.0/",
                "http://10.1.2.3/",
                "http://172.16.0.1/",
                "http://192.168.0.1/",
                "http://[fd00::1]/",
                // Schemes which must never be used for an outbound request
                "file:///etc/passwd",
                "ftp://github.com/",
                // Hosts which are not part of the allowlist, including bypass attempts
                "https://untrusted.example.com/",
                "https://github.com.untrusted.example.com/",
                "https://untrusted.example.com/?redirect=https://github.com/",
                "https://user@github.com:pass@untrusted.example.com/",
                "invalidUrl");
    }

    @ParameterizedTest
    @MethodSource("blockedUrls")
    @DisplayName("Should block internal, metadata and non allowlisted destinations")
    void shouldBlockInternalAndNonAllowlistedDestinations(String url) {
        assertFalse(OutboundUrlValidator.parseAllowedUrl(url).isPresent());
    }

    @Test
    @DisplayName("Should block a null URL instead of failing")
    void shouldBlockNullUrl() {
        assertFalse(OutboundUrlValidator.parseAllowedUrl(null).isPresent());
    }

    @Test
    @DisplayName("Should return the parsed URL of an allowlisted destination")
    void shouldReturnParsedUrlOfAllowlistedDestination() {
        String url = "https://github.com/SasanLabs/VulnerableApp";
        Optional<URL> allowedUrl = OutboundUrlValidator.parseAllowedUrl(url);
        assertTrue(allowedUrl.isPresent());
        assertEquals("github.com", allowedUrl.get().getHost());
        assertEquals(url, allowedUrl.get().toString());
    }
}
