package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class PathContainmentValidatorTest {

    private static final String NAME_WITH_NUL_BYTE = "outsideFile" + (char) 0;

    @TempDir Path baseDir;

    private static Stream<String> escapingCandidates() {
        return Stream.of(
                // Relative traversal, also through a directory which does not exist yet
                "../outsideFile",
                "..",
                "nested/../../outsideFile",
                "nested/../..",
                // Absolute candidates ignore the base directory entirely
                "/etc/passwd",
                "/",
                // Not even a valid path name, because of the NUL byte
                NAME_WITH_NUL_BYTE);
    }

    @ParameterizedTest
    @MethodSource("escapingCandidates")
    @DisplayName("Should reject the candidates which do not stay inside the base directory")
    void shouldRejectCandidatesOutsideTheBaseDirectory(String candidate) {
        assertFalse(PathContainmentValidator.resolveWithin(baseDir, candidate).isPresent());
    }

    @ParameterizedTest
    @ValueSource(strings = {"insideFile", "nested/insideFile", "./insideFile"})
    @DisplayName("Should resolve the candidates which stay inside the base directory")
    void shouldResolveCandidatesInsideTheBaseDirectory(String candidate) {
        Optional<Path> resolved = PathContainmentValidator.resolveWithin(baseDir, candidate);
        assertTrue(resolved.isPresent());
        assertTrue(resolved.get().startsWith(baseDir));
    }

    @Test
    @DisplayName("Should treat the base directory itself as contained")
    void shouldTreatTheBaseDirectoryAsContained() {
        assertTrue(PathContainmentValidator.isWithin(baseDir, baseDir));
    }

    @Test
    @DisplayName("Should reject a symbolic link whose target is outside of the base directory")
    void shouldRejectSymbolicLinkPointingOutsideTheBaseDirectory(@TempDir Path outsideDir)
            throws IOException {
        Path outsideFile = Files.createFile(outsideDir.resolve("outsideFile"));
        try {
            Files.createSymbolicLink(baseDir.resolve("link"), outsideFile);
        } catch (IOException | UnsupportedOperationException notSupported) {
            assumeTrue(false, "The filesystem does not support symbolic links");
            return;
        }

        assertFalse(PathContainmentValidator.resolveWithin(baseDir, "link").isPresent());
    }

    @Test
    @DisplayName("Should anchor a relative configured location to the working directory")
    void shouldAnchorARelativeConfiguredLocation() {
        Optional<Path> configuredLocation =
                PathContainmentValidator.resolveConfiguredLocation("benchmarks");

        Path expectedPath = PathContainmentValidator.workingDirectory().resolve("benchmarks");
        assertTrue(configuredLocation.isPresent());
        assertEquals(expectedPath, configuredLocation.get());
    }

    @Test
    @DisplayName("Should keep an absolute configured location as it is configured")
    void shouldKeepAnAbsoluteConfiguredLocation() {
        Optional<Path> configuredLocation =
                PathContainmentValidator.resolveConfiguredLocation(baseDir.toString());

        assertTrue(configuredLocation.isPresent());
        assertEquals(baseDir, configuredLocation.get());
    }

    @ParameterizedTest
    @ValueSource(strings = {"../escapedBenchmarks", "nested/../../escaped", "", "   "})
    @DisplayName("Should reject a blank or escaping configured location")
    void shouldRejectABlankOrEscapingConfiguredLocation(String location) {
        assertFalse(PathContainmentValidator.resolveConfiguredLocation(location).isPresent());
    }

    @Test
    @DisplayName("Should reject null arguments instead of failing")
    void shouldRejectNullArguments() {
        assertFalse(PathContainmentValidator.resolveWithin(null, "insideFile").isPresent());
        assertFalse(PathContainmentValidator.resolveWithin(baseDir, null).isPresent());
        assertFalse(PathContainmentValidator.resolveConfiguredLocation(null).isPresent());
        assertFalse(PathContainmentValidator.isWithin(null, baseDir));
        assertFalse(PathContainmentValidator.isWithin(baseDir, null));
    }
}
