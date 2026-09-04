package org.sasanlabs.internal.utility;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/** Validates that pathnames built from external input stay inside a base directory (CWE-22). */
public final class PathContainmentValidator {

    private PathContainmentValidator() {}

    /** Returns the candidate resolved inside the base directory, or empty when it escapes it. */
    public static Optional<Path> resolveWithin(Path baseDirectory, String candidate) {
        if (baseDirectory == null || candidate == null || candidate.isEmpty()) {
            return Optional.empty();
        }
        Path resolvedPath;
        try {
            resolvedPath = baseDirectory.resolve(candidate);
        } catch (InvalidPathException invalidCandidate) {
            // A candidate which is not even a valid path name, for example one with a NUL byte.
            return Optional.empty();
        }
        // An absolute candidate, and a "../" sequence which climbs out of the base directory, are
        // both rejected here so that the caller can only ever act on a contained path.
        if (!isWithin(baseDirectory, resolvedPath)) {
            return Optional.empty();
        }
        return Optional.of(resolvedPath.normalize());
    }

    /** Returns true only when the candidate is the base directory itself or an entry inside it. */
    public static boolean isWithin(Path baseDirectory, Path candidate) {
        if (baseDirectory == null || candidate == null) {
            return false;
        }
        Path canonicalBase = canonicalize(baseDirectory);
        return canonicalize(baseDirectory.resolve(candidate)).startsWith(canonicalBase);
    }

    /** Resolves a configured location, anchoring a relative one to the working directory. */
    public static Optional<Path> resolveConfiguredLocation(String location) {
        if (location == null || location.trim().isEmpty()) {
            return Optional.empty();
        }
        Path configuredPath;
        try {
            configuredPath = Paths.get(location);
        } catch (InvalidPathException invalidLocation) {
            return Optional.empty();
        }
        // An absolute location is a deliberate deployment choice, a relative one, like the
        // "benchmarks" default of benchmark.output.dir, may not climb out of the working directory.
        if (configuredPath.isAbsolute()) {
            return Optional.of(configuredPath.normalize());
        }
        return resolveWithin(workingDirectory(), location);
    }

    /** Returns the working directory of the application, the anchor of relative locations. */
    public static Path workingDirectory() {
        return Paths.get("").toAbsolutePath().normalize();
    }

    // Canonicalises a path so that two path names addressing the same entry compare equal.
    // Symbolic links are resolved for the part of the path which already exists, hence a link
    // inside the base directory cannot be used to reach a target outside of it. The remaining
    // names of a path which is about to be created are appended as they are.
    private static Path canonicalize(Path path) {
        Path absolutePath = path.toAbsolutePath().normalize();
        Path existingAncestor = absolutePath;
        int missingNames = 0;
        while (existingAncestor != null && !Files.exists(existingAncestor)) {
            existingAncestor = existingAncestor.getParent();
            missingNames++;
        }
        if (existingAncestor == null) {
            return absolutePath;
        }
        try {
            Path realAncestor = existingAncestor.toRealPath();
            if (missingNames == 0) {
                return realAncestor;
            }
            int nameCount = absolutePath.getNameCount();
            return realAncestor.resolve(absolutePath.subpath(nameCount - missingNames, nameCount));
        } catch (IOException notResolvable) {
            // Falls back on the normalised form when the real path cannot be read.
            return absolutePath;
        }
    }
}
