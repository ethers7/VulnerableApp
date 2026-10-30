package org.sasanlabs.benchmark.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import org.sasanlabs.benchmark.model.BenchmarkResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Persists a {@link BenchmarkResult} to a JSON file under the configured benchmarks directory.
 * Filename is derived from the (sanitised) tool name; existing files are overwritten so callers
 * always see the latest run for a given tool.
 */
@Component
public class BenchmarkResultWriter {

    private final ObjectMapper objectMapper;
    private final String defaultBenchmarksDir;

    public BenchmarkResultWriter(
            ObjectMapper objectMapper,
            @Value("${benchmark.output.dir:benchmarks}") String defaultBenchmarksDir) {
        this.objectMapper = objectMapper;
        this.defaultBenchmarksDir = defaultBenchmarksDir;
    }

    public Path write(BenchmarkResult result) throws IOException {
        return write(result, "");
    }

    /**
     * Writes the result under the configured benchmarks directory. {@code subDirectory} is resolved
     * relative to that root and must stay inside it; absolute paths and {@code ..} escapes are
     * rejected with an {@link IllegalArgumentException}.
     */
    public Path write(BenchmarkResult result, String subDirectory) throws IOException {
        Path root = Paths.get(defaultBenchmarksDir).toAbsolutePath().normalize();
        Path dir = resolveConfined(root, subDirectory);
        Files.createDirectories(dir);
        // Re-verify containment after symlinks are resolved.
        if (!dir.toRealPath().startsWith(root.toRealPath())) {
            throw new IllegalArgumentException("Benchmark directory escapes the benchmarks root");
        }
        String fileName = sanitizeToolName(result.getTool()) + "-results.json";
        Path target = dir.resolve(fileName);
        Path temp = Files.createTempFile(dir, fileName + ".", ".tmp");
        try {
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(temp.toFile(), result);
            moveAtomicallyOrReplace(temp, target);
        } catch (IOException ioe) {
            Files.deleteIfExists(temp);
            throw ioe;
        }
        return target;
    }

    private static Path resolveConfined(Path root, String subDirectory) {
        if (subDirectory == null || subDirectory.isEmpty()) {
            return root;
        }
        try {
            Path candidate = root.resolve(subDirectory).normalize();
            if (!candidate.startsWith(root)) {
                throw new IllegalArgumentException(
                        "Benchmark directory escapes the benchmarks root");
            }
            return candidate;
        } catch (InvalidPathException e) {
            throw new IllegalArgumentException("Invalid benchmark directory", e);
        }
    }

    private static void moveAtomicallyOrReplace(Path source, Path target) throws IOException {
        try {
            Files.move(
                    source,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException notSupported) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static final int MAX_TOOL_LENGTH = 64;

    static String sanitizeToolName(String tool) {
        if (tool == null) {
            return "unknown";
        }
        String lowered = tool.trim().toLowerCase(Locale.ROOT);
        String cleaned = lowered.replaceAll("[^a-z0-9_-]", "");
        if (cleaned.isEmpty()) {
            return "unknown";
        }
        if (cleaned.length() > MAX_TOOL_LENGTH) {
            cleaned = cleaned.substring(0, MAX_TOOL_LENGTH);
        }
        return cleaned;
    }
}
