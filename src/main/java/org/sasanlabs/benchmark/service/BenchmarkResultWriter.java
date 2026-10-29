package org.sasanlabs.benchmark.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
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
    private final Path baseDir;

    public BenchmarkResultWriter(
            ObjectMapper objectMapper,
            @Value("${benchmark.output.dir:benchmarks}") String defaultBenchmarksDir) {
        this.objectMapper = objectMapper;
        this.baseDir = Paths.get(defaultBenchmarksDir).toAbsolutePath().normalize();
    }

    public Path write(BenchmarkResult result) throws IOException {
        return writeInto(result, baseDir);
    }

    /**
     * Writes into {@code benchmarksDir}, which must be the configured benchmarks directory or a
     * location beneath it (relative values are resolved against it). Anything that would escape it
     * is rejected.
     */
    public Path write(BenchmarkResult result, String benchmarksDir) throws IOException {
        Path dir = baseDir.resolve(benchmarksDir).normalize();
        if (!dir.startsWith(baseDir)) {
            throw new IllegalArgumentException(
                    "Benchmarks directory must be inside the configured benchmark.output.dir");
        }
        return writeInto(result, dir);
    }

    private Path writeInto(BenchmarkResult result, Path dir) throws IOException {
        Files.createDirectories(dir);
        // Re-check after creation so symlinks cannot redirect the output outside the base
        if (!dir.toRealPath().startsWith(baseDir.toRealPath())) {
            throw new IllegalArgumentException(
                    "Benchmarks directory must be inside the configured benchmark.output.dir");
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
