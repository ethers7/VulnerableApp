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
    private final String defaultBenchmarksDir;

    public BenchmarkResultWriter(
            ObjectMapper objectMapper,
            @Value("${benchmark.output.dir:benchmarks}") String defaultBenchmarksDir) {
        this.objectMapper = objectMapper;
        this.defaultBenchmarksDir = defaultBenchmarksDir;
    }

    public Path write(BenchmarkResult result) throws IOException {
        return write(result, defaultBenchmarksDir);
    }

    /** Writes the report into {@code benchmarksDir}, which the file name may not escape. */
    public Path write(BenchmarkResult result, String benchmarksDir) throws IOException {
        // The directory itself is deployment configuration (benchmark.output.dir), so absolute
        // locations stay supported. The report path derived from the tool name is canonicalised
        // and has to stay inside that directory, so a tool name can never steer the write out.
        Path dir = Paths.get(benchmarksDir).normalize();
        Files.createDirectories(dir);
        String fileName = sanitizeToolName(result.getTool()) + "-results.json";
        Path target = dir.resolve(fileName).normalize();
        if (!isContainedIn(target, dir)) {
            throw new IOException(
                    "Refusing to write the benchmark result to '"
                            + target
                            + "': it resolves outside of the configured directory '"
                            + dir
                            + "'.");
        }
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

    private static boolean isContainedIn(Path target, Path dir) {
        return target.toAbsolutePath().normalize().startsWith(dir.toAbsolutePath().normalize());
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
