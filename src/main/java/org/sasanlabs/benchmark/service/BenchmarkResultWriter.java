package org.sasanlabs.benchmark.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Optional;
import org.sasanlabs.benchmark.model.BenchmarkResult;
import org.sasanlabs.internal.utility.PathContainmentValidator;
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

    public Path write(BenchmarkResult result, String benchmarksDir) throws IOException {
        // A relative output directory, like the "benchmarks" default, is anchored to the working
        // directory and may not climb out of it, so the configured value cannot turn into a write
        // to an arbitrary location on disk.
        Optional<Path> configuredOutputDir =
                PathContainmentValidator.resolveConfiguredLocation(benchmarksDir);
        if (configuredOutputDir.isEmpty()) {
            throw new IOException(
                    "The benchmark output directory must stay inside the working directory: "
                            + benchmarksDir);
        }
        Path dir = configuredOutputDir.get();
        Files.createDirectories(dir);
        String fileName = sanitizeToolName(result.getTool()) + "-results.json";
        // The file name is derived from the tool name of the request, hence the result file is
        // required to be an entry of the output directory itself.
        Optional<Path> resultFile = PathContainmentValidator.resolveWithin(dir, fileName);
        if (resultFile.isEmpty()) {
            throw new IOException("Refusing to write the benchmark result outside of " + dir);
        }
        Path target = resultFile.get();
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
