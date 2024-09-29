import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.*;

public class Main {
    private static final String GIT_DIR = ".git";
    private static final String OBJECTS_DIR = GIT_DIR + "/objects";
    private static final String REFS_DIR = GIT_DIR + "/refs";

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Please provide a command");
            return;
        }

        try {
            executeCommand(args);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void executeCommand(String[] args) throws IOException {
        String command = args[0];
        switch (command) {
            case "init" -> initRepository();
            case "cat-file" -> catFile(args);
            case "hash-object" -> hashObject(args);
            case "ls-tree" -> lsTree(args);
            case "write-tree" -> writeTree();
            case "commit-tree" -> commitTree(args);
            case "clone" -> cloneRepository(args);
            default -> System.out.println("Unknown command: " + command);
        }
    }

    // Git command implementations

    private static void initRepository() throws IOException {
        Files.createDirectories(Paths.get(OBJECTS_DIR));
        Files.createDirectories(Paths.get(REFS_DIR));
        Files.write(Paths.get(GIT_DIR, "HEAD"), "ref: refs/heads/main\n".getBytes(StandardCharsets.UTF_8));
        System.out.println("Initialized git directory");
    }

    private static void catFile(String[] args) throws IOException {
        if (args.length < 3 || !args[1].equals("-p")) {
            throw new IllegalArgumentException("Usage: java GitImplementation cat-file -p <object>");
        }
        String hash = args[2];
        String content = readObject(hash);
        System.out.print(content);
    }

    private static void hashObject(String[] args) throws IOException {
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: java GitImplementation hash-object [-w] <file>");
        }
        boolean write = args[1].equals("-w");
        String fileName = write ? args[2] : args[1];
        String hash = createBlobObject(fileName, write);
        System.out.println(hash);
    }

    private static void lsTree(String[] args) throws IOException {
        if (args.length < 3) {
            throw new IllegalArgumentException("Usage: java GitImplementation ls-tree --name-only <tree-ish>");
        }
        boolean nameOnly = args[1].equals("--name-only");
        String treeIsh = args[2];
        List<String> entries = readTreeObject(treeIsh);
        printTreeEntries(entries, nameOnly);
    }


    private static void writeTree() throws IOException {
        String treeHash = writeTreeRecursive(Paths.get("."));
        System.out.print(treeHash);
    }

    private static void commitTree(String[] args) throws IOException {
        if (args.length < 6) {
            throw new IllegalArgumentException("Usage: java GitImplementation commit-tree <tree> -p <parent> -m <message>");
        }
        String treeHash = args[1];
        String parentHash = args[3];
        String message = args[5];
        String commitHash = createCommitObject(treeHash, parentHash, message);
        System.out.println(commitHash);
    }

    private static void cloneRepository(String[] args) throws IOException {
        if (args.length != 3) {
            throw new IllegalArgumentException("Usage: java GitImplementation clone <repository-url> <target-directory>");
        }
        String repoLink = args[1];
        String dirName = args[2];
        executeGitClone(repoLink, dirName);
    }

    // Helper methods

    private static String sha1Hex(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] sha1Bytes = md.digest(input);
            return bytesToHex(sha1Bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not found", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b & 0xff));
        }
        return hexString.toString();
    }

    private static String readObject(String hash) throws IOException {
        Path objectPath = Paths.get(shaToPath(hash));
        try (InputStream fileIn = Files.newInputStream(objectPath);
             InflaterInputStream inflater = new InflaterInputStream(fileIn);
             BufferedReader reader = new BufferedReader(new InputStreamReader(inflater))) {

            String header = reader.readLine();
            int nullIndex = header.indexOf('\0');
            if (nullIndex != -1) {
                header = header.substring(nullIndex + 1);
            }

            return header + reader.lines().collect(Collectors.joining("\n"));
        }
    }

    private static String createBlobObject(String fileName, boolean write) throws IOException {
        byte[] content = Files.readAllBytes(Paths.get(fileName));
        String header = "blob " + content.length + "\0";
        byte[] fullContent = concatenateArrays(header.getBytes(StandardCharsets.UTF_8), content);
        String sha1Hash = sha1Hex(fullContent);

        if (write) {
            writeObject(sha1Hash, fullContent);
        }

        return sha1Hash;
    }

    private static void writeObject(String hash, byte[] content) throws IOException {
        Path objectPath = Paths.get(shaToPath(hash));
        Files.createDirectories(objectPath.getParent());
        try (OutputStream fileOut = Files.newOutputStream(objectPath);
             DeflaterOutputStream deflater = new DeflaterOutputStream(fileOut)) {
            deflater.write(content);
        }
    }

    private static List<String> readTreeObject(String hash) throws IOException {
        String content = readObject(hash);
        return Arrays.stream(content.split("\n"))
                .filter(line -> !line.startsWith("tree "))
                .collect(Collectors.toList());
    }

    private static void printTreeEntries(List<String> entries, boolean nameOnly) {
        if (nameOnly) {
            entries.stream()
                    .map(entry -> entry.split("\\s+")[2]) // Extract the filename
                    .sorted()
                    .forEach(System.out::println);
        } else {
            entries.forEach(System.out::println);
        }
    }

    private static String writeTreeRecursive(Path dir) throws IOException {
        ByteArrayOutputStream treeContent = new ByteArrayOutputStream();
        Files.list(dir)
                .sorted()
                .forEach(path -> writeTreeEntry(treeContent, dir, path));

        byte[] content = treeContent.toByteArray();
        String header = "tree " + content.length + "\0";
        byte[] fullContent = concatenateArrays(header.getBytes(StandardCharsets.UTF_8), content);

        String treeHash = sha1Hex(fullContent);
        writeObject(treeHash, fullContent);

        return treeHash;
    }

    private static void writeTreeEntry(ByteArrayOutputStream out, Path dir, Path path) {
        try {
            String relativePath = dir.relativize(path).toString();
            if (Files.isDirectory(path) && !relativePath.equals(GIT_DIR)) {
                String subTreeHash = writeTreeRecursive(path);
                writeEntry(out, "40000", relativePath, subTreeHash);
            } else if (Files.isRegularFile(path)) {
                String blobHash = createBlobObject(path.toString(), true);
                String mode = Files.isExecutable(path) ? "100755" : "100644";
                writeEntry(out, mode, relativePath, blobHash);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void writeEntry(ByteArrayOutputStream out, String mode, String name, String hash) throws IOException {
        out.write(String.format("%s %s\0", mode, name).getBytes(StandardCharsets.UTF_8));
        out.write(hexToBytes(hash));
    }

    private static String createCommitObject(String treeHash, String parentHash, String message) throws IOException {
        String timestamp = Instant.now().toString();
        String author = "John Doe <john@example.com>";
        String committer = author;

        StringBuilder commitContent = new StringBuilder()
                .append("tree ").append(treeHash).append('\n')
                .append("parent ").append(parentHash).append('\n')
                .append("author ").append(author).append(' ').append(timestamp).append('\n')
                .append("committer ").append(committer).append(' ').append(timestamp).append('\n')
                .append('\n').append(message).append('\n');

        byte[] content = commitContent.toString().getBytes(StandardCharsets.UTF_8);
        String header = "commit " + content.length + "\0";
        byte[] fullContent = concatenateArrays(header.getBytes(StandardCharsets.UTF_8), content);

        String commitHash = sha1Hex(fullContent);
        writeObject(commitHash, fullContent);

        return commitHash;
    }

    private static void executeGitClone(String repoLink, String dirName) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder("git", "clone", repoLink, dirName);
        processBuilder.inheritIO();

        try {
            Process process = processBuilder.start();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("Failed to clone repository. Exit code: " + exitCode);
            }
            System.out.println("Repository cloned successfully into: " + dirName);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Cloning process was interrupted.", e);
        }
    }

    // Utility methods

    private static String shaToPath(String sha) {
        return String.format("%s/%s/%s", OBJECTS_DIR, sha.substring(0, 2), sha.substring(2));
    }

    private static byte[] concatenateArrays(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}