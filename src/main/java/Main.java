//import java.io.*;
//import java.nio.charset.StandardCharsets;
//import java.nio.file.*;
//import java.util.*;
//import java.util.zip.*;
//import java.security.*;
//
//public class Main {
//
//    // SHA-1 hash calculation
//    public static String sha1Hex(byte[] input) {
//        try {
//            MessageDigest md = MessageDigest.getInstance("SHA-1");
//            byte[] sha1Bytes = md.digest(input);
//
//            StringBuilder hexString = new StringBuilder();
//            for (byte b : sha1Bytes) {
//                hexString.append(String.format("%02x", b));
//            }
//            return hexString.toString();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException("SHA-1 algorithm not found", e);
//        }
//    }
//
//    // Read compressed object and return its content
//    private static byte[] readCompressedFile(String path) throws IOException {
//        try (InflaterInputStream inflaterStream = new InflaterInputStream(new FileInputStream(path))) {
//            return inflaterStream.readAllBytes();
//        }
//    }
//
//    // cat-file command handler
//    public static void catFileHandler(String hash) throws IOException {
//        String objectPath = shaToPath(hash);
//        byte[] content = readCompressedFile(objectPath);
//
//        int nullIndex = indexOfNullByte(content);
//        if (nullIndex != -1) {
//            content = Arrays.copyOfRange(content, nullIndex + 1, content.length);
//        }
//
//        System.out.print(new String(content, StandardCharsets.UTF_8));
//    }
//
//    // Convert SHA-1 hash to file path
//    private static String shaToPath(String sha) {
//        return String.format(".git/objects/%s/%s", sha.substring(0, 2), sha.substring(2));
//    }
//
//    // Create blob object and optionally write it to disk
//    public static String createBlobObject(String fileName, boolean write) throws IOException {
//        byte[] fileContents = Files.readAllBytes(Paths.get(fileName));
//        String header = "blob " + fileContents.length + "\0";
//        byte[] fullContent = concatenate(header.getBytes(StandardCharsets.UTF_8), fileContents);
//
//        String sha1Hash = sha1Hex(fullContent);
//
//        if (write) {
//            writeCompressedFile(shaToPath(sha1Hash), fullContent);
//        }
//        return sha1Hash;
//    }
//
//    // Initialize repository
//    public static void initRepository() throws IOException {
//        Path gitDir = Paths.get(".git");
//        Files.createDirectories(gitDir.resolve("objects"));
//        Files.createDirectories(gitDir.resolve("refs"));
//        Files.write(gitDir.resolve("HEAD"), "ref: refs/heads/main\n".getBytes(StandardCharsets.UTF_8));
//        System.out.println("Initialized git directory");
//    }
//
//    // ls-tree command handler
//    public static void lsTreeHandler(String[] args) throws IOException {
//        if (args.length < 3 || !args[1].equals("--name-only")) {
//            throw new IllegalArgumentException("Usage: java Main ls-tree --name-only <tree-ish>");
//        }
//
//        List<String> entries = readTreeObject(args[2]);
//        entries.stream().map(e -> e.split("\t")[1]).sorted().forEach(System.out::println);
//    }
//
//    // Read and parse a tree object
//    private static List<String> readTreeObject(String hash) throws IOException {
//        String objectPath = shaToPath(hash);
//        byte[] content = readCompressedFile(objectPath);
//        List<String> entries = new ArrayList<>();
//
//        try (DataInputStream dataIn = new DataInputStream(new ByteArrayInputStream(content))) {
//            String header = readNullTerminatedString(dataIn);
//            if (!header.startsWith("tree ")) throw new IOException("Invalid tree object header");
//
//            while (dataIn.available() > 0) {
//                String mode = readUntilSpace(dataIn);
//                String name = readNullTerminatedString(dataIn);
//                byte[] sha = new byte[20];
//                dataIn.readFully(sha);
//                entries.add(String.format("%s %s %s\t%s", mode, mode.startsWith("100") ? "blob" : "tree", bytesToHex(sha), name));
//            }
//        }
//        return entries;
//    }
//
//    // Write tree command handler
//    public static void writeTreeHandler() throws IOException {
//        String treeHash = writeTree(Paths.get("."));
//        System.out.print(treeHash);
//    }
//
//    // Recursive method to write tree objects
//    private static String writeTree(Path dir) throws IOException {
//        ByteArrayOutputStream treeContent = new ByteArrayOutputStream();
//        Files.list(dir).sorted().forEach(path -> {
//            try {
//                if (Files.isDirectory(path) && !dir.relativize(path).toString().equals(".git")) {
//                    String subTreeHash = writeTree(path);
//                    writeTreeEntry(treeContent, "40000", dir.relativize(path).toString(), subTreeHash);
//                } else {
//                    String blobHash = createBlobObject(path.toString(), true);
//                    String mode = Files.isExecutable(path) ? "100755" : "100644";
//                    writeTreeEntry(treeContent, mode, dir.relativize(path).toString(), blobHash);
//                }
//            } catch (IOException e) {
//                throw new UncheckedIOException(e);
//            }
//        });
//
//        byte[] content = treeContent.toByteArray();
//        String header = "tree " + content.length + "\0";
//        byte[] fullContent = concatenate(header.getBytes(StandardCharsets.UTF_8), content);
//        String treeHash = sha1Hex(fullContent);
//        writeCompressedFile(shaToPath(treeHash), fullContent);
//        return treeHash;
//    }
//
//    // Helper to write compressed file
//    private static void writeCompressedFile(String path, byte[] content) throws IOException {
//        File file = new File(path);
//        file.getParentFile().mkdirs();
//        try (DeflaterOutputStream out = new DeflaterOutputStream(new FileOutputStream(file))) {
//            out.write(content);
//        }
//    }
//
//    // Helper to write a tree entry
//    private static void writeTreeEntry(ByteArrayOutputStream out, String mode, String name, String hash) throws IOException {
//        out.write(String.format("%s %s\0", mode, name).getBytes(StandardCharsets.UTF_8));
//        out.write(hexToBytes(hash));
//    }
//
//    // Helper method to concatenate byte arrays
//    private static byte[] concatenate(byte[] a, byte[] b) {
//        byte[] result = new byte[a.length + b.length];
//        System.arraycopy(a, 0, result, 0, a.length);
//        System.arraycopy(b, 0, result, a.length, b.length);
//        return result;
//    }
//
//    // Helper to find the index of the null byte
//    private static int indexOfNullByte(byte[] array) {
//        for (int i = 0; i < array.length; i++) {
//            if (array[i] == 0) return i;
//        }
//        return -1;
//    }
//
//    // Helper to convert bytes to hex
//    private static String bytesToHex(byte[] bytes) {
//        StringBuilder sb = new StringBuilder();
//        for (byte b : bytes) {
//            sb.append(String.format("%02x", b));
//        }
//        return sb.toString();
//    }
//
//    // Helper to read until space
//    private static String readUntilSpace(DataInputStream in) throws IOException {
//        StringBuilder sb = new StringBuilder();
//        int ch;
//        while ((ch = in.read()) != ' ') {
//            sb.append((char) ch);
//        }
//        return sb.toString();
//    }
//
//    // Helper to read a null-terminated string
//    private static String readNullTerminatedString(DataInputStream in) throws IOException {
//        StringBuilder sb = new StringBuilder();
//        int ch;
//        while ((ch = in.read()) != 0) {
//            sb.append((char) ch);
//        }
//        return sb.toString();
//    }
//
//    // Convert hex string to byte array
//    private static byte[] hexToBytes(String hex) {
//        int len = hex.length();
//        byte[] data = new byte[len / 2];
//        for (int i = 0; i < len; i += 2) {
//            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
//                    + Character.digit(hex.charAt(i + 1), 16));
//        }
//        return data;
//    }
//
//    public static void main(String[] args) {
//        if (args.length == 0) {
//            System.out.println("Please provide a command");
//            return;
//        }
//
//        String command = args[0];
//        try {
//            switch (command) {
//                case "init":
//                    initRepository();
//                    break;
//                case "cat-file":
//                    if (args.length < 3 || !args[1].equals("-p")) {
//                        throw new IllegalArgumentException("Usage: java Main cat-file -p <object>");
//                    }
//                    catFileHandler(args[2]);
//                    break;
//                case "hash-object":
//                    boolean write = args.length > 2 && args[1].equals("-w");
//                    String fileName = write ? args[2] : args[1];
//                    System.out.println(createBlobObject(fileName, write));
//                    break;
//                case "ls-tree":
//                    lsTreeHandler(args);
//                    break;
//                case "write-tree":
//                    writeTreeHandler();
//                    break;
//                default:
//                    System.out.println("Unknown command: " + command);
//            }
//        } catch (Exception e) {
//            System.err.println("Error: " + e.getMessage());
//            e.printStackTrace();
//        }
//    }
//}




import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import java.security.*;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class Main {

    // SHA-1 hash calculation
    public static String sha1Hex(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] sha1Bytes = md.digest(input);

            StringBuilder hexString = new StringBuilder();
            for (byte b : sha1Bytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not found", e);
        }
    }

    // Read compressed object and return its content
    private static byte[] readCompressedFile(String path) throws IOException {
        try (InflaterInputStream inflaterStream = new InflaterInputStream(new FileInputStream(path))) {
            return inflaterStream.readAllBytes();
        }
    }

    // cat-file command handler
    public static void catFileHandler(String hash) throws IOException {
        String objectPath = shaToPath(hash);
        byte[] content = readCompressedFile(objectPath);

        int nullIndex = indexOfNullByte(content);
        if (nullIndex != -1) {
            content = Arrays.copyOfRange(content, nullIndex + 1, content.length);
        }

        System.out.print(new String(content, StandardCharsets.UTF_8));
    }

    // Convert SHA-1 hash to file path
    private static String shaToPath(String sha) {
        return String.format(".git/objects/%s/%s", sha.substring(0, 2), sha.substring(2));
    }

    // Create blob object and optionally write it to disk
    public static String createBlobObject(String fileName, boolean write) throws IOException {
        byte[] fileContents = Files.readAllBytes(Paths.get(fileName));
        String header = "blob " + fileContents.length + "\0";
        byte[] fullContent = concatenate(header.getBytes(StandardCharsets.UTF_8), fileContents);

        String sha1Hash = sha1Hex(fullContent);

        if (write) {
            writeCompressedFile(shaToPath(sha1Hash), fullContent);
        }
        return sha1Hash;
    }

    // Initialize repository
    public static void initRepository() throws IOException {
        Path gitDir = Paths.get(".git");
        Files.createDirectories(gitDir.resolve("objects"));
        Files.createDirectories(gitDir.resolve("refs"));
        Files.write(gitDir.resolve("HEAD"), "ref: refs/heads/main\n".getBytes(StandardCharsets.UTF_8));
        System.out.println("Initialized git directory");
    }

    // ls-tree command handler
    public static void lsTreeHandler(String[] args) throws IOException {
        if (args.length < 3 || !args[1].equals("--name-only")) {
            throw new IllegalArgumentException("Usage: java Main ls-tree --name-only <tree-ish>");
        }

        List<String> entries = readTreeObject(args[2]);
        entries.stream().map(e -> e.split("\t")[1]).sorted().forEach(System.out::println);
    }

    // Read and parse a tree object
    private static List<String> readTreeObject(String hash) throws IOException {
        String objectPath = shaToPath(hash);
        byte[] content = readCompressedFile(objectPath);
        List<String> entries = new ArrayList<>();

        try (DataInputStream dataIn = new DataInputStream(new ByteArrayInputStream(content))) {
            String header = readNullTerminatedString(dataIn);
            if (!header.startsWith("tree ")) throw new IOException("Invalid tree object header");

            while (dataIn.available() > 0) {
                String mode = readUntilSpace(dataIn);
                String name = readNullTerminatedString(dataIn);
                byte[] sha = new byte[20];
                dataIn.readFully(sha);
                entries.add(String.format("%s %s %s\t%s", mode, mode.startsWith("100") ? "blob" : "tree", bytesToHex(sha), name));
            }
        }
        return entries;
    }

    // Write tree command handler
    public static void writeTreeHandler() throws IOException {
        String treeHash = writeTree(Paths.get("."));
        System.out.print(treeHash);
    }

    // Recursive method to write tree objects
    private static String writeTree(Path dir) throws IOException {
        ByteArrayOutputStream treeContent = new ByteArrayOutputStream();
        Files.list(dir).sorted().forEach(path -> {
            try {
                if (Files.isDirectory(path) && !dir.relativize(path).toString().equals(".git")) {
                    String subTreeHash = writeTree(path);
                    writeTreeEntry(treeContent, "40000", dir.relativize(path).toString(), subTreeHash);
                } else {
                    String blobHash = createBlobObject(path.toString(), true);
                    String mode = Files.isExecutable(path) ? "100755" : "100644";
                    writeTreeEntry(treeContent, mode, dir.relativize(path).toString(), blobHash);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });

        byte[] content = treeContent.toByteArray();
        String header = "tree " + content.length + "\0";
        byte[] fullContent = concatenate(header.getBytes(StandardCharsets.UTF_8), content);
        String treeHash = sha1Hex(fullContent);
        writeCompressedFile(shaToPath(treeHash), fullContent);
        return treeHash;
    }

    // Commit tree handler (commit-tree)
    public static void commitTreeHandler(String treeSha, String parentSha, String message) throws IOException {
        // Hardcoded author/committer details
        String author = "John Doe <john.doe@example.com>";

        // Get current timestamp in the correct format
        String timestamp = Instant.now().getEpochSecond() + " +0000";

        // Build the commit object content
        StringBuilder commitContent = new StringBuilder();
        commitContent.append("tree ").append(treeSha).append("\n");
        if (parentSha != null && !parentSha.isEmpty()) {
            commitContent.append("parent ").append(parentSha).append("\n");
        }
        commitContent.append("author ").append(author).append(" ").append(timestamp).append("\n");
        commitContent.append("committer ").append(author).append(" ").append(timestamp).append("\n\n");
        commitContent.append(message).append("\n");

        // Prepend the header
        String commitString = commitContent.toString();
        String header = "commit " + commitString.length() + "\0";
        byte[] commitBytes = concatenate(header.getBytes(StandardCharsets.UTF_8), commitString.getBytes(StandardCharsets.UTF_8));

        // Calculate the SHA1 for the commit object
        String commitSha = sha1Hex(commitBytes);

        // Write the commit object to .git/objects
        writeCompressedFile(shaToPath(commitSha), commitBytes);

        // Output the commit SHA
        System.out.println(commitSha);
    }

    // Helper to write compressed file
    private static void writeCompressedFile(String path, byte[] content) throws IOException {
        File file = new File(path);
        file.getParentFile().mkdirs();
        try (DeflaterOutputStream out = new DeflaterOutputStream(new FileOutputStream(file))) {
            out.write(content);
        }
    }

    // Helper to write a tree entry
    private static void writeTreeEntry(ByteArrayOutputStream out, String mode, String name, String hash) throws IOException {
        out.write(String.format("%s %s\0", mode, name).getBytes(StandardCharsets.UTF_8));
        out.write(hexToBytes(hash));
    }

    // Helper method to concatenate byte arrays
    private static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    // Helper to find the index of the null byte
    private static int indexOfNullByte(byte[] array) {
        for (int i = 0; i < array.length; i++) {
            if (array[i] == 0) return i;
        }
        return -1;
    }

    // Helper to convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // Helper to convert hex string to bytes
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // Helper to read until space
    private static String readUntilSpace(DataInputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte b;
        while ((b = in.readByte()) != ' ') {
            buffer.write(b);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    // Helper to read null-terminated string
    private static String readNullTerminatedString(DataInputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte b;
        while ((b = in.readByte()) != 0) {
            buffer.write(b);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    // Main method
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.err.println("Usage: <command> [<args>]");
            return;
        }

        String command = args[0];
        switch (command) {
            case "init":
                initRepository();
                break;
            case "cat-file":
                catFileHandler(args[1]);
                break;
            case "ls-tree":
                lsTreeHandler(args);
                break;
            case "write-tree":
                writeTreeHandler();
                break;
            case "commit-tree":
                String treeSha = args[1];
                String parentSha = args[3]; // -p argument
                String message = args[5]; // -m argument
                commitTreeHandler(treeSha, parentSha, message);
                break;
            default:
                System.err.println("Unknown command: " + command);
        }
    }
}

