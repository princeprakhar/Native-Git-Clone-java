import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.InflaterInputStream;
import java.util.zip.DeflaterOutputStream;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Main {
    // ... [Previous methods remain unchanged]

    // New method to handle ls-tree command
    public static void lsTreeHandler(String[] args) throws IOException {
        if (args.length < 3) {
            throw new IllegalArgumentException("Usage: java Main ls-tree --name-only <tree-ish>");
        }

        boolean nameOnly = args[1].equals("--name-only");
        String treeIsh = args[2];

        List<String> entries = readTreeObject(treeIsh);

        for (String entry : entries) {
            if (nameOnly) {
                System.out.println(entry.split("\t")[1]);
            } else {
                System.out.println(entry);
            }
        }
    }

    // Helper method to read and parse a tree object
    private static List<String> readTreeObject(String hash) throws IOException {
        String objectPath = shaToPath(hash);
        List<String> entries = new ArrayList<>();

        try (InflaterInputStream inflaterStream = new InflaterInputStream(new FileInputStream(objectPath));
             DataInputStream dataIn = new DataInputStream(inflaterStream)) {

            // Read and verify the header
            String header = readNullTerminatedString(dataIn);
            if (!header.startsWith("tree ")) {
                throw new IOException("Invalid tree object header");
            }

            // Read entries
            while (dataIn.available() > 0) {
                String mode = readUntilSpace(dataIn);
                String name = readNullTerminatedString(dataIn);
                byte[] sha = new byte[20];
                dataIn.readFully(sha);
                String shaHex = bytesToHex(sha);

                entries.add(String.format("%s %s %s\t%s", mode,
                        mode.startsWith("100") ? "blob" : "tree", shaHex, name));
            }
        }

        Collections.sort(entries);
        return entries;
    }

    // Helper method to read a null-terminated string
    private static String readNullTerminatedString(DataInputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int ch;
        while ((ch = in.read()) != 0) {
            sb.append((char) ch);
        }
        return sb.toString();
    }

    // Helper method to read until a space character
    private static String readUntilSpace(DataInputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int ch;
        while ((ch = in.read()) != ' ') {
            sb.append((char) ch);
        }
        return sb.toString();
    }

    // Helper method to convert bytes to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Please provide a command");
            return;
        }

        String command = args[0];

        try {
            switch (command) {
                case "init":
                    initRepository();
                    break;
                case "cat-file":
                    if (args.length < 3 || !args[1].equals("-p")) {
                        throw new IllegalArgumentException("Usage: java Main cat-file -p <object>");
                    }
                    catFileHandler(args[2]);
                    break;
                case "hash-object":
                    if (args.length < 2) {
                        throw new IllegalArgumentException("Usage: java Main hash-object [-w] <file>");
                    }
                    createBlobObject(args);
                    break;
                case "ls-tree":
                    lsTreeHandler(args);
                    break;
                default:
                    System.out.println("Unknown command: " + command);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}