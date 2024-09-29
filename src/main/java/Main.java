import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.InflaterInputStream;
import java.util.zip.DeflaterOutputStream;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {
    // SHA-1 hash calculation
    public static String sha1Hex(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] sha1Bytes = md.digest(input);

            StringBuilder hexString = new StringBuilder();
            for (byte b : sha1Bytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not found", e);
        }
    }

    // cat-file command handler
    public static void catFileHandler(String hash) throws IOException {
        String hashOfDir = hash.substring(0, 2);
        String hashOfFilename = hash.substring(2);
        File fileDestination = new File(".git/objects/" + hashOfDir + "/" + hashOfFilename);

        try (InflaterInputStream inflaterStream = new InflaterInputStream(new FileInputStream(fileDestination));
             BufferedReader reader = new BufferedReader(new InputStreamReader(inflaterStream))) {

            StringBuilder content = new StringBuilder();
            String line;
            boolean firstLine = true;
            while ((line = reader.readLine()) != null) {
                if (firstLine) {
                    // Skip the header in the first line
                    int nullIndex = line.indexOf('\0');
                    if (nullIndex != -1) {
                        line = line.substring(nullIndex + 1);
                    }
                    firstLine = false;
                }
                content.append(line).append("\n");
            }

            System.out.print(content);
        } catch (IOException e) {
            throw new IOException("Error reading object file: " + hash, e);
        }
    }

    // Convert SHA-1 hash to file path
    private static String shaToPath(String sha) {
        return String.format(".git/objects/%s/%s", sha.substring(0, 2), sha.substring(2));
    }

    // hash-object command handler
    public static void createBlobObject(String[] args) throws IOException {
        boolean write = false;
        String fileName = null;

        for (String arg : args) {
            if (arg.equals("-w")) {
                write = true;
            } else if (!arg.equals("hash-object")) {
                fileName = arg;
            }
        }

        if (fileName == null) {
            throw new IllegalArgumentException("No file name provided");
        }

        try {
            byte[] fileContents = Files.readAllBytes(Paths.get(fileName));
            String header = "blob " + fileContents.length + "\0";
            byte[] headerBytes = header.getBytes(StandardCharsets.UTF_8);

            byte[] fullContent = new byte[headerBytes.length + fileContents.length];
            System.arraycopy(headerBytes, 0, fullContent, 0, headerBytes.length);
            System.arraycopy(fileContents, 0, fullContent, headerBytes.length, fileContents.length);

            String sha1Hash = sha1Hex(fullContent);
            System.out.println(sha1Hash);

            if (write) {
                String blobPath = shaToPath(sha1Hash);
                File blobFile = new File(blobPath);
                blobFile.getParentFile().mkdirs();
                try (DeflaterOutputStream out = new DeflaterOutputStream(new FileOutputStream(blobFile))) {
                    out.write(fullContent);
                }
            }
        } catch (IOException e) {
            throw new IOException("Error processing file: " + fileName, e);
        }
    }

    // init command handler
    public static void initRepository() throws IOException {
        File root = new File(".git");
        new File(root, "objects").mkdirs();
        new File(root, "refs").mkdirs();
        File head = new File(root, "HEAD");

        try {
            head.createNewFile();
            Files.write(head.toPath(), "ref: refs/heads/main\n".getBytes(StandardCharsets.UTF_8));
            System.out.println("Initialized git directory");
        } catch (IOException e) {
            throw new IOException("Error initializing git repository", e);
        }
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
                default:
                    System.out.println("Unknown command: " + command);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}