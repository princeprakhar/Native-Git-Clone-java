import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.InflaterInputStream;
import java.util.zip.DeflaterOutputStream;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {
    //sha1hex
    public static String sha1Hex(String input) {
        try {
            // Create MessageDigest instance for SHA-1
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            // Add input string's bytes to digest using UTF-8 encoding
            byte[] messageDigest = md.digest(input.getBytes(StandardCharsets.UTF_8));

            // Convert byte array into a hex representation
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            // Return the full hash as a hexadecimal string
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
//  cat-file
  public static  void catFileHandler(String args) throws IOException
  {
    String hashOfDirAndFilename = args;
    String hashOfDir = hashOfDirAndFilename.substring(0,2);
    String hashOfFilename = hashOfDirAndFilename.substring(2);
    final File fileDestination = new File(".git/objects/"+hashOfDir+"/"+hashOfFilename);
    try{
      String blobData = new BufferedReader(new InputStreamReader(new InflaterInputStream(new FileInputStream(fileDestination)))).readLine();
      String fileContent = blobData.substring(blobData.indexOf("\0")+1);

      System.out.print(fileContent);
    }catch (IOException e)
    {
      throw new RuntimeException(e);
    }
  }
  // string formaater for path
    private static String shaToPath(String path)
    {
        return String.format(".git/objects/%s/%s", path.substring(0, 2),
                path.substring(2));
    }

  // hash-ObjectHandler  || createBlobObject
  public static void createBlobObject(String []args)throws IOException
  {

      boolean write = false;
      String fileName = "";
      for(String arg : args){
          if(arg.equals("-w")){
              write = true;
              fileName = args[2];
          }else{
              fileName = args[2];
          }
      }
      try {
          long fileSize = Files.size(Paths.get(fileName));
          byte []fileContents = Files.readAllBytes(Paths.get(fileName));
          final String fileContentStringFormat = new String (fileContents);
//          header =   blob <size>\0<content>
//          content = fileContentStringFormat
//          combinedData in file = header + content;
          String header = "Blob" + fileSize +"\0";
          String combinedData = header + fileContentStringFormat;
          String SHA_1_hash = sha1Hex(combinedData);

          String blobPath = shaToPath(SHA_1_hash);
          File blobFile = new File(blobPath);
          blobFile.getParentFile().mkdirs();
          DeflaterOutputStream out =
                  new DeflaterOutputStream(new FileOutputStream(blobFile));
          out.write("blob".getBytes());
          out.write(" ".getBytes());
          out.write(String.valueOf(fileSize).getBytes());
          out.write(0);
          out.write(fileContents);
          out.close();
          System.out.println(SHA_1_hash);

      }catch (IOException e){
          throw new RuntimeException(e);
      }
  }
  public static void main(String[] args) throws IOException {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
//    System.out.println("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    //
     final String command = args[0];
    //
     switch (command) {
       case "init" -> {
         final File root = new File(".git");
         new File(root, "objects").mkdirs();
         new File(root, "refs").mkdirs();
         final File head = new File(root, "HEAD");

         try {
           head.createNewFile();
           Files.write(head.toPath(), "ref: refs/heads/main\n".getBytes());
           System.out.println("Initialized git directory");
         } catch (IOException e) {
           throw new RuntimeException(e);
         }
       }
       case "cat-file" ->{
         catFileHandler(args[2]);
       }
       case "hash-object"->{
         createBlobObject(args);
       }
       default -> System.out.println("Unknown command: " + command);
     }
  }
}
