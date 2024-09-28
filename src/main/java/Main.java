import java.io.*;
import java.nio.file.Files;
import java.util.zip.InflaterInputStream;
import java.util.zip.DeflaterOutputStream;

public class Main {
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
       default -> System.out.println("Unknown command: " + command);
     }
  }
}
