[![progress-banner](https://backend.codecrafters.io/progress/git/c3e76670-02e5-4b8a-a45f-ab4bfaf55816)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)



# Java Git Implementation

## Overview

This project is a basic implementation of Git in Java, providing core Git functionality without relying on the Git command-line tool. It's designed for educational purposes to understand the inner workings of Git, demonstrating how Git manages objects, creates commits, and handles basic version control operations.

## Project Goals

1. Implement core Git commands in Java
2. Provide a clear, readable codebase for learning about Git internals
3. Demonstrate low-level operations like object hashing, tree traversal, and commit creation

## Features

This implementation supports the following Git commands:

- `init`: Initialize a new Git repository
- `cat-file`: Display the contents of a Git object
- `hash-object`: Compute object ID and optionally create a blob from a file
- `ls-tree`: List the contents of a tree object
- `write-tree`: Create a tree object from the current index
- `commit-tree`: Create a new commit object
- `clone`: Clone a repository into a new directory

## Technical Details

### Object Storage

Git objects (blobs, trees, and commits) are stored in the `.git/objects` directory. Each object is compressed using zlib compression and named according to its SHA-1 hash.

### Object Types

1. **Blob**: Represents file contents
2. **Tree**: Represents directories and file names
3. **Commit**: Represents a specific point in the project's history

### Hashing

SHA-1 hashing is used to generate unique identifiers for Git objects. This project implements SHA-1 hashing using Java's `MessageDigest` class.

### File I/O

The project uses Java NIO (`java.nio.file`) for efficient file operations, providing better performance and more flexible file handling compared to the older `java.io` package.

## Prerequisites

- Java Development Kit (JDK) 14 or higher
- Java compiler (javac)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/princeprakhar/Native-Git-Clone-java.git
   ```
2. Navigate to the project directory:
   ```
   cd Native-Git-Clone-java
   ```
3. Compile the Java file:
   ```
   javac Main.java
   ```

## Usage

After compilation, you can run the program using the `java` command followed by `GitImplementation` and the Git command you want to execute. Here are some examples:

1. Initialize a new Git repository:
   ```
   java Main init
   ```

2. Compute the hash of a file and write it as a blob object:
   ```
   java Main hash-object -w <filename>
   ```

3. Display the contents of a Git object:
   ```
   java Main cat-file -p <object-hash>
   ```

4. List the contents of a tree object:
   ```
   java Main ls-tree --name-only <tree-hash>
   ```

5. Create a new commit:
   ```
   java Main commit-tree <tree-hash> -p <parent-commit-hash> -m "Commit message"
   ```

6. Clone a repository:
   ```
   java Main clone <repository-url> <target-directory>
   ```

## Implementation Details

### Command Execution

The `executeCommand` method in the `Main` class serves as the entry point for all Git commands. It uses a switch statement to delegate to the appropriate method based on the command.

### Object Reading and Writing

- `readObject`: Reads and decompresses a Git object from the object store.
- `writeObject`: Compresses and writes a Git object to the object store.

### Tree Handling

The `writeTreeRecursive` method recursively creates tree objects for directories, while `readTreeObject` parses the binary format of tree objects.

### Commit Creation

The `createCommitObject` method assembles commit data, including tree hash, parent commit, author information, and commit message.

## Limitations

This is a basic implementation and does not include all features of Git. Some limitations include:

- No support for branches or tags
- Limited error handling and edge case management
- No networking capabilities (except for the basic `clone` command)
- No index (staging area) management

It's meant for educational purposes and may not handle all complex scenarios that the official Git implementation does.

## Future Enhancements

Potential areas for improvement include:

1. Implementing branch and tag support
2. Adding index management for staging changes
3. Improving error handling and input validation
4. Implementing more Git commands (e.g., `merge`, `rebase`)
5. Adding support for config files and Git hooks

## Contributing

Contributions to improve the implementation or add new features are welcome. Please feel free to submit a pull request or open an issue for any bugs or feature requests.

To contribute:

1. Fork the repository
2. Create a new branch for your feature (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).

## Acknowledgments

This project was created as an educational exercise to understand the internal workings of Git. It's inspired by the Git version control system but is not affiliated with or endorsed by the official Git project.

Special thanks to:
- The Git community for creating and maintaining such a powerful version control system
- Contributors to various Git internals documentation and articles, which provided valuable insights into Git's inner workings

## Author
**[Prakhar Deep](https://github.com/princeprakhar)**  

## Contact

If you have any questions, feel free to reach out or open an issue in the GitHub repository.

Happy coding and Git exploring!
