#include <fcntl.h> // for open flags
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // for mode constants
#include <unistd.h>   // for close()

// read_file:
// Opens (or creates) the file specified by 'filename' for reading,
// and returns its entire contents as a null-terminated string.
// On error, returns NULL. Caller must free the returned string.
char *read_file(const char *filename) {
  // Open (or create) file with read+write access.
  int fd =
      open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    perror("open");
    return NULL;
  }

  // Convert file descriptor to FILE* for convenient I/O.
  FILE *fp = fdopen(fd, "r+");
  if (!fp) {
    perror("fdopen");
    close(fd);
    return NULL;
  }

  // Determine file size
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(fp);
    return NULL;
  }
  long filesize = ftell(fp);
  if (filesize < 0) {
    perror("ftell");
    fclose(fp);
    return NULL;
  }
  rewind(fp);

  // Allocate memory for contents plus a null terminator.
  char *buffer = malloc(filesize + 1);
  if (!buffer) {
    perror("malloc");
    fclose(fp);
    return NULL;
  }

  // Read the entire file.
  size_t bytesRead = fread(buffer, 1, filesize, fp);
  if (ferror(fp)) {
    perror("fread");
    free(buffer);
    fclose(fp);
    return NULL;
  }
  buffer[bytesRead] = '\0'; // Null-terminate the string.

  fclose(fp); // Closes the stream and underlying file descriptor.
  return buffer;
}

// write_file:
// Opens (or creates) the file specified by 'filename' for writing (truncating
// existing data), writes the string 'content' to it, and returns 0 on success
// or -1 on error.
int write_file(const char *filename, const char *content) {
  // Open (or create) file with write-only access and truncate existing content.
  int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    perror("open");
    return -1;
  }

  // Convert file descriptor to FILE* stream for writing.
  FILE *fp = fdopen(fd, "w");
  if (!fp) {
    perror("fdopen");
    close(fd);
    return -1;
  }

  size_t contentLen = strlen(content);
  size_t bytesWritten = fwrite(content, 1, contentLen, fp);
  if (bytesWritten != contentLen) {
    perror("fwrite");
    fclose(fp);
    return -1;
  }

  fflush(fp);
  fclose(fp);
  return 0;
}

#ifdef TEST_FILE_FUNCTIONS

int main(void) {
  const char *filename = "example.txt";
  const char *testContent = "Hello, world!\nThis is a test file.";

  // Write content to the file.
  if (write_file(filename, testContent) != 0) {
    fprintf(stderr, "Error writing to file.\n");
    return EXIT_FAILURE;
  }

  // Read the file back.
  char *contents = read_file(filename);
  if (!contents) {
    fprintf(stderr, "Error reading from file.\n");
    return EXIT_FAILURE;
  }

  printf("File contents:\n%s\n", contents);
  free(contents);
  return EXIT_SUCCESS;
}
#endif
