#include "../include/context.h"

char *readFile(const char *filename) {
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

int writeFile(const char *filename, const char *content) {
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
