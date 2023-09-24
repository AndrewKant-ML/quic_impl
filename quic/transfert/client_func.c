//
// Created by andrea on 12/09/23.
//

#include <unistd.h>
#include <string.h>
#include <malloc.h>

#include "messages.h"

/**
 * @brief Write a command transfert_msg into a file.
 *
 * Write a command transfert_msg into a file by using its
 * descriptor, using the format <br>
 *
 * <code> CMD &lt;SP&gt; [file_name] </code>
 *
 * @param fd the file descriptor
 * @param cmd the command to be written
 * @param file_name the optional file name, as command argument
 * @return the number of bytes written, excluding the terminating
 * null byte, or -1 on errors
 */
int enqueue_cmd_message(int fd, char cmd[], char *file_name) {
    return dprintf(fd, "%s %s", cmd, file_name);
}