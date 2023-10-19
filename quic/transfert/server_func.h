//
// Created by andrea on 22/09/23.
//

#ifndef SERVER_FUNC
#define SERVER_FUNC

#include <stdio.h>
#include <dirent.h>

#include "transfert_base.h"
#include "transfert_errors.h"
#include "messages.h"

char *parse_and_exec_list_msg(char *);

char *parse_get_or_put_msg(char *);

void write_response(uint8_t code, char *, char *);

int exec_get_request(char *);

char *exec_put_request(char *);

char *exec(transfert_msg *);

#endif //SERVER_FUNC
