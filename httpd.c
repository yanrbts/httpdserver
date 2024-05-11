/*
 * Copyright 2024-2024 yanruibinghxu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>
#include <errno.h>
#include <fcntl.h>
#include <microhttpd.h>
#include "log.h"

#define PORT 8080
#define UPLOAD_DIR "uploads"
#define POSTBUFFERSIZE 4096
#define GET             0
#define POST            1
#define MAXCLIENTS      5
#define DEFAULT_DIR     "kxykworks"
#define TIME_FORMAT     "%Y-%m-%d %H:%M:%S"

char *ascii_logo ="\n" 
"    __   ______    __  __ \n"     
"   / /__/ __/ /_  / /_/ /_____    | PID : %d\n"
"  / //_/ /_/ __ \\/ __/ __/ __ \\   | Port: %d\n"
" / ,< / __/ / / / /_/ /_/ /_/ /   | Author: yanruibing\n"
"/_/|_/_/ /_/ /_/\\__/\\__/ .___/    | Version: 1.0.0\n"
"                      /_/      \n\n";

static unsigned int uploading_clients = 0;
static char homedir[512];
static char *subdir = NULL;

struct connection_info_struct {
    int connectiontype;
    struct MHD_PostProcessor *postprocessor;
    FILE *fp;
    const char *answerstring;
    const char *url;
    int answercode;
};

const char *askpage = "<html><body>\n\
                       Upload a file, please!<br>\n\
                       There are %u clients uploading at the moment.<br>\n\
                       <form action=\"/filepost\" method=\"post\" enctype=\"multipart/form-data\">\n\
                       <input name=\"file\" type=\"file\">\n\
                       <input type=\"submit\" value=\" Send \"></form>\n\
                       </body></html>";

const char *busypage =
  "<html><body>This server is busy, please try again later.</body></html>";

const char *completepage =
  "<html><body>The upload has been completed.</body></html>";

const char *errorpage =
  "<html><body>This doesn't seem to be right.</body></html>";
const char *servererrorpage =
  "<html><body>An internal server error has occured.</body></html>";
const char *fileexistspage =
  "<html><body>This file already exists.</body></html>";

static void
get_home_dir() {
    uid_t uid;
    struct passwd *pw_entry;

    uid = getuid();
    pw_entry = getpwuid(uid);
    if (pw_entry != NULL) {
        strncpy(homedir, pw_entry->pw_dir, sizeof(homedir)-1);
        homedir[sizeof(homedir)-1] = '\0';
    } else {
        log_error("getpwuid() error %s", strerror(errno));
        exit(0);
    }
}

static int 
check_dir_vaild(const char *dir) {
    char buffer[PATH_MAX] = {0};

    snprintf(buffer, sizeof(buffer), "%s/%s%s", homedir, subdir ? subdir : DEFAULT_DIR, dir);
    if (access(buffer, F_OK) != -1) {
        return 1;
    }
    return 0;
}

static int
send_page(struct MHD_Connection *connection, const char *page, int status_code)
{
    int ret;
    struct MHD_Response *response;

    response = MHD_create_response_from_buffer(strlen(page), 
                                                (void *)page,
				                                MHD_RESPMEM_PERSISTENT);
    if (!response) return MHD_NO;

    ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response (response);

    return ret;
}

static int
iterate_post (void *cls, enum MHD_ValueKind kind, const char *key,
              const char *filename, const char *content_type,
              const char *transfer_encoding, const char *data, uint64_t off,
              size_t size)
{
    FILE *fp;
    char filepath[1024];
    struct connection_info_struct *con_info = cls;

    con_info->answerstring = servererrorpage;
    con_info->answercode = MHD_HTTP_INTERNAL_SERVER_ERROR;

    if (strcmp(key, "file") != 0)
        return MHD_NO;
    
    if (!con_info->fp) {
        snprintf(filepath, sizeof(filepath), "%s/%s%s/%s", 
                    homedir, 
                    subdir ? subdir : DEFAULT_DIR,
                    con_info->url, 
                    filename);
        // log_info("(%s) %s", con_info->url+1, filepath);

        if ((fp = fopen(filepath, "rb")) != NULL) {
            fclose(fp);
            con_info->answerstring = fileexistspage;
            con_info->answercode = MHD_HTTP_FORBIDDEN;
            log_error("kfhttp server Forbidden 403.");
            return MHD_NO;
        }
        if (check_dir_vaild(con_info->url)) {
            con_info->fp = fopen(filepath, "ab");
        } else {
            log_warn("(%s) %s", con_info->url+1, "User directory does not exist.");
        }

        if (!con_info->fp) return MHD_NO;
    }

    if (size) {
        if (fwrite(data, size, sizeof(char), con_info->fp) == 0) {
            log_error("(%s) %sfile save failed.", con_info->url+1, filepath);
            return MHD_NO;
        }
    }
    con_info->answerstring = completepage;
    con_info->answercode = MHD_HTTP_OK;
    log_info("(%s) %s upload successful.", con_info->url+1, filepath);
    return MHD_YES;
}

static void
request_completed (void *cls, struct MHD_Connection *connection,
                   void **con_cls, enum MHD_RequestTerminationCode toe)
{
    struct connection_info_struct *con_info = *con_cls;

    if (con_info == NULL)
        return;
    
    if (con_info->connectiontype == POST) {
        if (con_info->postprocessor != NULL) {
            MHD_destroy_post_processor (con_info->postprocessor);
            uploading_clients--;
            log_info("close client.");
        }

        if (con_info->fp)
            fclose(con_info->fp);
    }
    free(con_info);
    *con_cls = NULL;
    log_trace("(%s) Request completed.", con_info->url+1);
}

static int
answer_to_connection (void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method,
                      const char *version, const char *upload_data,
                      size_t *upload_data_size, void **con_cls)
{
    if (*con_cls == NULL) {
        struct connection_info_struct *con_info;

        if (uploading_clients >= MAXCLIENTS)
            return send_page(connection, busypage, MHD_HTTP_SERVICE_UNAVAILABLE);
        
        con_info = malloc(sizeof(struct connection_info_struct));
        if (con_info == NULL)
            return MHD_NO;
        con_info->fp = NULL;
        con_info->url = url;

        if (strcmp(method, "POST") == 0) {
            con_info->postprocessor = MHD_create_post_processor(connection, 
                                                                POSTBUFFERSIZE,
                                                                iterate_post, 
                                                                (void *)con_info);
            if (con_info->postprocessor == NULL) {
                free(con_info);
                return MHD_NO;
            }
            uploading_clients++;
            con_info->connectiontype = POST;
            con_info->answercode = MHD_HTTP_OK;
            con_info->answerstring = completepage;
        } else {
            con_info->connectiontype = GET;
        }
        *con_cls = (void *)con_info;

        return MHD_YES;
    }

    if (strcmp(method, "GET") == 0) {
        char buffer[1024];

        sprintf (buffer, askpage, uploading_clients);
        return send_page(connection, buffer, MHD_HTTP_OK);
    }

    if (strcmp(method, "POST") == 0) {
        struct connection_info_struct *con_info = *con_cls;

        if (*upload_data_size != 0) {
            MHD_post_process(con_info->postprocessor, 
                            upload_data,
                            *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            return send_page(connection, 
                            con_info->answerstring,
                            con_info->answercode);
        }
    }
    return send_page(connection, errorpage, MHD_HTTP_BAD_REQUEST);
}

void daemonize(void) {
    int fd;

    if (fork() != 0) exit(0); /* parent exits */
    setsid(); /* create a new session */

    /* Every output goes to /dev/null. If Redis is daemonized but
     * the 'logfile' is set to 'stdout' in the configuration file
     * it will not log at all. */
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

int main(int argc, char **argv) {
    pid_t pid;
    struct MHD_Daemon *daemon;

    setlocale(LC_COLLATE, "");
    
    pid = getpid();
    printf(ascii_logo, pid, PORT);
    get_home_dir();

    log_info("kfhttp server run (pid=%d, port=%d).", pid, PORT);
    daemonize();
    daemon = MHD_start_daemon(MHD_USE_EPOLL_INTERNALLY | MHD_USE_DEBUG, 
                                PORT, NULL, NULL,
                                &answer_to_connection, NULL,
                                MHD_OPTION_NOTIFY_COMPLETED, 
                                request_completed,
                                NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        log_error("kfhttp server run failed.");
        return 1;
    }

    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}