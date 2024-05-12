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
#include <getopt.h>
#include <error.h>
#include <signal.h>
#include <microhttpd.h>
#include "log.h"

#define AUTHORS             "Written by Yan Ruibing."
#define PACKAGE_VERSION     "0.0.1"
#define PORT                8080
#define POSTBUFFERSIZE      4096
#define GET                 0
#define POST                1
#define MAXCLIENTS          5
#define DEFAULT_DIR         "kxykworks"
#define TIME_FORMAT         "%Y-%m-%d %H:%M:%S"

char *ascii_logo ="\n" 
"    __   ______    __  __ \n"     
"   / /__/ __/ /_  / /_/ /_____    | PID : %d\n"
"  / //_/ /_/ __ \\/ __/ __/ __ \\   | Port: %d\n"
" / ,< / __/ / / / /_/ /_/ /_/ /   | Author: yanruibing\n"
"/_/|_/_/ /_/ /_/\\__/\\__/ .___/    | Version: %s\n"
"                      /_/      \n\n";

// static unsigned int uploading_clients = 0;
static char homedir[512];
// static char *subdir = NULL;

struct connection_info_struct {
    int connectiontype;
    struct MHD_PostProcessor *postprocessor;
    FILE *fp;
    const char *answerstring;
    const char *url;
    int answercode;
};

struct server {
    char *logfile;  /*log file*/
    int port;       /* server port */
    int daemonize;  /* Whether to daemonize, 1 or 0*/
    char *subdir;   /* User working subdirectory */
    uint64_t uploading_clients_num; /*Number of clients being uploaded*/
};

struct server hserver;

const char *askpage = "<html><body>\n\
                       Upload a file, please!<br>\n\
                       There are %u clients uploading at the moment.<br>\n\
                       <form action=\"/filepost\" method=\"post\" enctype=\"multipart/form-data\">\n\
                       <input name=\"file\" type=\"file\">\n\
                       <input type=\"submit\" value=\" Send \"></form>\n\
                       </body></html>";

const char *busypage =
  "This server is busy, please try again later.";

const char *completepage =
  "The upload has been completed.";

const char *errorpage =
  "This doesn't seem to be right.";
const char *servererrorpage =
  "An internal server error has occured.";
const char *fileexistspage =
  "This file already exists.";

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

    snprintf(buffer, sizeof(buffer), "%s/%s%s", homedir, hserver.subdir, dir);
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
                    hserver.subdir,
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
            hserver.uploading_clients_num--;
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

        if (hserver.uploading_clients_num >= MAXCLIENTS)
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
            hserver.uploading_clients_num++;
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

        sprintf(buffer, askpage, hserver.uploading_clients_num);
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

static void notify_connection(void *cls,
                            struct MHD_Connection *connection,
                            void **socket_context,
                            enum MHD_ConnectionNotificationCode toe) 
{
    switch (toe) {
    case MHD_CONNECTION_NOTIFY_STARTED:
        log_info("new connection start");
        break;
    case MHD_CONNECTION_NOTIFY_CLOSED:
        log_info("connection closed");
        break;
    }
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

static void
inti_server() {
    hserver.daemonize = 0;
    hserver.logfile = NULL;
    hserver.port = PORT;
    hserver.subdir = DEFAULT_DIR;
    hserver.uploading_clients_num = 0;
}

static void
destroy_server() {
    if (hserver.logfile) free(hserver.logfile);
    if (hserver.subdir) free(hserver.subdir);
}

static void sigShutdownHandler(int sig) {
    char *msg;

    switch (sig) {
    case SIGINT:
        msg = "Received SIGINT scheduling shutdown...";
        break;
    case SIGTERM:
        msg = "Received SIGTERM scheduling shutdown...";
        break;
    default:
        msg = "Received shutdown signal, scheduling shutdown...";
    }
    printf("[*] %s\n", msg);
    exit(1);
}

void setupSignalHandlers(void) {
    struct sigaction act;
    
    /* When the SA_SIGINFO flag is set in sa_flags then sa_sigaction is used.
     * Otherwise, sa_handler is used. */
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;

    /* This is the termination signal sent by the kill(1) command by default.
     * Because it can be caught by applications, using SIGTERM gives programs
     * a chance to terminate gracefully by cleaning up before exiting */
    sigaction(SIGTERM, &act, NULL);
    /* This signal is generated by the terminal driver when we press the
     * interrupt key (often DELETE or Control-C). This signal is sent to all
     * processes in the foreground process group . This
     * signal is often used to terminate a runaway program, especially when it’s
     * generating a lot of unwanted output on the screen.*/
    sigaction(SIGINT, &act, NULL);

    return;
}

/* Return the UNIX time in microseconds */
static long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

static void usage() {
    printf ("\nUsage: [OPTION]... \n"
                "list file interface contents\n\n"
                "  -p,              Server port(The default is 8080).\n"
                "  -f,              Log file (If not set it will be displayed on the screen).\n"
                "  -s,              User working subdirectory.\n"
                "  -b,              Whether to daemonize.\n"
                "      --help       display this help and exit.\n"
                "      --version    output version information and exit.\n\n"
                "Examples:\n"
                "  httpdserver -p 8080\n\n");
}

static struct option const long_options[] = {
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0}
};

int main(int argc, char **argv) {
    pid_t pid;
    struct MHD_Daemon *daemon;
    int ret = -1;
    int opt = 0;
    int option_index = 0;
    FILE *logfp = NULL;

    
    /* First initialize the server, and then decide to modify 
     * the parameters from the input parameters to prevent 
     * violation of initialization.*/
    inti_server();

    if (argv[argc-1] == NULL || argv[argc-1][0] == '\0') {
        fprintf(stderr, "Invalid command line arguments\n");
        goto err;
    }

    optind = 0;
    while (1) {
        opt = getopt_long(argc, argv, "p:f:s:bhv", long_options, &option_index);

        if (opt == -1) break;

        switch (opt) {
        case 'p':
            if (optarg)
                hserver.port = atoi(optarg);
            break;
        case 'f':
            if (optarg)
                hserver.logfile = strdup(optarg);
            break;
        case 's':
            hserver.subdir = strdup(optarg);
            break;
        case 'b':
            hserver.daemonize = 1;
            break;
        case 'v':
            printf ("%s (%s) %s\n", argv[0], PACKAGE_VERSION, AUTHORS);
            goto out;
        case 'h':
            usage();
            goto out;
        default:
            goto err;
        }
    }

    if (optind < argc) {
        error(0, 0, "missing operand");
        goto err;
    }

    setlocale(LC_COLLATE, "");

    /* When a terminal disconnect (hangup) occurs, 
     * this signal is sent to the controlling process of the termin*/
    signal(SIGHUP, SIG_IGN);
    /* If we write to a pipeline but the reader has terminated, SIGPIPE is
     * generated. This signal is also generated when a process writes to 
     * a socket of type SOCK_STREAM that is no longer connected.*/
    signal(SIGPIPE, SIG_IGN);
    setupSignalHandlers();
    
    pid = getpid();
    printf(ascii_logo, pid, hserver.port, PACKAGE_VERSION);

    get_home_dir();

    if (hserver.logfile) {
        logfp = fopen(hserver.logfile, "a+");
        if (logfp) {
            log_add_fp(logfp, LOG_INFO | LOG_TRACE);
            log_set_quiet(1);
        } else {
            log_error("Failed to open or create the %s log file.", hserver.logfile);
        }
    }

    log_info("kfhttp server run (pid=%d, port=%d).", pid, hserver.port);
    // daemonize();
    struct MHD_OptionItem ops[] = {
        { MHD_OPTION_CONNECTION_LIMIT, 100, NULL },
        { MHD_OPTION_CONNECTION_TIMEOUT, 10, NULL },
        { MHD_OPTION_NOTIFY_COMPLETED, (intptr_t)request_completed, NULL },
        { MHD_OPTION_NOTIFY_CONNECTION, (intptr_t)notify_connection, NULL },
        { MHD_OPTION_END, 0, NULL }
    };

    daemon = MHD_start_daemon(MHD_USE_EPOLL_INTERNALLY | MHD_USE_DEBUG, 
                          hserver.port, NULL, NULL,
                          &answer_to_connection, NULL,
                          MHD_OPTION_ARRAY, ops, MHD_OPTION_END);

    if (daemon == NULL) {
        log_error("kfhttp server run failed.");
        return 1;
    }

    getchar();
    if (logfp) fclose(logfp);
    MHD_stop_daemon(daemon);
    destroy_server();

    return 0;
err:
    error(0, 0, "Try user --help for more information.");
out:
    return ret;
}