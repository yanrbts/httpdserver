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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <microhttpd.h>

#define PORT 8080
#define UPLOAD_DIR "uploads"

int file_handler(void *cls, struct MHD_Connection *connection,
                 const char *url, const char *method,
                 const char *version, const char *upload_data,
                 size_t *upload_data_size, void **ptr) {
    if (strcmp(method, "POST") == 0) {
        static FILE *fp = NULL;
        printf("METHOD : %s\n", method);
        printf("URL : %s\n", url);

        if (*upload_data_size > 0) {
            if (!fp) {
                char filename[256];
                snprintf(filename, sizeof(filename), "%s/%lld", UPLOAD_DIR, (long long)time(NULL));
                fp = fopen(filename, "wb");
                if (!fp) {
                    return MHD_NO;
                }
            }

            fwrite(upload_data, 1, *upload_data_size, fp);
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            if (fp) {
                fclose(fp);
                fp = NULL;
            }
            // printf("Received file\n");
            return MHD_YES;
        }
    }

    return MHD_NO;
}

int main() {
    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                               &file_handler, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("Server started on port %d\n", PORT);
    getchar();

    MHD_stop_daemon(daemon);
    return 0;
}

