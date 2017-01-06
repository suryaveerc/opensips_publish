/*
 * RepositoryAccessClient.h
 *
 *  Created on: Jul 21, 2015
 *      Author: suryaveer
 */
#include <curl/curl.h>

extern CURL *curl;
extern struct curl_slist *headers;
struct json_response {
    char *payload;
    size_t size;
};

int curl_post(const char* url, char *postdata);
int curl_get(const char* url, struct json_response **result);
int curl_delete(const char* url);
int curl_head(const char* url);
int curl_put(const char* url, char* putdata);
int curl_patch(const char* url, char* putdata);
static size_t write_callback(void *contents, size_t size, size_t nmemb, void **userp);
void curl_create_connections(const char *url);
int curl_read_responses();
void curl_delete_handles();
