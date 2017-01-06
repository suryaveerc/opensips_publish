/*
 * RepositoryHandler.c
 *
 *  Created on: Jul 21, 2015
 *      Author: suryaveer
 */

#include <stdio.h>
#include "RepositoryAccessClient.h"
#include "../../dprint.h"

//TODO: Lot of duplicate code. Improve by moving into generic code to perform.

int curl_head(const char *url) {
    if (!url) {
        LM_ERR("URL not provided. Returning with error.\n");
        return -1;
    }
    CURLcode res;
    int http_code = 0;

    /* set URL */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    res = curl_easy_perform(curl);

    //LM_DBG("curl_easy_perform %s\n", curl_easy_strerror(res));
    if (res != CURLE_OK) {
        LM_ERR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    //LM_DBG("HTTP return CODE %d\n", http_code);

    curl_easy_reset(curl);
    return http_code;

}

int curl_delete(const char *url) {
    if (!url) {
        LM_ERR("URL not provided. Returning with error.\n");
        return -1;
    }

    CURLcode res;
    int http_code = 0;

    /* set URL */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    res = curl_easy_perform(curl);

    
     if (res != CURLE_OK) {
         LM_ERR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
     }
     curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
     //LM_DBG("HTTP return CODE %d\n", http_code);
     curl_easy_reset(curl);
    return 200;

}

int curl_put(const char *url, char *putdata) {
    if (!url) {
        LM_ERR("URL not provided. Returning with error.\n");
        return -1;
    }

    CURLcode res;

    int http_code = 0;

    /* set URL */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, putdata);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        LM_ERR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    //LM_DBG("HTTP return CODE %d\n", http_code);

    curl_easy_reset(curl);

    return http_code;

}
int curl_post(const char *url, char *postdata) {
    if (!url) {
        LM_ERR("URL not provided. Returning with error.\n");
        return -1;
    }

    CURLcode res;
    int http_code = 0;
//    LM_DBG("URL: %s \n", url);
    //LM_DBG("\n\n\nDATA: %s \n", postdata);
    /* set URL */
 /*   FILE *file_debug=NULL;
    file_debug = fopen("/home/file.txt", "a+");   //open the specified file on local host
    curl_easy_setopt(curl, CURLOPT_STDERR,file_debug);
*/
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, postdata);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcrp/0.1");
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        LM_ERR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    //fclose(file_debug);
   // LM_DBG("HTTP return CODE %d\n", http_code);

    curl_easy_reset(curl);
    return http_code;
}

int curl_get(const char *url, struct json_response **result) {
    if (!url) {
        LM_ERR("URL not provided. Returning with error.\n");
        return -1;
    }
    CURLcode res;

    int http_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (result != NULL) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void **) result);
    }
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        LM_ERR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_reset(curl);
        return -1;
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
     //   LM_DBG("HTTP return CODE %d\n", http_code);

        curl_easy_reset(curl);

        return http_code;
    }
}

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void **userp) {
    size_t realsize = size * nmemb;
    struct json_response *cf = (struct json_response *) (*userp);

    cf->payload = realloc(cf->payload, cf->size + realsize + 1);
    if (cf->payload == NULL) {
        /* out of memory! */
        LM_ERR("not enough memory (realloc returned NULL)\n");
        return -1;
    }

    memcpy(&(cf->payload[cf->size]), contents, realsize);
    cf->size += realsize;
    cf->payload[cf->size] = 0;
    //LM_DBG("In callback: %s\n", cf->payload);
    return realsize;
}

void curl_create_connections(const char *url) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_perform(curl);
    curl_easy_reset(curl);
}
