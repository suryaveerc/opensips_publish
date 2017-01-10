/*
 * RepositoryHandler.c
 *
 *  Created on: Jul 21, 2015
 *      Author: suryaveer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Common.h"
#include "Util.h"
#include "RepositoryAccessClient.h"
#include "RepositoryHandler.h"

int update_request = 0;
int delete_request = 0;

int updateResource(const db_key_t *_qk, const db_val_t *_qv, const db_key_t *_uk, const db_val_t *_uv, const int _qn,
                   const int _un, const char *_rt, char *_u1, char *_u2)
{

    // LM_DBG("*********UpdateResource***********\n");
    if ((!_qk) || (!_qv) || (!_qn) || (!_uk) || (!_uv) || (!_un) || (!_rt)) {
        if (!_qk)
            LM_ERR("Required parameters _qk not received.\n");
        else if (!_qv)
            LM_ERR("Required parameters _qv not received.\n");
        else if (!_qn)
            LM_ERR("Required parameters _qn not received.\n");
        else if (!_uk)
            LM_ERR("Required parameters _uk not received.\n");
        else if (!_uv)
            LM_ERR("Required parameters _uv not received.\n");
        else if (!_un)
            LM_ERR("Required parameters _un not received.\n");
        else
            LM_ERR("Required parameters _rt not received.\n");
        return -1;
    }
    char *jsonBuffer =  malloc(JSON_BUF_LEN);
    if (jsonBuffer == NULL) {
        LM_ERR("No more pkg memory left");
        return -1;
    }
    int status = 0;
    status = db_print_single_json(jsonBuffer, _uk, _uv, _un);

    if (!status) {
        LM_ERR("Unable to process the requested input");
        free(jsonBuffer);
        return -1;
    }

    /*char *url = (char *) pkg_malloc(MAX_URL_LEN);
     if (url == NULL) {
         LM_ERR("No more pkg memory left");
         return -1;
     }*/
    char url[MAX_URL_LEN];
    //update_request=1;
    if (create_url(_qk, _qv, _qn, url, _rt, _u1, _u2, NULL, 0) < 0) {
        LM_ERR("Unable to create complete URL\n");
       // pkg_free(url);
        return -1;
    }
    //update_request=0;
//	LM_DBG("The URL is %s \n", url);

    /* struct timeval start, end;
     long secs_used, msec_used;
     gettimeofday(&start, NULL);*/

    status = curl_put(url, jsonBuffer);

    /*gettimeofday(&end, NULL);
    secs_used = (end.tv_sec - start.tv_sec); //avoid overflow by subtracting first
    msec_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
    LM_WARN(" curl_put took %ld millisecond\n", msec_used / 1000);
*/
    /* if (status)
         LM_DBG("PUT to %s successful with status %d. \n", url, status);
     else
         LM_DBG("PUT to %s failed. \n", url);*/

  //  pkg_free(url);
    free(jsonBuffer);
    //LM_DBG("Returning.");
    return ((status == 200 || status == 204) ? 1 : 0);
}

int
insertResource(const db_key_t *_k, const db_val_t *_v, const int _n, const char *_rt, const char *_r, char *jsonBuffer)
{

    if ((!_k) || (!_v) || (!_n) || (!_rt))
        return -1;
    //moved to presentity.c/subscribe.cfor micro service architecture
//    char *jsonBuffer = (char *) pkg_malloc(JSON_BUF_LEN);
    /*if (jsonBuffer == NULL) {
        LM_ERR("No more pkg memory left");
        return -1;
    }*/
    int status = 0;
    status = db_print_single_json(jsonBuffer, _k, _v, _n);


    if (!status) {
        LM_ERR("Unable to process the requested input");
        free(jsonBuffer);
        return -1;
    }

    /*char *url = (char *) pkg_malloc(MAX_URL_LEN);
    if (url == NULL) {
        LM_ERR("No more pkg memory left");
        return -1;
    }*/
    char url[MAX_URL_LEN];
    memcpy(url, ROOT_URL, strlen(ROOT_URL) + 1);
    memcpy(url + strlen(ROOT_URL), _rt, strlen(_rt) + 1);
//	LM_DBG("The URL is %s: \n", url);
    if (!_r)/* Presence of _r represent the request for PUT request*/
    {
        if (micro_srv_arch)
            status = curl_post(url, jsonBuffer + 2);
        else
            status = curl_post(url, jsonBuffer);
    }
    else
    {
        if (micro_srv_arch)
            status = curl_post(url, jsonBuffer + 2);
        else
            status = curl_post(url, jsonBuffer);
    }
    //pkg_free(url);
    //moved to presentity.c for micro service architecture
    //pkg_free(jsonBuffer);
    return ((status == 201 || status == 200) ? 1 : 0);
}

int
getResource(const db_key_t *_k, const db_val_t *_v, const int _n, db_res_t **_r, const char *_rt, char *_u1, char *_u2,
            const db_key_t *_kr, const int _nr)
{

    //LM_DBG("ENTER INTO getResource\n");

    if (!_rt) {
        LM_ERR("Required values not provided.\n");
        return -1;
    }

    /*char *url = (char *) pkg_malloc(MAX_URL_LEN);
    if (url == NULL) {
        LM_ERR("No more pkg memory left");
        return -1;
    }*/
    char url[MAX_URL_LEN];

    if (create_url(_k, _v, _n, url, _rt, _u1, _u2, _kr, _nr) < 0) {
        LM_ERR("Failed to process request. URL creation failed.\n");
       // pkg_free(url);
        return -1;
    }
    // LM_DBG("!!!!!%s", url);
    int status = 0;
    struct json_response re;
    struct json_response *jresponse = &re;
    jresponse->payload = (char *) malloc(1);
    if (!jresponse->payload)
        return -1;
    jresponse->size = 0;


/*
	struct timeval start, end;
	long secs_used, msec_used;
	gettimeofday(&start, NULL);

*/

    status = curl_get(url, &jresponse);

/*

	gettimeofday(&end, NULL);
	secs_used = (end.tv_sec - start.tv_sec); //avoid overflow by subtracting first
	msec_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
	LM_WARN(" curl_get took %ld millisecond\n", msec_used / 1000);
*/


    //LM_DBG("GEt from %s returned with status %d. \n", url, status);
//	LM_DBG("GETRESOURCE: result after GET: %s\n", jresponse->payload);
    //parse result only if status is 200 OK.

    int return_status = 0;
    if (status == 200) //returned results
    {
        return_status = parse_json_to_result(jresponse->payload, _r);
    }
    else if (status != 404) // no results, return_status = 0
    {
        return_status = -1;
    }
    //else some error occured at server side

    /*else if (status == -1)
     {
     LM_DBG("GET from %s failed with status %d. \n", url, status);
     return status;
     }
     else
     LM_DBG("GET from %s returned with status %d. \n", url, status);
     */
    //pkg_free(url);
    if (jresponse->payload)
        free(jresponse->payload);
    //LM_DBG("************parse_status: %d\n", return_status);
    return return_status;
}

int checkResource(const db_key_t *_k, const db_val_t *_v, const int _n, const char *_rt, char *_p)
{
    if (!_k || !_v || !_n || !_p || !_rt) {
        LM_ERR("Required values not provided.\n");
        return -1;
    }
    /*char *url = (char *) pkg_malloc(MAX_URL_LEN);
    if (url == NULL) {
        LM_ERR("No more pkg memory left");
        return -1;
    }*/
    char url[MAX_URL_LEN];
    if (create_url(_k, _v, _n, url, _rt, _p, NULL, NULL, 0) < 0) {
        LM_ERR("Failed to process request. URL creation failed. Resource is: %s\n", _p);
       // pkg_free(url);
        return -1;
    }
    int status = 0;
/*
	struct timeval start, end;
	long secs_used, msec_used;
	gettimeofday(&start, NULL);
*/
    status = curl_head(url);
/*
	gettimeofday(&end, NULL);
	secs_used = (end.tv_sec - start.tv_sec); //avoid overflow by subtracting first
	msec_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
	LM_WARN(" curl_head took %ld millisecond\n", msec_used / 1000);
*/
    if (status)
        LM_DBG("HEAD for %s successful with status %d. \n", url, status);
    else
        LM_DBG("HEAD for %s failed with status %d. \n", url, status);
    //pkg_free(url);
    return (status != 200 ? 0 : 1);
}

int deleteResource(const db_key_t *_k, const db_val_t *_v, const int _n, const char *_rt, char *_u1, char *_u2)
{

    if (!_rt) {
        LM_ERR("Required values not provided.\n");
        return -1;
    }
    /*char *url = (char *) pkg_malloc(MAX_URL_LEN);
    if (url == NULL) {
        LM_ERR("No more pkg memory left");
        return -1;
    }*/
    char url[MAX_URL_LEN];
    // delete_request = 1;
    if (create_url(_k, _v, _n, url, _rt, _u1, _u2, NULL, 0) < 0) {
        LM_ERR("Failed to process request. URL creation failed.\n");
       // pkg_free(url);
        return -1;
    }
    // delete_request = 0;
    int status = 0;
/*
	struct timeval start, end;
	long secs_used, msec_used;
	gettimeofday(&start, NULL);
*/
    status = curl_delete(url);
/*
	gettimeofday(&end, NULL);
	secs_used = (end.tv_sec - start.tv_sec); //avoid overflow by subtracting first
	msec_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
	LM_WARN(" curl_delete took %ld millisecond\n", msec_used / 1000);
*/
    if (status)
        LM_DBG("DELETE for %s successful with status %d. \n", url, status);
    else
        LM_DBG("DELETE for %s failed with status %d. \n", url, status);
    //pkg_free(url);
    return ((status == 200 || status == 204) ? 1 : 0);
}
/*
 int curl_perform(char* url, char operation)
 {
 switch(operation)
 {
 case DELETE :
 break;
 case GET :
 break;
 case HEAD :
 break;
 default :
 LM_DBG("Invalid Operation\n" );
 }
 }*/
