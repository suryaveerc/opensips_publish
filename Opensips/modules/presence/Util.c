/*
 * Util.c
 *
 *  Created on: Jul 21, 2015
 *      Author: suryaveer
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Util.h"
#include "Common.h"
#include "../../db/db_row.h"
#include "cJSON.h"

//This function fails when values are null. ex: {"username":null}
//Sending default values from the server.
int parse_json_to_result(char *json, db_res_t** result) {
//	LM_DBG("\n\nReceived json: %s\n\n\n", json);
	cJSON *root, *record;
	int recordCount = 0;
	int colCount = 0;
	int i = 0;
	int j = 0;
	int int_val = 0;
	char *str_val = '\0';

	root = cJSON_Parse(json);

    recordCount = cJSON_GetArraySize(root);
    LM_DBG("Count: %d\n", recordCount);
    if(recordCount==0)
    {
    	return 0;
    }
	*result = calloc(1,sizeof(db_res_t));
	if (!result) {
		LM_ERR("No more memory to assign to result.");
		return -1;
	}

	(*result)->n = recordCount;
	(*result)->rows = calloc(recordCount,sizeof(db_row_t));

	if (!(*result)->rows) {
		LM_ERR("No more memory to assign to (*result)->rows.");
		return -1;
	}
	//this is done to get the count of columns only once.
	record = cJSON_GetArrayItem(root, i);
	colCount = cJSON_GetArraySize(record);

	for (i = 0; i < recordCount; i++) {
		j = 0;
		record = cJSON_GetArrayItem(root, i);
		(*result)->rows[i].n = colCount;
		(*result)->rows[i].values = calloc(colCount,sizeof(db_val_t));
		if (!(*result)->rows[i].values) {
			LM_ERR("No more memory to assign to (*result)->rows[i].values .");
			return -1;
		}
		cJSON *subitem = record->child;
		while (subitem) {
	//		LM_DBG("%d---%s: ", j, subitem->string);
			if (subitem->type == cJSON_Number) {
				int_val =
						cJSON_GetObjectItem(record, subitem->string)->valueint;
				(*result)->rows[i].values[j].type = DB_INT;
//				(*result)->rows[i].values[j].nul = 0;
				(*result)->rows[i].values[j++].val.int_val = int_val;
	//			LM_DBG("%d\n", int_val);
			} else {
				str_val =
						cJSON_GetObjectItem(record, subitem->string)->valuestring;
			//	LM_DBG("%s\n", str_val);
				(*result)->rows[i].values[j].type = DB_STRING;
				if (strcmp(str_val, "") == 0) {
					(*result)->rows[i].values[j].nul = 1;
//					(*result)->rows[i].values[j].free = 0;
					(*result)->rows[i].values[j++].val.string_val = NULL;
	//				LM_DBG("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n");
				} else {
					(*result)->rows[i].values[j].nul = 0;
//					(*result)->rows[i].values[j].free = 1;
					(*result)->rows[i].values[j++].val.string_val = strdup(
							str_val);
				//	LM_DBG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
				}
			}
			subitem = subitem->next;
		}
	}
	//LM_DBG("Exiting");
	cJSON_Delete(root);
	return recordCount;
}

int create_url(const db_key_t *_k, const db_val_t *_v, int _n, char *url, const char *_rt, const char *_ruri1,
               const char *_ruri2, const db_key_t *_kr, int _nr)
{

//	LM_DBG("************************ENTER IN create_url******************************\n");
    char *temp = url;
    temp = my_strcpy(temp, ROOT_URL, 0, 0);
    temp = my_strcpy(temp, _rt, 0, 0);
    //LM_DBG("URL RT: %s\n", url);

    int i, len = 0;
    int _l = MAX_URL_LEN;

    if (_k && _v && _n) {
        if (update_request || delete_request) {
            temp = my_strcpy(temp, "/*?", 0, 0);
        }
        else {
            temp = my_strcpy(temp, "?", 0, 0);
        }

        //LM_DBG("URL NOW: %s  \n", url);

        char urlJson[256];// = (char *) pkg_malloc(256);
        if (urlJson == NULL) {
            LM_ERR("No more pkg memory left");
            return -1;
        }
        int status = 0;
        status = db_print_single_json(urlJson, _k, _v, _n);

        if (!status) {
            LM_ERR("Unable create URL key-value json");
            //pkg_free(urlJson);
            return -1;
        }
        //LM_DBG("urlJson: %s  \n", urlJson);
        temp = my_strcpy(temp, FILTER, 0, 0);
        temp = my_strcpy(temp, urlJson, 0, 0);
        //used in mongodb
        /* if(!update_request && !delete_request)
             temp = my_strcpy(temp, NOT_REQ_KEYS, 0, 0);*/


        // Print required keys for GET here
        if (_kr) {
            /*for (i = 0; i < _nr; i++) {
                     LM_DBG("Key: %s \n", _kr[i]->s);
                     }*/
            status = db_print_single_json(urlJson, _kr, NULL, _nr);
            temp = my_strcpy(temp, "&", 0, 0);
            temp = my_strcpy(temp, KEYS, 0, 0);

            if (!status) {
                LM_ERR("Unable to create URL return keys JSON");
               // pkg_free(urlJson);
                return -1;
            }
            //   LM_DBG("urlJson: %s  \n", urlJson);
            temp = my_strcpy(temp, urlJson, 0, 0);
        }
        *(temp) = '\0'; // to remove the last &.
       // pkg_free(urlJson);
    }
    //LM_DBG("\n\nGenerated URL: %s\n\n\n\n", url);

    return len <= _l ? 1 : -1;
}

void get_user_from_sip_uri(char *_u, char *_d, char *uri)
{
    char *uril = uri;
    char *_ul = _u;

    //LM_DBG("PASSED URI %s\n", uril);
    uril = uril + 4;
    //LM_DBG("PASSED URI NOW %s\n", uril);
    while (*uril != '@') {
        *_ul++ = *uril++;
    }
    *_ul = '\0';
    //LM_DBG("PASSED URIL NOW %s\n", uril);
    //LM_DBG("FETCHED USER %s\n", _u);
    ++uril;
    _ul = _d;
    while (*uril != '\0') {
        *_ul++ = *uril++;
    }
    *_ul = '\0';
    //LM_DBG("PASSED URIL NOW %s\n", uril);
    //LM_DBG("FETCHED DOMAIN %s\n", _d);
}

int db_print_single_json(char *_b, const db_key_t *_k, const db_val_t *_v, const int _n)
{

    //LM_DBG("In db_print_single_json\n");
    int i = 0, len = 0;
    char *temp = _b;
    // prepending 0/1 to json before publishing to queue for NOTIFY processing to indicate PUBLISHERS are present or not.
    if (micro_srv_arch) {
        if (avail_pubs)
            temp = my_strcpy(temp, "1:", 0, 0);
        else
            temp = my_strcpy(temp, "0:", 0, 0);
    }
    temp = my_strcpy(temp, "{", 0, 0);
    //_l = JSON_BUF_LEN;
    //ret = sprintf(_b, "%s", "{");
    //len = ret;

//	LM_DBG("The current value of buffer is: %s\n",_b);
    if ((!_k) || (!_n) || (!_b)) {
        return -1;
    }

    for (i = 0; i < _n; i++) {
        //	LM_DBG("Now processing Columns:\t\t %s\n",_k[i]->s);

        temp = my_strcpy(temp, "\"", 0, 0);
        temp = my_strcpy(temp, _k[i]->s, 1, _k[i]->len);
        temp = my_strcpy(temp, "\":", 0, 0);


        // This to print return values JSON.
        if (_v == NULL) {
            //LM_DBG("*********Printing return key %s\n", _k[i]->s);
            temp = my_strcpy(temp, "1,", 0, 0);
            continue;
        }
        // This to print return query key-value JSON.
        if (_v[i].type == DB_INT) {
            //LM_DBG("Which has value:\t\t %d\n",_v[i].val.int_val);
            temp = my_strcpy(temp, my_itoa(_v[i].val.int_val), 0, 0);
            temp = my_strcpy(temp, ",", 0, 0);
        }
        else if (_v[i].type == DB_BITMAP) {
            //LM_DBG("**_id value:\t\t %u\n",_v[i].val.bitmap_val);
            //LM_DBG("**_id value:\t\t %d\n",_v[i].val.bitmap_val);
            temp = my_strcpy(temp, my_uitoa(_v[i].val.bitmap_val), 0, 0);
            temp = my_strcpy(temp, ",", 0, 0);
        }
        else {
            if (strcmp(_k[i]->s, "body") == 0) {
                temp = escapeXML(temp, _v[i].val.str_val.s);
            }
            else {
                temp = my_strcpy(temp, "\"", 0, 0);
                temp = my_strcpy(temp, _v[i].val.str_val.s, 1, _v[i].val.str_val.len);
                temp = my_strcpy(temp, "\",", 0, 0);
            }
        }
        //LM_DBG("Current buffer filled length:\t\t	 %d\n",len);
    }
    temp = my_strcpy(temp - 1, "}", 0, 0);
    *temp = '\0';
    //LM_DBG("GENERATED JSON IS: %s\n", _b);
    return 1;
}

char *escapeXML(char *_b, char *_source)
{
    char *_s = _source;
    char *escapeString = "\\\"";
    char *t1 = escapeString;
    //int len = 0;
    //len = len + sprintf(_b++, "%s", "\"");
    _b = my_strcpy(_b, "\"", 0, 0);
//	LM_DBG("Buffer :\t %s\n",_b);
    while (*_s != '\0') {
        escapeString = t1;
        if (*_s == '\"') {
            while (*escapeString) {
                *_b++ = *escapeString++;
                //		++len;
            }
            ++_s;
        }
        else if (*_s == '\n' || *_s == '\r') {
            ++_s;
        }
        else {
//			++len;
            *_b++ = *_s++;
        }
    }
    //*_b = '\0';
//	len = len + sprintf(_b, "%s", "\",");
    _b = my_strcpy(_b, "\",", 0, 0);
//	LM_DBG("%d\n",len);
    return _b;
}

int free_result(db_res_t *_r)
{
    if (!_r) {
        LM_ERR("invalid parameter\n");
        return -1;
    }
    int i, row_count = 0;
    int col_count = 0;
//	LM_DBG("freeing result set at %p\n", _r);
    row_count = _r->n;
    for (i = 0; i < row_count; i++) {
//		LM_DBG("Freeing %d row.", i);
        col_count = _r->rows[i].n;
        int j = 0;
        for (j = 0; j < col_count; j++) {
            if (_r->rows[i].values[j].type == DB_STRING) {//&& _r->rows[i].values[j].nul == 0
//				LM_DBG("Freeing %d col.", j);
                if (_r->rows[i].values[j].val.string_val)
                    free(_r->rows[i].values[j].val.string_val);
                _r->rows[i].values[j].val.string_val = NULL;
            }
            else if (_r->rows[i].values[j].type == DB_STR) { //&& _r->rows[i].values[j].nul == 0
//				LM_DBG("Freeing %d col.", j);
                if (_r->rows[i].values[j].val.str_val.s)
                    free(_r->rows[i].values[j].val.str_val.s);
                _r->rows[i].values[j].val.str_val.s = NULL;
            }
        }
        free(_r->rows[i].values);
        _r->rows[i].values = NULL;
    }
    if (row_count) {
        free(_r->rows);
        _r->rows = NULL;
    }
    free(_r);
    _r = NULL;
//	LM_DBG("freeing result set a %p\n", _r);
    return 0;
}

unsigned int get_hash(const char *s)
{
    unsigned int hash = 0;
    int c;

    while ((c = *s++)) {
        /* hash = hash * 33 ^ c */
        hash = ((hash << 5) + hash) ^ c;
    }

    return hash;
}
