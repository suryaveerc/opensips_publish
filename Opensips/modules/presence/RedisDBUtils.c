/*
 * RedisDBUtils.c
 *
 *  Created on: Sep 14, 2015
 *      Author: suryaveer
 */

#include <stdio.h>
#include "RedisDBUtils.h"
#include "Common.h"

redisContext *redis_context;
int redisCounter = 0;
//char *subs_queue_msg;
int addSubscriptionInCache(subs_t* subs, str* pres_uri, int read_response) {

	redisReply *reply;

	char temp_key[200] = "";
	char *tk = my_strcpy(temp_key, "", 0, 0);
	char *subs_cache_key = tk;

	tk = my_strcpy(tk, SUBSCRIPTION_SET_PREFIX, 0, 0);
	tk = my_strcpy(tk, "-", 0, 0);
	tk = my_strcpy(tk, subs->pres_uri.s, 1, subs->pres_uri.len);
	tk = my_strcpy(tk, ":", 0, 0);
	tk = my_strcpy(tk, subs->event->name.s, 1, subs->event->name.len);
	*tk = '\0';


	LM_DBG("subs_cache_key: %d %s \n", strlen(subs_cache_key), subs_cache_key);

	int subs_cache_value_len = subs->callid.len + subs->to_tag.len + subs->from_tag.len + 2; // add 2 for :

	char temp_value[200] = "";
	char *tv = my_strcpy(temp_value, "", 0, 0);
	char *subs_cache_value = tv;
	tv = my_strcpy(tv, subs->to_tag.s, 1, subs->to_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->from_tag.s, 1, subs->from_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->callid.s, 1, subs->callid.len);
	*tv = '\0';

	// Commented for passing whole subs to queue.
   /* if(micro_srv_arch)
    {
    //    LM_DBG("pres_uri: %s  \n", subs->pres_uri.s);
    //    LM_DBG("from_user: %s  \n",  subs->from_user.s);
    //    LM_DBG("from_domain: %s  \n", subs->from_domain.s);
        int len = subs_cache_value_len + subs->pres_uri.len + subs->from_user.len + subs->from_domain.len + 3; //2 for concatinate '+' 1 for '@'.
    //    LM_DBG("subs_queue_msg len : %d \n",len);


        subs_queue_msg = pkg_malloc(sizeof(char)*len + 1);

        char *temp = subs_queue_msg;
        temp = my_strcpy(temp, subs->pres_uri.s, 1, subs->pres_uri.len);

        temp = my_strcpy(temp, "+", 0, 0);

        temp = my_strcpy(temp, subs->from_user.s, 1, subs->from_user.len);
        temp = my_strcpy(temp, "@", 0, 0);
        temp = my_strcpy(temp, subs->from_domain.s, 1, subs->from_domain.len);
        temp = my_strcpy(temp, "+", 0, 0);
        temp = my_strcpy(temp, subs_cache_value, 1, subs_cache_value_len);
        *temp = '\0';

        LM_DBG("Subscription Queue Message %s\n",subs_queue_msg);

    }
*/
	//add in pipeline
	redisAppendCommand(redis_context, "SADD %s %s", subs_cache_key,
			subs_cache_value);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	//set expires
	redisAppendCommand(redis_context, "EXPIRE %s %d", subs_cache_key,
			subs->expires);
	//LM_INFO("Redis set counter: %d", ++redisCounter);

	// create hash for to_tag:call_id
	int argc = 0;

	char *arvg[24];
	size_t argvlen[24];

	arvg[argc] = "HMSET";
	argvlen[argc] = 5;
	argc++;

	arvg[argc] = subs_cache_value;
	argvlen[argc] = subs_cache_value_len;
	argc++;

	arvg[argc] = str_local_contact_col.s;
	argvlen[argc] = str_local_contact_col.len;

	argc++;

	arvg[argc] = subs->local_contact.s;
	argvlen[argc] = subs->local_contact.len;

	argc++;

	arvg[argc] = str_record_route_col.s;
	argvlen[argc] = str_record_route_col.len;

	argc++;

	arvg[argc] = subs->record_route.s;
	argvlen[argc] = subs->record_route.len;

	argc++;

	arvg[argc] = str_reason_col.s;
	argvlen[argc] = str_reason_col.len;

	argc++;
	if (subs->reason.s) {
		arvg[argc] = subs->reason.s;
		argvlen[argc] = subs->reason.len;

		argc++;
	} else {
		arvg[argc] = '\0';
		argvlen[argc] = 0;

		argc++;
	}

	arvg[argc] = str_event_id_col.s;
	argvlen[argc] = str_event_id_col.len;

	argc++;
	if (subs->event_id.s) {
		arvg[argc] = subs->event_id.s;
		argvlen[argc] = subs->event_id.len;

		argc++;
	} else {
		arvg[argc] = '\0';
		argvlen[argc] = 0;

		argc++;
	}
	arvg[argc] = str_local_cseq_col.s;
	argvlen[argc] = str_local_cseq_col.len;

	argc++;

	char local_cseq[10];
	int l = 0;
	l = snprintf(local_cseq, 10, "%d", subs->local_cseq);
    arvg[argc] = local_cseq;
//    arvg[argc] = my_itoa_len(subs->local_cseq, &l);;
	argvlen[argc] = l;

	argc++;

	arvg[argc] = str_remote_cseq_col.s;
	argvlen[argc] = str_remote_cseq_col.len;

	argc++;

	char remote_cseq[10];
	l = snprintf(remote_cseq, 10, "%d", subs->remote_cseq);
    arvg[argc] = remote_cseq;
//	arvg[argc] = my_itoa_len(subs->remote_cseq, &l);
	argvlen[argc] = l;

	argc++;

	arvg[argc] = str_status_col.s;
	argvlen[argc] = str_status_col.len;
    //LM_DBG("***** %s\n",arvg[argc]);
	argc++;

	char status[10];
	l = snprintf(status, 10, "%d", subs->status);

    arvg[argc] = status;
//	l=0;
//	arvg[argc] = my_itoa_len(subs->status, &l);
	argvlen[argc] = l;
    //LM_DBG("*****9 %s\n",arvg[argc]);
    int x=argc;
	argc++;

	arvg[argc] = str_version_col.s;
	argvlen[argc] = str_version_col.len;
    //LM_DBG("*****8 %s\n",arvg[x]);
	argc++;

	char version[10];
	l = snprintf(version, 10, "%d", subs->version);

    arvg[argc] = version;
//	arvg[argc] = my_itoa_len(subs->version, &l);
	argvlen[argc] = l;
    //LM_DBG("*****7 %s\n",arvg[x]);
	argc++;

	arvg[argc] = str_expires_col.s;
	argvlen[argc] = str_expires_col.len;
   // LM_DBG("*****6 %s\n",arvg[x]);
	argc++;

	char expires[10];
	l = snprintf(expires, 10, "%d", subs->expires);
    arvg[argc] = expires;
//	arvg[argc] = my_itoa_len(subs->expires, &l);
	argvlen[argc] = l;
   // LM_DBG("*****5 %s\n",arvg[x]);
	argc++;

	arvg[argc] = str_contact_col.s;
	argvlen[argc] = str_contact_col.len;
    //LM_DBG("*****4 %s\n",arvg[x]);
	argc++;


	arvg[argc] = subs->contact.s;
	argvlen[argc] = subs->contact.len;
   // LM_DBG("*****3 %s\n",arvg[x]);
	argc++;

    arvg[argc] = str_socket_info_col.s;
    argvlen[argc] = str_socket_info_col.len;
   // LM_DBG("*****2 %s\n",arvg[x]);
    argc++;
    if (subs->sockinfo) {
        arvg[argc] = subs->sockinfo->sock_str.s;
        argvlen[argc] = subs->sockinfo->sock_str.len;
    } else {
        arvg[argc] = 0;
        argvlen[argc] = 0;
    }
    argc++;
   // LM_DBG("*****1 %s\n",arvg[x]);
   // LM_DBG("**************************** status %d\n",subs->status);
   /* int j=0;
    for(j=0;j<argc;j++)
    {
        LM_DBG("***** %s\n",arvg[j]);
    }*/
	//add in pipeline
	redisAppendCommandArgv(redis_context, argc, arvg, argvlen);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	redisAppendCommand(redis_context, "EXPIRE %s %d", subs_cache_value,
			subs->expires);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	if (read_response) {

		redisGetReply(redis_context, &reply); // reply for SET
		//LM_DBG("Reply from redis: %d\n", reply->integer);
		freeReplyObject(reply);
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		redisGetReply(redis_context, &reply); // reply for EXPIRES
		//LM_DBG("Reply from redis: %d\n", reply->integer);
		freeReplyObject(reply);
		//LM_INFO("Redis unset counter: %d", --redisCounter);

		redisGetReply(redis_context, &reply); // reply for HMSET
		//LM_DBG("Reply from redis: %s\n", reply->str);
		freeReplyObject(reply);
		//LM_INFO("Redis unset counter: %d", --redisCounter);

		redisGetReply(redis_context, &reply); // reply for HMSET EXPIRES
		//LM_DBG("Reply from redis: %s\n", reply->str);
		freeReplyObject(reply);
		//LM_INFO("Redis unset counter: %d", --redisCounter);
	} //else
		//LM_DBG("Skipped reading response.\n");

	//LM_DBG("Insert in Cache complete.\n");


	return 1;
}
int addPresentityInCache(presentity_t* presentity, str* pres_uri,
		str* pres_cache_key, str* pres_cache_value, int read_response) {

	redisReply *reply;

	//add in pipeline, set sorted by received time (ASC)
	redisAppendCommand(redis_context, "ZADD %s %d %s", pres_cache_key->s,
			presentity->received_time, pres_cache_value->s);
	//set expires
//	LM_INFO("Redis set counter: %d", ++redisCounter);
	redisAppendCommand(redis_context, "EXPIRE %s %d", pres_cache_key->s,
			presentity->expires);
//	LM_INFO("Redis set counter: %d", ++redisCounter);
	// create hash for presentity:event:etag
	int argc = 6; //HMSET <hashname> <body> <value>
//	argc = presentity->extra_hdrs ? 6 : 5;

	char *arvg[argc];
	size_t argvlen[argc];

	argc = 0;

	arvg[argc] = "HMSET";
	argvlen[argc] = 5;
	argc++;

//	LM_DBG("Setting HASH Key:%s\n", pres_cache_value->s);
	arvg[argc] = pres_cache_value->s;

	argvlen[argc] = pres_cache_value->len - 1; // 1 for null character

	argc++;

	arvg[argc] = str_body_col.s;
	argvlen[argc] = str_body_col.len;
	argc++;

	arvg[argc] = presentity->body.s;
	argvlen[argc] = presentity->body.len;
	argc++;

	arvg[argc] = str_extra_hdrs_col.s;
	argvlen[argc] = str_extra_hdrs_col.len;
	argc++;
	if (presentity->extra_hdrs) {
		arvg[argc] = presentity->extra_hdrs->s;
		argvlen[argc] = presentity->extra_hdrs->len;
		argc++;
	} else {
		arvg[argc] = '\0';
		argvlen[argc] = 0;
		argc++;
	}

	//add in pipeline
	redisAppendCommandArgv(redis_context, argc, arvg, argvlen);
//	LM_INFO("Redis set counter: %d", ++redisCounter);
	redisAppendCommand(redis_context, "EXPIRE %s %d", pres_cache_value->s,
			presentity->expires);
//	LM_INFO("Redis set counter: %d", ++redisCounter);
	if (read_response) {
		redisGetReply(redis_context, &reply); // reply for SET
//		LM_DBG("Reply from redis: %d\n", reply->integer);
		freeReplyObject(reply);
	//	LM_INFO("Redis unset counter: %d", --redisCounter);
		redisGetReply(redis_context, &reply); // reply for EXPIRES
	//	LM_DBG("Reply from redis: %d\n", reply->integer);
		freeReplyObject(reply);
	//	LM_INFO("Redis unset counter: %d", --redisCounter);
		redisGetReply(redis_context, &reply); // reply for HMSET
		//LM_DBG("Reply from redis: %s\n", reply->str);
		freeReplyObject(reply);
	//	LM_INFO("Redis unset counter: %d", --redisCounter);
		redisGetReply(redis_context, &reply); // reply for EXPIRES
		//LM_DBG("Reply from redis: %d\n", reply->integer);
		freeReplyObject(reply);
	//	LM_INFO("Redis unset counter: %d", --redisCounter);
	} //else
		//LM_DBG("Skipped reading response.\n");

	//LM_DBG("Insert in Cache complete.\n");
	return 1;
}
int checkPresentityInCache(char* pres_cache_key, char* pres_cache_value,
		int fetch_values, char ***listOfPublish) {
	redisReply *reply;
//	LM_DBG("\n\n\n!!!!!!-%s-\n\n\n", pres_cache_key);

	if (fetch_values) {
		reply = redisCommand(redis_context, "ZRANGE %s 0 -1", pres_cache_key);
		if (reply->type == REDIS_REPLY_ERROR) {
			LM_ERR("Error: %s\n", reply->str);
			freeReplyObject(reply);
			return -1;
		} else {
			int i;
			int count = 0;
			count = reply->elements;
			if (count > 0) {

				*listOfPublish = pkg_malloc(1 + count * sizeof(char*));
				if (*listOfPublish == NULL) {
					LM_ERR("NO more pkg memory left.\n");
					return -1;
				}
			} else {
			//	LM_DBG("Nothing found in cache.\n");
				return 0;
			}
			//LM_DBG("In checkPresentityInCache 4\n");
			for (i = 0; i < reply->elements; i++) {
//				LM_DBG("Result: %s\n", reply->element[i]->str);
				(*listOfPublish)[i] = pkg_malloc(
						strlen(reply->element[i]->str) * sizeof(char) + 1);
				if ((*listOfPublish)[i] == NULL) {
					LM_ERR("NO more pkg memory left.\n");
					return -1;
				}
				strcpy((*listOfPublish)[i], reply->element[i]->str);
//				LM_DBG("listOfPublish: %s\n", (*listOfPublish)[i]);
			}
			(*listOfPublish)[i] = NULL;
			freeReplyObject(reply);
			return count;
		}

	} else {
//		LM_DBG("Searching in cache for *%s* *%s*", pres_cache_key,				pres_cache_value);
		reply = redisCommand(redis_context, "ZSCORE %s %s", pres_cache_key,
				pres_cache_value);

		if (reply->type == REDIS_REPLY_NIL) {
			//LM_DBG("NOT FOUND");
			freeReplyObject(reply);
			return 0;
		} else {
			//int found = atoi(reply->str);
			//LM_DBG("FOUND");
			freeReplyObject(reply);
			return 1;
		}
	}
	//found > 0
	//not found = 0

}
void deletePresentityFromCache(str* pres_set_key, str* pres_hash_key,
		int read_response) {
	redisReply *reply;
	//LM_DBG("DELETING KEY:%s\n", pres_set_key->s);
	//LM_DBG("DELETING VALUE:%s\n", pres_hash_key->s);
	redisAppendCommand(redis_context, "ZREM %s %s", pres_set_key->s,
			pres_hash_key->s);
	//LM_INFO("Redis set counter: %d", ++redisCounter);

	redisAppendCommand(redis_context, "DEL %s", pres_hash_key->s);
	//LM_INFO("Redis set counter: %d", ++redisCounter);

	if (read_response) {
		redisGetReply(redis_context, &reply); // reply for ZREM
		freeReplyObject(reply);
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		redisGetReply(redis_context, &reply); // reply for DEL
		freeReplyObject(reply);
		//LM_INFO("Redis unset counter: %d", --redisCounter);
	} //else
		//LM_DBG("Skipped readign response.\n");
}
int updatePresentityInCache(presentity_t* presentity, str* pres_cache_key,
		str* pres_cache_value, str* pres_uri, str* new_etag) {
	redisReply *reply;
	if (!new_etag) {
		LM_ERR("No etag found to create new record.\n");
		return -1;
	}
	int status = 1;
	//LM_DBG("UPDATING SET:%s\n", pres_cache_key->s);
	//LM_DBG("UPDATING VALUE:%s\n", pres_cache_value->s);

	deletePresentityFromCache(pres_cache_key, pres_cache_value,
	NO_READ_RESPONSE);
	if (generatePresentitySetNameValue(presentity, pres_cache_key,
			pres_cache_value, pres_uri, new_etag, !GENERATE_KEY) < 0) {
		LM_ERR("Creating KV pair for presentity.\n");
		return -1;
	}
	addPresentityInCache(presentity, pres_uri, pres_cache_key, pres_cache_value,
	NO_READ_RESPONSE);
	// replies from delete
	redisGetReply(redis_context, &reply); // reply for ZREM
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	freeReplyObject(reply);
	redisGetReply(redis_context, &reply); // reply for DEL
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	freeReplyObject(reply);

	// replies from add
	redisGetReply(redis_context, &reply); // reply for EXPIRES
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	freeReplyObject(reply);
	redisGetReply(redis_context, &reply); // reply for SET
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	//LM_DBG("Reply from redis: %d\n", reply->integer);
	freeReplyObject(reply);
	redisGetReply(redis_context, &reply); // reply for EXPIRES
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	//LM_DBG("Reply from redis: %d\n", reply->integer);
	freeReplyObject(reply);
	redisGetReply(redis_context, &reply); // reply for HMSET
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	//LM_DBG("Reply from redis: %s\n", reply->str);
	freeReplyObject(reply);
	return status;
}
int fetchPresentityFromCache(char* pres_cache_key, int *body_col,
		int *extra_hdrs_col, int *expires_col, int *etag_col, db_res_t** result) {

	//LM_DBG("In fetchPresentityFromCache\n");
	redisReply *reply;
	char **listOfPublish;
	int publish_count = 0;
	publish_count = checkPresentityInCache(pres_cache_key, NULL, FETCH_VALUES,
			&listOfPublish);
	if (publish_count < 0) {
		LM_ERR("Fetching details from cache. Try database.");
		return -1;
	} else if (publish_count == 0) {
		//LM_DBG("No records in cache. Try database.");
		return 0;
	}

//	LM_DBG("___________________publish_count.%d\n", publish_count);
	int i = 0, j = 0;

	for (i = 0; i < publish_count; i++) {
//		LM_DBG("Searching: %s\n", listOfPublish[i]);
		redisAppendCommand(redis_context, "HGETALL %s", listOfPublish[i]);
		//LM_INFO("Redis set counter: %d", ++redisCounter);
	}
	*result = pkg_malloc(sizeof(db_res_t));
	if (!result) {
		LM_ERR("No more memory to assign to result.");
		for (i = 0; i < sizeof(listOfPublish) / sizeof(listOfPublish[0]); i++)
			free(listOfPublish[i]);
		free(listOfPublish);
		return -1;
	}
	(*result)->n = publish_count;
	(*result)->rows = pkg_malloc(sizeof(db_row_t) * publish_count);
	if (!(*result)->rows) {
		LM_ERR("No more memory to assign to (*result)->rows.");
		free_result(result);
		for (i = 0; i < sizeof(listOfPublish) / sizeof(listOfPublish[0]); i++)
			free(listOfPublish[i]);
		free(listOfPublish);
		return -1;
	}
	*etag_col = 0;
	*expires_col = 1;
	*body_col = 2;
	*extra_hdrs_col = 3;
	for (i = 0; i < publish_count; i++) {
		redisGetReply(redis_context, &reply);
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		if (reply->type == REDIS_REPLY_ERROR) {
			LM_ERR("Error: %s\n", reply->str);
			freeReplyObject(reply);
			return -1;
		} else {
			char *temp = listOfPublish[i] + strlen(listOfPublish[i]);
			while (*temp != ':') {
				temp--;
			}
			temp++;
			//LM_DBG("%s\n", temp); //fetched etag from the key.
			(*result)->rows[i].n = 4; //actual returned will be 2 or 1 but this is done to match the expected result in the calling function. Work around!!
			(*result)->rows[i].values = pkg_malloc(sizeof(db_val_t) * 4);

			// 0- etag, 1-expires, 2-body, 3-extra_hdrs

			int customindex = 0;
			// assign etag
			(*result)->rows[i].values[customindex].type = DB_STR;
//			(*result)->rows[i].values[customindex].nul = 0;
			(*result)->rows[i].values[customindex].val.str_val.s = strdup(temp);
			customindex++;
			// assign expires
			(*result)->rows[i].values[customindex].type = DB_INT;
//			(*result)->rows[i].values[customindex].nul = 1;
			(*result)->rows[i].values[customindex].val.int_val = 0; //value currently not used.
			//customindex++;
			//LM_DBG("Key value pair count:%d\n", reply->elements / 2);
			for (j = 1; j < reply->elements; j += 2) { // read only odd values. evens contains key names.
				//LM_DBG("KEY returned [%d]:%s\n", j - 1,reply->element[j - 1]->str);
				//LM_DBG("VALUE returned [%d]:%s\n", j, reply->element[j]->str);

				if (strcmp("body", reply->element[j - 1]->str) == 0) {
					customindex = *body_col;
				} else {
					customindex = *extra_hdrs_col;
				}
				(*result)->rows[i].values[customindex].type = DB_STR;
				if (reply->element[j]->str) {
//					(*result)->rows[i].values[customindex].nul = 0;
					(*result)->rows[i].values[customindex].val.string_val =
							strdup(reply->element[j]->str);
					//LM_DBG("!!! %d !!!!!!!!!!!!!!!!!!%s\n", customindex,	(*result)->rows[i].values[customindex].val.string_val);
				} else {
//					(*result)->rows[i].values[customindex].nul = 1;
					(*result)->rows[i].values[customindex].val.string_val =
							'\0';
				}

			}
			freeReplyObject(reply);
		}

	}
	/*LM_DBG("**********VERIFY RESULT*****************");
	 LM_DBG("Count of ROWS:%d\n", (*result)->n);
	 for (i = 0; i < (*result)->n; i++) {
	 LM_DBG("Count of COLUMNS:%d\n", (*result)->rows[i].n);
	 for (j = 0; j < (*result)->rows[i].n; j++) {
	 if ((*result)->rows[i].values[j].type
	 == DB_STR&& (*result)->rows[i].values[j].val.string_val !=NULL)
	 LM_DBG("*****%s\n",
	 (*result)->rows[i].values[j].val.string_val);
	 else
	 LM_DBG("*****%d\n", (*result)->rows[i].values[j].val.int_val);
	 }
	 }*/
	for (i = 0; i < sizeof(listOfPublish) / sizeof(listOfPublish[0]); i++)
		pkg_free(listOfPublish[i]);
	pkg_free(listOfPublish);
	return 1;
}
int hasPublication(char **pres_cache_key) {
	redisReply *reply;
	int ret = 0;
	reply = redisCommand(redis_context, "ZCARD %s", *pres_cache_key);
	if (reply->type == REDIS_REPLY_ERROR) {
		freeReplyObject(reply);
		return -1;
	} else {
		ret = reply->integer;
		freeReplyObject(reply);
		return ret;
	}
}
int updateSubscriptionInCache(subs_t* subs, int type) {

	//TODO: Add the code to publish in queue as done in addsubscription.
	//LM_DBG("Enter!!!!");
	redisReply *reply;

//	int subs_cache_key_len = SUBSCRIPTION_SET_PREFIX_LEN + subs->event->name.len
//			+ subs->pres_uri.len + 3; // add 2 for :-, 1 for '\0
	int subs_cache_value_len = subs->callid.len + subs->from_tag.len
			+ subs->to_tag.len + 3;

	char temp_key[200] = "";
	char *tk = my_strcpy(temp_key, "", 0, 0);
	char *subs_cache_key = tk;

	char temp_value[200] = "";
	char *tv = my_strcpy(temp_value, "", 0, 0);
	char *subs_cache_value = tv;

	tk = my_strcpy(tk, SUBSCRIPTION_SET_PREFIX, 0, 0);
	tk = my_strcpy(tk, "-", 0, 0);
	tk = my_strcpy(tk, subs->pres_uri.s, 1, subs->pres_uri.len);
	tk = my_strcpy(tk, ":", 0, 0);
	tk = my_strcpy(tk, subs->event->name.s, 1, subs->event->name.len);
	*tk = '\0';

	tv = my_strcpy(tv, subs->to_tag.s, 1, subs->to_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->from_tag.s, 1, subs->from_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->callid.s, 1, subs->callid.len);
	*tv = '\0';


//	LM_DBG("Search !%s!  !%s!",subs_cache_key,subs_cache_value);
	reply = redisCommand(redis_context, "SISMEMBER %s %s", subs_cache_key,
			subs_cache_value);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	if (reply->integer == 0) {
		LM_ERR("Value not found in cache\n");
		freeReplyObject(reply);
		return -1;
	}
//Commented for passing whole subs info to queue.
/*
	if(micro_srv_arch)
	{
		LM_DBG("pres_uri: %s  \n", subs->pres_uri.s);
		LM_DBG("from_user: %s  \n",  subs->from_user.s);
		LM_DBG("from_domain: %s  \n", subs->from_domain.s);
		int len = subs_cache_value_len + subs->pres_uri.len + subs->from_user.len + subs->from_domain.len + 3; //2 for concatinate '+' 1 for '@'.
		LM_DBG("subs_queue_msg len : %d \n",len);


		subs_queue_msg = pkg_malloc(sizeof(char)*len + 1);

		char *temp = subs_queue_msg;
		temp = my_strcpy(temp, subs->pres_uri.s, 1, subs->pres_uri.len);
		LM_DBG("1\n");
		temp = my_strcpy(temp, "+", 0, 0);
		LM_DBG("2\n");
		temp = my_strcpy(temp, subs->from_user.s, 1, subs->from_user.len);
		temp = my_strcpy(temp, "@", 0, 0);
		temp = my_strcpy(temp, subs->from_domain.s, 1, subs->from_domain.len);
		temp = my_strcpy(temp, "+", 0, 0);
		temp = my_strcpy(temp, subs_cache_value, 1, subs_cache_value_len);
		*temp = '\0';

		LM_DBG("Subscription Queue Message %s\n",subs_queue_msg);

	}
*/

	/*reply = redisCommand(redis_context, "PING");
	 LM_DBG("Check!!!!!!%s", reply->str);
	 freeReplyObject(reply);*/
	int argc = 0;
	if (type & REMOTE_TYPE)
		argc = 8;
	else
		argc = 4;

	char *arvg[argc];
	size_t argvlen[argc];

	argc = 0; //reset to zero
	arvg[argc] = "HMSET";
	argvlen[argc] = 5;
	argc++;

	arvg[argc] = subs_cache_value;
	argvlen[argc] = subs_cache_value_len - 1;
	argc++;

	int l = 0;
	if (type & REMOTE_TYPE) {

		//LM_DBG("REMOTE_TYPE");
		arvg[argc] = str_remote_cseq_col.s;
		argvlen[argc] = str_remote_cseq_col.len;
		argc++;

		char remote_cseq[10];
		l = snprintf(remote_cseq, 10, "%d", subs->remote_cseq);

        arvg[argc] = remote_cseq;
		//arvg[argc] = my_itoa_len(subs->remote_cseq, &l);
//		arvg[argc] = remote_cseq;
		argvlen[argc] = l;
		argc++;

		arvg[argc] = str_expires_col.s;
		argvlen[argc] = str_expires_col.len;
		argc++;

		char expires[10];
		l = snprintf(expires, 10, "%d", subs->expires + (int) time(NULL));
		arvg[argc] = expires;

//		arvg[argc] = my_itoa_len(subs->expires+ (int) time(NULL), &l);
		argvlen[argc] = l;
		argc++;

	} else {
		//LM_DBG("LOCAL_TYPE");

		redisAppendCommand(redis_context, "MULTI");

		//LM_INFO("Redis set counter: %d", ++redisCounter);

		redisAppendCommand(redis_context, "HINCRBY %s %s %d",
								subs_cache_value, "local_cseq", 1);
		//LM_INFO("Redis set counter: %d", ++redisCounter);

		redisAppendCommand(redis_context, "HINCRBY %s %s %d",
								subs_cache_value, "version", 1);
		//LM_INFO("Redis set counter: %d", ++redisCounter);

	}

	arvg[argc] = str_status_col.s;
	argvlen[argc] = str_status_col.len;
	argc++;

	char status[10];
	l = snprintf(status, 10, "%d", subs->status);
	arvg[argc] = status;
//	l=0;
//	arvg[argc] = my_itoa_len(subs->status, &l);
	argvlen[argc] = l;
	argc++;

	if (REDIS_OK != redisAppendCommandArgv(redis_context, argc, arvg, argvlen))
		LM_ERR("Error in MULTI %s", redis_context->errstr);
	//LM_INFO("Redis set counter: %d", ++redisCounter);

	if (type & LOCAL_TYPE) {

		redisAppendCommand(redis_context, "EXEC");
		//LM_INFO("Redis set counter: %d", ++redisCounter);

		redisGetReply(redis_context, &reply);
		// reply for MULTI
		//LM_INFO("Redis unset counter: %d", --redisCounter);

		freeReplyObject(reply);

		redisGetReply(redis_context, &reply);
		// reply for HINCRBY local_cseq
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		freeReplyObject(reply);

		//LM_DBG("Reply from redis: %d\n", reply->integer);

		redisGetReply(redis_context, &reply);
		// reply for HINCRBY version
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		freeReplyObject(reply);

		//LM_DBG("Reply from redis: %d\n", reply->integer);

		redisGetReply(redis_context, &reply);
		// reply for HMSET
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		freeReplyObject(reply);

		redisGetReply(redis_context, &reply);
		// reply for EXEC
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		freeReplyObject(reply);

	} else {
		redisGetReply(redis_context, &reply); // reply for HMSET
		//LM_INFO("Redis unset counter: %d", --redisCounter);
		//LM_DBG("Reply from redis: %s\n", reply->str);
		freeReplyObject(reply);
	}
	return 1;
}
int checkSusbcriptionInCache(subs_t* subs) {
	redisReply *reply;

	int subs_cache_value_len = subs->callid.len + subs->from_tag.len
			+ subs->to_tag.len + 2;

	char temp_value[200] = "";
	char *tv = my_strcpy(temp_value, "", 0, 0);
	char *subs_cache_value = tv;

	tv = my_strcpy(tv, subs->to_tag.s, 1, subs->to_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->from_tag.s, 1, subs->from_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->callid.s, 1, subs->callid.len);
	*tv = '\0';
	char *arvg[8];
	size_t argvlen[8];
	str reason;

	int argc = 0;

	arvg[argc] = "HMGET";
	argvlen[argc] = 5;
	argc++;

	arvg[argc] = subs_cache_value;
	argvlen[argc] = subs_cache_value_len;
	argc++;

	int local_cseq_col = 0;
	int remote_cseq_col = 0;
	int record_route_col = 0;
	int status_col = 0;
	int reason_col = 0;
	int version_col = 0;

	arvg[argc] = str_record_route_col.s;
	argvlen[argc] = str_record_route_col.len;
	record_route_col = argc++;

	arvg[argc] = str_reason_col.s;
	argvlen[argc] = str_reason_col.len;
	reason_col = argc++;

	arvg[argc] = str_local_cseq_col.s;
	argvlen[argc] = str_local_cseq_col.len;
	local_cseq_col = argc++;

	arvg[argc] = str_remote_cseq_col.s;
	argvlen[argc] = str_remote_cseq_col.len;
	remote_cseq_col = argc++;

	arvg[argc] = str_status_col.s;
	argvlen[argc] = str_status_col.len;
	status_col = argc++;

	arvg[argc] = str_version_col.s;
	argvlen[argc] = str_version_col.len;
	version_col = argc++;

	redisAppendCommandArgv(redis_context, argc, arvg, argvlen);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	redisGetReply(redis_context, &reply);
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	if (reply->type == REDIS_REPLY_ERROR)
		return -1;
	else {
		int count = reply->elements;
		if (count == 0)
			return 0;

		int remote_cseq = 0;
		remote_cseq = atoi(reply->element[remote_cseq_col]->str);
		if (subs->remote_cseq <= remote_cseq) {
			LM_ERR("wrong sequence number received: %d - stored: %d\n",
					subs->remote_cseq, remote_cseq);

			return -1;
		}

		subs->status = atoi(reply->element[status_col]->str);
		reason.s = (char*) reply->element[reason_col]->str;
		if (reason.s) {
			reason.len = strlen(reason.s);
			subs->reason.s = (char*) pkg_malloc(reason.len);
			if (subs->reason.s == NULL) {
				LM_ERR("No more memory.");
				return -1;
			}
			memcpy(subs->reason.s, reason.s, reason.len);
			subs->reason.len = reason.len;
		}

		subs->local_cseq = atoi(reply->element[local_cseq_col]->str);
		subs->version = atoi(reply->element[version_col]->str);

		str record_route;
		record_route.s = (char*) reply->element[record_route_col]->str;
		if (record_route.s) {
			record_route.len = strlen(record_route.s);
			subs->record_route.s = (char*) pkg_malloc(record_route.len);
			if (subs->record_route.s == NULL) {
				LM_ERR("No more memory.");
				return -1;
			}
			memcpy(subs->record_route.s, record_route.s, record_route.len);
			subs->record_route.len = record_route.len;
		}
		freeReplyObject(reply);
		/*LM_DBG("###########################################################");
		 LM_DBG("subs->record_route.s %s", subs->record_route.s);
		 LM_DBG("subs->version %d", subs->version);
		 LM_DBG("subs->local_cseq %d", subs->local_cseq);
		 LM_DBG("subs->reason.s %s", subs->reason.s);
		 LM_DBG("subs->remote_cseq %d", subs->remote_cseq);
		 LM_DBG("subs->status %d", subs->status);*/

		return 1;
	}

}
int deleteSubscriptionInCache(subs_t* subs) {
	redisReply *reply;
	int cseq = 0;

	char temp_key[200] = "";
	char *tk = my_strcpy(temp_key, "", 0, 0);
	char *subs_cache_key = tk;

	char temp_value[200] = "";
	char *tv = my_strcpy(temp_value, "", 0, 0);
	char *subs_cache_value = tv;

	tk = my_strcpy(tk, SUBSCRIPTION_SET_PREFIX, 0, 0);
	tk = my_strcpy(tk, "-", 0, 0);
	tk = my_strcpy(tk, subs->pres_uri.s, 1, subs->pres_uri.len);
	tk = my_strcpy(tk, ":", 0, 0);
	tk = my_strcpy(tk, subs->event->name.s, 1, subs->event->name.len);
	*tk = '\0';

	tv = my_strcpy(tv, subs->to_tag.s, 1, subs->to_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->from_tag.s, 1, subs->from_tag.len);
	tv = my_strcpy(tv, ":", 0, 0);
	tv = my_strcpy(tv, subs->callid.s, 1, subs->callid.len);
	*tv = '\0';

	redisAppendCommand(redis_context, "HGET %s %s", subs_cache_key,
			str_local_cseq_col.s);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	redisAppendCommand(redis_context, "SREM %s %s", subs_cache_key,
			subs_cache_value);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	redisAppendCommand(redis_context, "HDEL %s", subs_cache_value);
	//LM_INFO("Redis set counter: %d", ++redisCounter);
	redisGetReply(redis_context, &reply); // reply for SREM
	//LM_INFO("Redis unset counter: %d", --redisCounter);
	if (reply->type == REDIS_REPLY_ERROR) {
		LM_ERR("Error: %s\n", reply->str);
		return -1;
	} else {
		cseq = atoi(reply->str);
		//LM_DBG("Returned LOCAL_CSEQ %d", cseq);
	}
	freeReplyObject(reply);
	redisGetReply(redis_context, &reply); // reply for SREM
	//LM_INFO("Redis unset counter: %d", --redisCounter);

	freeReplyObject(reply);
	redisGetReply(redis_context, &reply); // reply for HDEL
	//LM_INFO("Redis unset counter: %d", --redisCounter);

	freeReplyObject(reply);
	return cseq;
}

// this function adds presentity in cache fetched from the SUBS flow.
int upsertPresentityInCache(char** pres_cache_key, str* pres_uri, str* event, db_res_t **result) {

    redisReply *reply;
    str pres_cache_value = { NULL, 0 };
    int i=0, count=0;// redisCounter=0;

    count  = (*result)->n;
  //  LM_DBG("**** %s !! %s !! %s**** %d\n",*pres_cache_key,pres_uri->s,event->s, count);
    for (i = 0; i < count; i++) {

    //    LM_DBG("!!!!!!!!!!!!!!%s\n", (*result)->rows[i].values[0].val.string_val);
     //   LM_DBG("!!!!!!!!!!!!!!%d\n", (*result)->rows[i].values[1].val.int_val);
     //   LM_DBG("!!!!!!!!!!!!!!%s\n", (*result)->rows[i].values[2].val.string_val);
        /*if ((*result)->rows[i].values[3].val.string_val != NULL)
            LM_DBG("!!!!!!!!!!!!!!%s\n",(*result)->rows[i].values[3].val.string_val);
        else
            LM_DBG("EXTRA HEADERS IS NULL\n");
*/        //add in pipeline, set sorted by received time (ASC)
        generatePresentityCacheValue(&pres_cache_value, pres_uri, &((*result)->rows[i].values[0].val.string_val), event);
   //     LM_DBG("pres_cache_value %s %d\n", pres_cache_value.s, pres_cache_value.len);
        redisAppendCommand(redis_context, "ZADD %s %d %s", *pres_cache_key,
                           time(NULL), pres_cache_value.s);
        //set expires
        //LM_INFO("Redis set counter: %d", ++redisCounter);
        redisAppendCommand(redis_context, "EXPIRE %s %d", *pres_cache_key,
                           (*result)->rows[i].values[1].val.int_val);
        //LM_INFO("Redis set counter: %d", ++redisCounter);
        // create hash for presentity:event:etag
        int argc = 6; //HMSET <hashname> <body> <value>

        char *arvg[argc];
        size_t argvlen[argc];

        argc = 0;

        arvg[argc] = "HMSET";
        argvlen[argc] = 5;
        argc++;

//	LM_DBG("Setting HASH Key:%s\n", pres_cache_value->s);
        arvg[argc] = pres_cache_value.s;

        argvlen[argc] = pres_cache_value.len - 1; // 1 for null character

        argc++;

        arvg[argc] = str_body_col.s;
        argvlen[argc] = str_body_col.len;
        argc++;

        arvg[argc] = (*result)->rows[i].values[2].val.string_val;
        argvlen[argc] = strlen((*result)->rows[i].values[2].val.string_val);
        argc++;

        arvg[argc] = str_extra_hdrs_col.s;
        argvlen[argc] = str_extra_hdrs_col.len;
        argc++;
        if ((*result)->rows[i].values[3].val.string_val != NULL) {
            arvg[argc] = (*result)->rows[i].values[3].val.string_val;
            argvlen[argc] = strlen((*result)->rows[i].values[3].val.string_val);
            argc++;
        } else {
            arvg[argc] = '\0';
            argvlen[argc] = 0;
            argc++;
        }

        //add in pipeline
        redisAppendCommandArgv(redis_context, argc, arvg, argvlen);
        //LM_INFO("Redis set counter: %d", ++redisCounter);
        redisAppendCommand(redis_context, "EXPIRE %s %d", pres_cache_value.s,
                           (*result)->rows[i].values[1].val.int_val);
        //LM_INFO("Redis set counter: %d", ++redisCounter);

        redisGetReply(redis_context, &reply); // reply for SET
       // LM_DBG("Reply from redis: %d\n", reply->integer);
        freeReplyObject(reply);
        //LM_INFO("Redis unset counter: %d", --redisCounter);
        redisGetReply(redis_context, &reply); // reply for EXPIRES
     //   LM_DBG("Reply from redis: %d\n", reply->integer);
        freeReplyObject(reply);
        //LM_INFO("Redis unset counter: %d", --redisCounter);
        redisGetReply(redis_context, &reply); // reply for HMSET
       // LM_DBG("Reply from redis: %s\n", reply->str);
        freeReplyObject(reply);
        //LM_INFO("Redis unset counter: %d", --redisCounter);
        redisGetReply(redis_context, &reply); // reply for EXPIRES
        //LM_DBG("Reply from redis: %d\n", reply->integer);
        freeReplyObject(reply);
        //LM_INFO("Redis unset counter: %d", --redisCounter);
    }
    //LM_DBG("Insert in Cache complete.\n");
    return 1;
}
