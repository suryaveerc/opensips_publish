/*
 * RedisDBUtils.h
 *
 *  Created on: Sep 14, 2015
 *      Author: suryaveer
 */

#ifndef REDISDBUTILS_H_
#define REDISDBUTILS_H_
#include "../../str.h"
#include "../../dprint.h"
#include "../../db/db_res.h"
#include "presentity.h"
#include "notify.h"
#include <hiredis/hiredis.h>

#define FETCH_VALUES 1
#define NO_FETCH_VALUES 0

#define READ_RESPONSE 1
#define NO_READ_RESPONSE 0

#define PRESENTITY_SET_PREFIX "PRES"
#define PRESENTITY_SET_PREFIX_LEN 4
#define SUBSCRIPTION_SET_PREFIX "SUBS"
#define SUBSCRIPTION_SET_PREFIX_LEN 4

#define GENERATE_KEY 1

/*
 Structure of Redis cache for Presentity:
 A set named as pres_uri:event - contains value as pres_uri:event:etag. Has TTL.
 A hash named as  pres_uri:event:etag - contains body, extra_hdrs.
 */

/* Adds a presentity in set and hash.
 * read_response is used for updating presentity in hash. If set this function does not read the response.
 * Response will be read by the update function.
 */
int addPresentityInCache(presentity_t* presentity, str* pres_uri,
		str* pres_cache_key, str* pres_cache_value, int read_response);
int addSubscriptionInCache(subs_t* subs, str* pres_uri, int read_response);
/*
 * Checks for presentity in set.
 * If fetch_values is set, retrieve all the elements of the set in listOfPublish
 * returns count of records fetch otherwise 1/-1.
 */
int checkPresentityInCache(char* pres_cache_key, char* pres_cache_value,
		int fetch_values, char ***listOfPublish);

int hasPublication(char **pres_cache_key);
/*
 * Deletes the presentity from set and hash.
 * read_response is used for updating presentity in hash. If set this function does not read the response.
 * Response will be read by the update function.
 */
void deletePresentityFromCache(str* pres_set_key, str* pres_hash_key,
		int read_response);

/*
 * When refresh PUBLISH arrives, this function is used to delete old values from set & hash and add new.
 * This sends commands as pipeline to redis therefore reads the response here. Sets read_response fields to add/delete to 0
 */
int updatePresentityInCache(presentity_t* presentity, str* pres_cache_key,
		str* pres_cache_value, str* pres_uri, str* new_etag);

int updateSubscriptionInCache(subs_t* subs, int type);
int upsertPresentityInCache(char **p_key,str* pres_uri, str* event,db_res_t** result);
int fetchPresentityFromCache(char* pres_cache_key, int *body_col,
		int *extra_hdrs_col, int *expires_col, int *etag_col,
		db_res_t** result);

int checkSusbcriptionInCache(subs_t* subs);

int deleteSubscriptionInCache(subs_t* subs);
/*
 * This creates the KeyValue names for set.
 * If new_etag value is passed, that is used to generate the key/values as that is the latest.
 */
static inline int generatePresentitySetNameValue(presentity_t* presentity,
		str* pres_cache_key, str* pres_cache_value, str* pres_uri,
		str* new_etag, int generateKey) {

		int etag_len = 0;
	etag_len = new_etag ? new_etag->len : presentity->etag.len;

	int ret = 0;
	int pres_cache_value_len = presentity->event->name.len + pres_uri->len
			+ etag_len + 3; // add 2 for :, 1 for '\0'

	if (generateKey) {
		int pres_cache_key_len = PRESENTITY_SET_PREFIX_LEN
				+ presentity->event->name.len + pres_uri->len + 3; // add 2 for :-, 1 for '\0'

		// create set as pres_uri:event
		if (!pres_cache_key->s) {

			pres_cache_key->s = pkg_malloc(pres_cache_key_len);
			if (pres_cache_key->s == NULL) {
				LM_ERR("no more memory\n");
				return -1;
			}
		}
		pres_cache_key->len = pres_cache_key_len;

		ret = snprintf(pres_cache_key->s, pres_cache_key_len, "%s-%.*s:%.*s",
		PRESENTITY_SET_PREFIX, pres_uri->len, pres_uri->s,
				presentity->event->name.len, presentity->event->name.s);
		if (!ret)
			return -1;
	//	LM_DBG("Generated SET name:%s\n", pres_cache_key->s);
	}
	if (!pres_cache_value->s) {

		pres_cache_value->s = pkg_malloc(pres_cache_value_len);
		if (pres_cache_value->s == NULL) {
			LM_ERR("no more memory\n");
			return -1;
		}
	}

	pres_cache_value->len = pres_cache_value_len;

	ret = snprintf(pres_cache_value->s, pres_cache_value_len, "%.*s:%.*s:%.*s",
			pres_uri->len, pres_uri->s, presentity->event->name.len,
			presentity->event->name.s, etag_len,
			new_etag ? new_etag->s : presentity->etag.s);
//	LM_DBG("Generated SET VALUE:%s\n", pres_cache_value->s);
	if (!ret)
		return -1;
	return 1;
}

static inline int generatePresentityCacheValue(str* pres_cache_value, str* pres_uri, char** etag, str* event) {


 //   LM_DBG("## %s !! %s !! %s ##\n", pres_uri->s,*etag, event->s);
    int etag_len = strlen(*etag);
 //   LM_DBG("Length= %d",etag_len);
    int pres_cache_value_len = event->len + pres_uri->len
                               + etag_len + 3; // add 2 for :, 1 for '\0'
    int ret = 0;
    if (!pres_cache_value->s) {

        pres_cache_value->s = pkg_malloc(pres_cache_value_len);
        if (pres_cache_value->s == NULL) {
            LM_ERR("no more memory\n");
            return -1;
        }
    }

    pres_cache_value->len = pres_cache_value_len;

    ret = snprintf(pres_cache_value->s, pres_cache_value_len, "%.*s:%.*s:%.*s",
                   pres_uri->len, pres_uri->s, event->len,
                   event->s, etag_len, *etag);
//	LM_DBG("Generated SET VALUE:%s\n", pres_cache_value->s);
    if (!ret)
        return -1;
    return 1;
}

/*
 * This creates the KeyValue names for set.
 * If new_etag value is passed, that is used to generate the key/values as that is the latest.
 */
/*static inline int generateSubscriptionSetNameValue(subs_t* subs ,str* subs_cache_key, str* subs_cache_value) {

 LM_DBG(
 "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");

 int ret = 0;
 int subs_cache_value_len = subs->callid.len + subs->from_tag.len
 + subs->to_tag.len + 3; // add 2 for :, 1 for '\0'
 int subs_cache_key_len = SUBSCRIPTION_SET_PREFIX_LEN + subs->event->name.len
 + subs->pres_uri.len + 3; // add 2 for :-, 1 for '\0'

 // create set as pres_uri:event
 if (!subs_cache_key.s) {
 LM_DBG("!!!!!!!!!!!!!!!!!!!!!!!!!pres_cache_key.s already malloced\n");
 subs_cache_key.s = malloc(subs_cache_key_len);
 }
 subs_cache_key.len = subs_cache_key_len - 1;

 ret = snprintf(subs_cache_key.s, subs_cache_key_len, "%s-%.*s:%.*s",
 SUBSCRIPTION_SET_PREFIX, subs->pres_uri.len, subs->pres_uri.s, subs->event->name.len,
 subs->event->name.s);
 if (!ret)
 return -1;
 LM_DBG("Generated SET name:%s\n", subs_cache_key.s);

 if (!subs_cache_value.s) {
 LM_DBG(
 "!!!!!!!!!!!!!!!!!!!!!!!!!pres_cache_value.s already malloced\n");
 subs_cache_value.s = malloc(subs_cache_value_len);
 }

 subs_cache_value.len = subs_cache_value_len - 1;
 //to_tag:from_tag:call_id
 ret = snprintf(subs_cache_value.s, subs_cache_value_len, "%.*s:%.*s:%.*s",
 subs->to_tag.len, subs->to_tag.s, subs->from_tag.len,
 subs->from_tag.s, subs->callid.len, subs->callid.s);
 LM_DBG("Generated SET VALUE:%s\n", subs_cache_value.s);
 if (!ret)
 return -1;
 return 1;
 }*/

#endif /* REDISDBUTILS_H_ */
