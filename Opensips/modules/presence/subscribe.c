/*
 * $Id: subscribe.c 10423 2014-03-12 17:22:46Z opensipsrelease $
 *
 * presence module - presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 *
 * This file is part of opensips, a free SIP serves.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2006-08-15  initial version (Anca Vamanu)
 *  2010-10-19  support for extra headers (osas)
 */

#include "../../ut.h"
#include "../../usr_avp.h"
#include "../../data_lump_rpl.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_event.h"
#include "../../parser/contact/parse_contact.h"
#include "presence.h"
#include "subscribe.h"
#include "utils_func.h"
#include "notify.h"
#include "../pua/hash.h"
#include "Common.h"
#include "RedisDBUtils.h"
#include "Util.h"
#include "RepositoryHandler.h"
#include "RepositoryAccessClient.h"
#include "../../db/db_val.h"
#include "queue_publisher.h"
#include <stdlib.h>

int get_stored_info(struct sip_msg *msg, subs_t *subs, int *error_ret,
                    str *reply_str);

int get_database_info(struct sip_msg *msg, subs_t *subs, int *error_ret,
                      str *reply_str);

int get_db_subs_auth(subs_t *subs, int *found);

int insert_db_subs_auth(subs_t *subs);

int insert_subs_db(subs_t *s, char *_b);

static str su_200_rpl = str_init("OK");
static str pu_481_rpl = str_init("Subscription does not exist");
static str pu_400_rpl = str_init("Bad request");
static str pu_500_rpl = str_init("Server Internal Error");
static str pu_489_rpl = str_init("Bad Event");

char *subs_queue_msg;
int send_2XX_reply(struct sip_msg *msg, int reply_code, int lexpire, str *rtag,
                   str *local_contact) {
    char *hdr_append = NULL;
    int lexpire_len;
    char *lexpire_s;
    int len;
    char *p;

    if (lexpire < 0)
        lexpire = 0;

    lexpire_s = int2str((unsigned long) lexpire, &lexpire_len);

    len = 9 /*"Expires: "*/+ lexpire_len + CRLF_LEN + 10 /*"Contact: <"*/
          + local_contact->len + 1 /*">"*/
          + ((msg->rcv.proto != PROTO_UDP) ? 15/*";transport=xxxx"*/: 0) + CRLF_LEN;

    hdr_append = (char *) pkg_malloc(len);
    if (hdr_append == NULL) {
        ERR_MEM(PKG_MEM_STR);
    }

    p = hdr_append;
    /* expires header */
    memcpy(p, "Expires: ", 9);
    p += 9;
    memcpy(p, lexpire_s, lexpire_len);
    p += lexpire_len;
    memcpy(p, CRLF, CRLF_LEN);
    p += CRLF_LEN;
    /* contact header */
    memcpy(p, "Contact: <", 10);
    p += 10;
    memcpy(p, local_contact->s, local_contact->len);
    p += local_contact->len;
    if (msg->rcv.proto != PROTO_UDP) {
        memcpy(p, ";transport=", 11);
        p += 11;
        p = proto2str(msg->rcv.proto, p);
        if (p == NULL) {
            LM_ERR("invalid proto\n");
            goto error;
        }
    }
    *(p++) = '>';
    memcpy(p, CRLF, CRLF_LEN);
    p += CRLF_LEN;

    if (add_lump_rpl(msg, hdr_append, p - hdr_append, LUMP_RPL_HDR) == 0) {
        LM_ERR("unable to add lump_rl\n");
        goto error;
    }

    if (sigb.reply(msg, reply_code, &su_200_rpl, rtag) == -1) {
        LM_ERR("sending reply\n");
        goto error;
    }

    pkg_free(hdr_append);
    return 0;

    error:
    if (hdr_append)
        pkg_free(hdr_append);
    return -1;
}

int delete_db_subs(str pres_uri, str ev_stored_name, str to_tag) {
//	static db_ps_t my_ps = NULL;
    db_key_t query_cols[5];
    db_val_t query_vals[5];
    int n_query_cols = 0;

    query_cols[n_query_cols] = &str_presentity_uri_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = pres_uri;
    n_query_cols++;

    query_cols[n_query_cols] = &str_event_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = ev_stored_name;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_tag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = to_tag;
    n_query_cols++;

    //char* presuri = pkg_malloc(pres_uri.len + 1);
    char presuri[pres_uri.len + 1];
    strncpy(presuri, pres_uri.s, pres_uri.len);
    *(presuri + pres_uri.len) = '\0';
    //LM_DBG("presuri %s\n", presuri);

    /*struct timeval start, end;
     long secs_used, msec_used;
     gettimeofday(&start, NULL);
     */if (deleteResource(query_cols, query_vals, n_query_cols, SUBSCRIPTION,
                          NULL,
                          NULL) <= 0) {
        LM_ERR("sql delete failed\n");
        return -1;
    }
    /*gettimeofday(&end, NULL);
     secs_used = (end.tv_sec - start.tv_sec); //avoid overflow by subtracting first
     msec_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
     LM_WARN(" deleteResource took %ld millisecond\n", msec_used / 1000);
     */return 0;
}

int update_subs_db(subs_t *subs, int type) {

//	LM_DBG("******IN UBDATE_SUBS_DB************");
//	static db_ps_t my_ps_remote = NULL, my_ps_local = NULL;
    db_key_t query_cols[22], update_keys[8];
    db_val_t query_vals[22], update_vals[8];
    int n_update_cols = 0;
    int n_query_cols = 0;
    //int len = subs->from_user.len + subs->from_domain.len + 2;

    //char watcher_uri[len];
    /*snprintf(watcher_uri, len, "%.*s@", subs->from_user.len, subs->from_user.s);
     snprintf(watcher_uri + subs->from_user.len + 1, len, "%.*s",
     subs->from_domain.len, subs->from_domain.s);*/
    /*char temp_key[200] = "";
    char *tk = my_strcpy(temp_key, "", 0, 0);
    char *watcher_uri = tk;

    tk = my_strcpy(tk, subs->from_user.s, 1, subs->from_user.len);
    tk = my_strcpy(tk, "@", 0, 0);
    tk = my_strcpy(tk, subs->from_domain.s, 1, subs->from_domain.len);
    *tk = '\0';
*///	LM_DBG("!!!!!!!!!!!!!!!!!!!watcher_uri %s**", watcher_uri);

//

//used for mongodb
    /*char temp_value[200] = "";
    char *tv = my_strcpy(temp_value, "", 0, 0);
    char *subs_cache_value = tv;

    tv = my_strcpy(tv, subs->to_tag.s, 1, subs->to_tag.len);
    tv = my_strcpy(tv, ":", 0, 0);
    tv = my_strcpy(tv, subs->from_tag.s, 1, subs->from_tag.len);
    tv = my_strcpy(tv, ":", 0, 0);
    tv = my_strcpy(tv, subs->callid.s, 1, subs->callid.len);
    *tv = '\0';


    unsigned int hash = get_hash(temp_value);


    LM_DBG("\n*********************\n\n\n%du\n*********************\n\n\n\n",
            hash);

    query_cols[n_query_cols] = &str__id_col;
    query_vals[n_query_cols].type = DB_BITMAP;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.bitmap_val = hash;
    n_query_cols++;*/

    query_cols[n_query_cols] = &str_presentity_uri_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = subs->pres_uri;
    n_query_cols++;

    query_cols[n_query_cols] = &str_watcher_username_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = subs->from_user;
    n_query_cols++;

    query_cols[n_query_cols] = &str_watcher_domain_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = subs->from_domain;
    n_query_cols++;
    //

    query_cols[n_query_cols] = &str_event_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->event->name;
    n_query_cols++;

    query_cols[n_query_cols] = &str_event_id_col;
    query_vals[n_query_cols].type = DB_STR;

    if (subs->event_id.s) {
        query_vals[n_query_cols].val.str_val = subs->event_id;
    } else {
        query_vals[n_query_cols].val.str_val.s = "";
        query_vals[n_query_cols].val.str_val.len = 0;
    }
    n_query_cols++;

    query_cols[n_query_cols] = &str_callid_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->callid;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_tag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->to_tag;
    n_query_cols++;

    query_cols[n_query_cols] = &str_from_tag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->from_tag;
    n_query_cols++;

    if (type & REMOTE_TYPE) {
        update_keys[n_update_cols] = &str_expires_col;
        update_vals[n_update_cols].type = DB_INT;
        update_vals[n_update_cols].val.int_val = subs->expires
                                                 + (int) time(NULL);
        n_update_cols++;

        update_keys[n_update_cols] = &str_remote_cseq_col;
        update_vals[n_update_cols].type = DB_INT;
        update_vals[n_update_cols].val.int_val = subs->remote_cseq;
        n_update_cols++;

        update_keys[n_update_cols] = &str_contact_col;
        update_vals[n_update_cols].type = DB_STR;
        update_vals[n_update_cols].val.str_val = subs->contact;
        n_update_cols++;

    } else {
        update_keys[n_update_cols] = &str_local_cseq_col;
        update_vals[n_update_cols].type = DB_INT;
        update_vals[n_update_cols].val.int_val = subs->local_cseq + 1;
        n_update_cols++;

        update_keys[n_update_cols] = &str_version_col;
        update_vals[n_update_cols].type = DB_INT;
        update_vals[n_update_cols].val.int_val = subs->version + 1;
        n_update_cols++;

    }

    update_keys[n_update_cols] = &str_status_col;
    update_vals[n_update_cols].type = DB_INT;
    update_vals[n_update_cols].val.int_val = subs->status;
    n_update_cols++;

    update_keys[n_update_cols] = &str_reason_col;
    update_vals[n_update_cols].type = DB_STR;
    update_vals[n_update_cols].val.str_val = subs->reason;
    n_update_cols++;

    //char* presuri = pkg_malloc(subs->pres_uri.len + 1);
    /*char presuri[subs->pres_uri.len + 1];

    strncpy(presuri, subs->pres_uri.s, subs->pres_uri.len);
    *(presuri + subs->pres_uri.len) = '\0';
*/    //LM_DBG("UPDATING ACTIVE WATCHERS");

    /*
     struct timeval start, end;
     long secs_used, msec_used;
     gettimeofday(&start, NULL);
     */
    if (updateResource(query_cols, query_vals, update_keys, update_vals,
                       n_query_cols, n_update_cols,
                       SUBSCRIPTION, NULL, NULL) < 0) {
        LM_ERR("updating presence information\n");

        return -1;
    }
    /*
     gettimeofday(&end, NULL);
     secs_used = (end.tv_sec - start.tv_sec); //avoid overflow by subtracting first
     msec_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
     LM_WARN(" updateResource took %ld millisecond\n", msec_used / 1000);
     */
    return 0;
}

int subs_process_insert_status(subs_t *subs) {
    struct sip_uri uri;

    /*default 'pending' status */
    subs->status = PENDING_STATUS;
    subs->reason.s = NULL;
    subs->reason.len = 0;

    if (parse_uri(subs->pres_uri.s, subs->pres_uri.len, &uri) < 0) {
        LM_ERR("parsing uri\n");
        goto error;

    }
    if (subs->event->get_rules_doc(&uri.user, &uri.host, &subs->auth_rules_doc)
        < 0) {
        LM_ERR("getting rules doc\n");
        goto error;
    }

    if (subs->event->get_auth_status(subs) < 0) {
        LM_ERR("in event specific function is_watcher_allowed\n");
        goto error;
    }
    if (get_status_str(subs->status) == NULL) {
        LM_ERR("wrong status= %d\n", subs->status);
        goto error;
    }

    if (insert_db_subs_auth(subs) < 0) {
        LM_ERR("while inserting record in watchers table\n");
        goto error;
    }

    return 0;

    error:
    return -1;
}

int update_subscription(struct sip_msg *msg, subs_t *subs, int init_req) {
    /*
     struct timeval start_method, end_method;
     long secs_used_1, msec_used_1;
     gettimeofday(&start_method, NULL);
     */
//	unsigned int hash_code;
    int reply_code = 200;
    char *jsonBuffer;

    if (subs->event->type & PUBL_TYPE)
        reply_code = (subs->status == PENDING_STATUS) ? 202 : 200;

//	hash_code = core_hash(&subs->pres_uri, &subs->event->name, shtable_size);

    if (init_req == 0) /*if a SUBSCRIBE within a dialog */
    {
        if (subs->expires == 0) {
            /*	LM_DBG(
                        "expires=0, deleting subscription from [%.*s@%.*s] to [%.*s]\n",
                        subs->from_user.len, subs->from_user.s,
                        subs->from_domain.len, subs->from_domain.s,
                        subs->pres_uri.len, subs->pres_uri.s);
    */
            if (delete_db_subs(subs->pres_uri, subs->event->name, subs->to_tag)
                < 0) {
                LM_ERR("deleting subscription record from database\n");
                goto error;
            }
            /* delete record from hash table also */
            int ret = 0;

            if ((ret = deleteSubscriptionInCache(subs)) < 0) {
                LM_ERR("deleting subscription record from database\n");
                goto error;
            }

            subs->local_cseq = ret;

            if (send_2XX_reply(msg, reply_code, subs->expires, 0,
                               &subs->local_contact) < 0) {
                LM_ERR("sending %d OK\n", reply_code);
                goto error;
            }

            goto send_notify;
        }
        //LM_DBG("_______SUBS WITHIN DIALOG :UPDATE SUBS IN DB_________");
        subs->expires += expires_offset;



            if (update_subs_db(subs, REMOTE_TYPE) < 0) {
                LM_ERR("updating subscription in database table\n");
                goto error;
            }


        if (send_2XX_reply(msg, reply_code, subs->expires, 0,
                           &subs->local_contact) < 0) {
            LM_ERR("sending 2XX reply\n");
            goto error;
        }

    } else {

        if (send_2XX_reply(msg, reply_code, subs->expires, &subs->to_tag,
                           &subs->local_contact) < 0) {
            LM_ERR("sending 2XX reply\n");
            goto error;
        }

        if (subs->expires != 0) {
            subs->expires += expires_offset;



            /*if (insert_shtable(subs_htable, hash_code, subs) < 0) {
             LM_ERR("inserting new record in subs_htable\n");
             goto error;
             }*/
            //LM_DBG("----------Initial SUBS:INSERT SUBS IN DB------------");
            jsonBuffer = malloc(JSON_BUF_LEN);
            if (insert_subs_db(subs, jsonBuffer) < 0) {
                LM_ERR("failed to insert subscription in database\n");
                goto error;
            }

        }
        /*otherwise there is a subscription outside a dialog with expires= 0
         * no update in database, but should try to send Notify */
    }

    /* send Notifies */
    //Not using WINFO
    send_notify:
    /*if ((subs->event->type & PUBL_TYPE) && subs->event->wipeer) {
     //LM_DBG("send Notify with winfo\n");
     if (query_db_notify(&subs->pres_uri, subs->event->wipeer,
     (subs->expires == 0) ? NULL : subs) < 0) {
     LM_ERR("Could not send notify winfo\n");
     goto error;
     }
     }*/
    //LM_INFO("notify\n");
    if (micro_srv_arch)
    {
        /*if(subs_queue_msg) {
			LM_DBG("***************Publishing to queue: %s\n",subs_queue_msg);
            publish_sub_queue(subs_queue_msg);
            pkg_free(subs_queue_msg);
        }*/
        if(jsonBuffer) {
            LM_DBG("***************Publishing to queue: %s\n",jsonBuffer);
            publish_sub_queue(jsonBuffer);
            free(jsonBuffer);
            jsonBuffer=NULL;
        }
        // First publish to queue to start NOTIFY process then insert/update cache.
        if (init_req == 0)
        {
            if (subs->expires == 0) {
                LM_DBG("Updating  in the cache.\n");
                updateSubscriptionInCache(subs, REMOTE_TYPE);
            }
        }
        else
        {
            LM_DBG("Inserting in the cache.\n");
            addSubscriptionInCache(subs, NULL, 1);
        }
    }
    else if (notify(subs, NULL, NULL, 0, NULL, 0) < 0) {
        LM_ERR("Failed to send notify request\n");
        goto error;
    }
    /*
     gettimeofday(&end_method, NULL);
     secs_used_1 = (end_method.tv_sec - start_method.tv_sec); //avoid overflow by subtracting first
     msec_used_1 = ((secs_used_1 * 1000000) + end_method.tv_usec)
     - (start_method.tv_usec);
     LM_WARN(" update_subscription  took %ld millisecond\n", msec_used_1 / 1000);
     */
    //LM_DBG("************update_subscription completed***********\n");
    if(jsonBuffer)
        free(jsonBuffer);
    return 0;

    error:
    if(jsonBuffer)
        free(jsonBuffer);
    return -1;
}

void msg_watchers_clean(unsigned int ticks, void *param) {
    db_key_t db_keys[3];
    db_val_t db_vals[3];

    //--LM_DBG("cleaning pending subscriptions\n");

    db_keys[0] = &str_inserted_time_col;
    db_vals[0].type = DB_INT;
    db_vals[0].val.int_val = (int) time(NULL) - waiting_subs_time;

    db_keys[1] = &str_status_col;
    db_vals[1].type = DB_INT;
    db_vals[1].val.int_val = PENDING_STATUS;

    if (deleteResource(db_keys, db_vals, 2, WATCHER, NULL, NULL) < 0)
        LM_ERR("cleaning pending subscriptions\n");
}

/*
 *	Function called from the script to process a SUBSCRIBE request
 *		returns:
 *				1 : success
 *				-1: error
 *		- sends a reply in all cases (success or error).
 *	TODO replace -1 return code in error case with 0 ( exit from the script)
 * */
int handle_subscribe(struct sip_msg *msg, char *force_active_param, char *str2) {

    /*struct timeval start, end;
    long secs_used, msec_used;
    gettimeofday(&start, NULL);
*/
    int init_req = 0;
    subs_t subs;
    pres_ev_t *event = NULL;
    event_t *parsed_event = NULL;
    param_t *ev_param = NULL;
    int found;
    str reason = {0, 0};
    int reply_code;
    str reply_str;
    int ret;

    /* ??? rename to avoid collisions with other symbols */
    counter++;

    memset(&subs, 0, sizeof(subs_t));

    reply_code = 400;
    reply_str = pu_400_rpl;

    if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
        LM_ERR("parsing headers\n");
        goto error;
    }

    /* inspecting the Event header field */
    if (msg->event && msg->event->body.len > 0) {
        if (!msg->event->parsed && (parse_event(msg->event) < 0)) {
            goto error;
        }
        if (((event_t *) msg->event->parsed)->parsed == EVENT_OTHER) {
            goto bad_event;
        }
    } else
        goto bad_event;

    /* search event in the list */
    parsed_event = (event_t *) msg->event->parsed;
    event = search_event(parsed_event);
    if (event == NULL) {
        goto bad_event;
    }
    subs.event = event;

    /* extract the id if any*/
    ev_param = parsed_event->params;
    while (ev_param) {
        if (ev_param->name.len == 2
            && strncasecmp(ev_param->name.s, "id", 2) == 0) {
            subs.event_id = ev_param->body;
            break;
        }
        ev_param = ev_param->next;
    }

    ret = extract_sdialog_info(&subs, msg, max_expires_subscribe, &init_req,
                               server_address);
    if (ret < 0) {
        LM_ERR("failed to extract dialog information\n");
        if (ret == -2) {
            reply_code = 500;
            reply_str = pu_500_rpl;
        }
        goto error;
    }

    /* from now one most of the possible error are due to fail in internal processing */
    reply_code = 500;
    reply_str = pu_500_rpl;

    /* getting presentity uri from Request-URI if initial subscribe - or else from database*/
    if (init_req) {
        //LM_DBG("NEW SUBSCRIPTION: FIRST CHECK*****");
        if (parsed_event->parsed != EVENT_DIALOG_SLA) {
            if (parse_sip_msg_uri(msg) < 0) {
                LM_ERR("failed to parse R-URI\n");
                reply_code = 400;
                reply_str = pu_400_rpl;
                goto error;
            }
            if (uandd_to_uri(msg->parsed_uri.user, msg->parsed_uri.host,
                             &subs.pres_uri) < 0) {
                LM_ERR("failed to construct uri from user and domain\n");
                goto error;
            }
//LABEL A
//Mark subs as active as currently not using authorization. When uncommenting this make sure to uncomment Label A below.
            subs.status = ACTIVE_STATUS;
        }
    } else {
        //LM_DBG("SUBSCRIPTION WITHIN DIALOG: FIRST CHECK*****");
        if (get_stored_info(msg, &subs, &reply_code, &reply_str) < 0) {
            LM_ERR("getting stored info\n");
            goto error;
        }
        reason = subs.reason;
    }

    /* call event specific subscription handling */
    if (event->evs_subs_handl) {
        if (event->evs_subs_handl(msg) < 0) {
            LM_ERR("in event specific subscription handling\n");
            goto error;
        }
    }

    /* if dialog initiation Subscribe - get subscription state */
//LABEL A
//Mark subs as active as currently not using authorization. When uncommenting this make sure to comment Label A above.
    /*
     if (init_req) {
     //LM_DBG("NEW SUBSCRIPTION: SECOND CHECK*****");
     if (!event->req_auth
     || (force_active_param && force_active_param[0] == '1'))
     subs.status = ACTIVE_STATUS;
     else {
     */
    /* query in watchers_table - if negative reply - server error *//*


	 if (get_db_subs_auth(&subs, &found) < 0) {
	 LM_ERR("getting subscription status from watchers table\n");
	 goto error;
	 }
	 if (found == 0) {
	 if (subs_process_insert_status(&subs) < 0) {
	 LM_ERR(
	 "Failed to extract and insert authorization status\n");
	 goto error;
	 }
	 } else {
	 reason = subs.reason;
	 }
	 }
	 }
	 */

    /* check if correct status */
    if (get_status_str(subs.status) == NULL) {
        LM_ERR("wrong status\n");
        goto error;
    }
    /*LM_DBG("subscription status= %s - %s\n", get_status_str(subs.status),
            found == 0 ? "inserted" : "found in watcher table");
*/
    if (update_subscription(msg, &subs, init_req) < 0) {
        LM_ERR("in update_subscription\n");
        goto error_free;
    }
    if (subs.auth_rules_doc) {
        pkg_free(subs.auth_rules_doc->s);
        pkg_free(subs.auth_rules_doc);
    }
    if (reason.s)
        pkg_free(reason.s);

    if (subs.pres_uri.s)
        pkg_free(subs.pres_uri.s);
    if (subs.record_route.s)
        pkg_free(subs.record_route.s);

/*
	gettimeofday(&end, NULL);
	secs_used = (end.tv_sec - start.tv_sec); //avoid overflow by subtracting first
	msec_used = ((secs_used * 1000000) + end.tv_usec) - (start.tv_usec);
	LM_WARN(" HANDLE_SUBSCRIBE took %ld millisecond\n", msec_used / 1000);
*/

//	LM_DBG("************HANDLE_SUBSCRIBE completed***********\n");

    return 1;

    bad_event:

    LM_INFO("Missing or unsupported event header field value\n");

    if (parsed_event && parsed_event->text.s)
        LM_INFO("\tevent= %.*s\n", parsed_event->text.len,
                parsed_event->text.s);

    reply_code = BAD_EVENT_CODE;
    reply_str = pu_489_rpl;

    error:
    if (send_error_reply(msg, reply_code, reply_str) < 0) {
        LM_ERR("failed to send reply on error case\n");
    }
    error_free:
    if (subs.pres_uri.s)
        pkg_free(subs.pres_uri.s);
    if (subs.auth_rules_doc) {
        if (subs.auth_rules_doc->s)
            pkg_free(subs.auth_rules_doc->s);
        pkg_free(subs.auth_rules_doc);
    }
    if (reason.s)
        pkg_free(reason.s);
    if (subs.record_route.s)
        pkg_free(subs.record_route.s);

    LM_INFO("************HANDLE_SUBSCRIBE -1 completed***********\n");
    return -1;
}

int extract_sdialog_info(subs_t *subs, struct sip_msg *msg, int mexp,
                         int *init_req, str local_address) {
    str rec_route = {0, 0};
    int rt = 0;
    contact_body_t *b;
    struct to_body *pto, *pfrom = NULL;
    int lexpire;
    struct sip_uri uri;
    int err_ret = -1;

    /* examine the expire header field */
    if (msg->expires && msg->expires->body.len > 0) {
        if (!msg->expires->parsed && (parse_expires(msg->expires) < 0)) {
            LM_ERR("cannot parse Expires header\n");
            goto error;
        }
        lexpire = ((exp_body_t *) msg->expires->parsed)->val;
        //--LM_DBG("'Expires' header found, value= %d\n", lexpire);

    } else {
        /*LM_DBG("'expires' not found; default=%d\n",
                subs->event->default_expires);*/
        lexpire = subs->event->default_expires;
    }
    if (lexpire > mexp)
        lexpire = mexp;

    subs->expires = lexpire;

    if ((!msg->to && parse_headers(msg, HDR_TO_F, 0) < 0) || !msg->to) {
        LM_ERR("bad request or missing TO hdr\n");
        goto error;
    }

    pto = get_to(msg);
    if (pto == NULL || pto->error != PARSE_OK) {
        LM_ERR("failed to parse TO header\n");
        goto error;
    }

    if (pto->parsed_uri.user.s && pto->parsed_uri.host.s
        && pto->parsed_uri.user.len && pto->parsed_uri.host.len) {
        subs->to_user = pto->parsed_uri.user;
        subs->to_domain = pto->parsed_uri.host;
    } else {
        if (parse_uri(pto->uri.s, pto->uri.len, &uri) < 0) {
            LM_ERR("while parsing uri\n");
            goto error;
        }
        subs->to_user = uri.user;
        subs->to_domain = uri.host;
    }

    /* examine the from header */
    if (!msg->from || !msg->from->body.s) {
        LM_ERR("cannot find 'from' header!\n");
        goto error;
    }
    if (msg->from->parsed == NULL) {
        //LM_DBG("'From' header not parsed\n");
        /* parsing from header */
        if (parse_from_header(msg) < 0) {
            LM_ERR("cannot parse From header\n");
            goto error;
        }
    }
    pfrom = (struct to_body *) msg->from->parsed;

    if (pfrom->parsed_uri.user.s && pfrom->parsed_uri.host.s
        && pfrom->parsed_uri.user.len && pfrom->parsed_uri.host.len) {
        subs->from_user = pfrom->parsed_uri.user;
        subs->from_domain = pfrom->parsed_uri.host;

    } else {
        if (parse_uri(pfrom->uri.s, pfrom->uri.len, &uri) < 0) {
            LM_ERR("while parsing uri\n");
            goto error;
        }
        subs->from_user = uri.user;
        subs->from_domain = uri.host;

    }

    /*check if the message is an initial request */
    if (pto->tag_value.s == NULL || pto->tag_value.len == 0) {
        //LM_DBG("initial request\n");
        *init_req = 1;
    } else {
        //LM_DBG("request in dialog\n");
        subs->to_tag = pto->tag_value;
        *init_req = 0;
    }
    if (msg->callid == NULL || msg->callid->body.s == NULL) {
        LM_ERR("cannot parse callid header\n");
        goto error;
    }
    subs->callid = msg->callid->body;

    if (msg->cseq == NULL || msg->cseq->body.s == NULL) {
        LM_ERR("cannot parse cseq header\n");
        goto error;
    }
    if (str2int(&(get_cseq(msg)->number), &subs->remote_cseq) != 0) {
        LM_ERR("cannot parse cseq number\n");
        goto error;
    }
    if (msg->contact == NULL || msg->contact->body.s == NULL) {
        LM_ERR("cannot parse contact header\n");
        goto error;
    }
    if (parse_contact(msg->contact) < 0) {
        LM_ERR(" cannot parse contact" " header\n");
        goto error;
    }
    b = (contact_body_t *) msg->contact->parsed;

    if (b == NULL) {
        LM_ERR("cannot parse contact header\n");
        goto error;
    }
    subs->contact = b->contacts->uri;

    /*LM_DBG("subs->contact= %.*s - len = %d\n", subs->contact.len,
            subs->contact.s, subs->contact.len);
*/
    if (subs->event->evp->parsed == EVENT_DIALOG_SLA) {
        //LM_DBG("_____________IN EVENT_DIALOG_SLA");
        pv_value_t tok;
        /* if pseudovaraible set use that value */
        if (bla_presentity_spec_param.s) /* if parameter defined */
        {
            memset(&tok, 0, sizeof(pv_value_t));
            if (pv_get_spec_value(msg, &bla_presentity_spec, &tok) < 0) /* if value set */
            {
                LM_ERR("Failed to get bla_presentity value\n");
                goto error;
            }
            if (!(tok.flags & PV_VAL_STR)) {
                LM_ERR("Wrong value in bla_presentity pvar\n");
                goto error;
            }
            if (parse_uri(tok.rs.s, tok.rs.len, &uri) < 0) {
                LM_ERR("Not a valid value, must be a uri [%.*s]\n", tok.rs.len,
                       tok.rs.s);
                goto error;
            }
            if (uandd_to_uri(uri.user, uri.host, &subs->pres_uri) < 0) {
                LM_ERR("failed to construct uri\n");
                goto error;
            }

        } else {
            //LM_DBG("_____________IN EVENT_DIALOG_SLA ELSE___________");
//			LM_DBG("subs->contact= %.*s - len = %d\n", subs->contact.len,subs->contact.s, subs->contact.len);
            /* user_contact@from_domain */
            if (parse_uri(subs->contact.s, subs->contact.len, &uri) < 0) {
                LM_ERR("failed to parse contact uri\n");
                goto error;
            }
//			LM_DBG("uri.user= %s \n", uri.user.s);
//			LM_DBG("subs->from_domain= %s \n", subs->from_domain.s);

            if (uandd_to_uri(uri.user, subs->from_domain, &subs->pres_uri)
                < 0) {
                LM_ERR("failed to construct uri\n");
                goto error;
            }
//			LM_DBG("subs->pres_uri= %s \n", subs->pres_uri.s);
        }
    }

    /*process record route and add it to a string*/
    if (*init_req && msg->record_route != NULL) {
        rt = print_rr_body(msg->record_route, &rec_route, 0, 0);
        if (rt != 0) {
            LM_ERR("processing the record route [%d]\n", rt);
            rec_route.s = NULL;
            rec_route.len = 0;
            //	goto error;
        }
    }
    subs->record_route = rec_route;

    subs->sockinfo = msg->rcv.bind_address;

    if (pfrom->tag_value.s == NULL || pfrom->tag_value.len == 0) {
        LM_ERR("no from tag value present\n");
        goto error;
    }
    subs->from_tag = pfrom->tag_value;

    subs->version = 0;

    if (!local_address.s || !local_address.len) {
        if (get_local_contact(msg->rcv.bind_address, &subs->local_contact)
            < 0) {
            LM_ERR("in function get_local_contact\n");
            err_ret = -2;
            goto error;
        }
    } else
        subs->local_contact = local_address;
    return 0;
    error:
    return err_ret;
    /*
     *  -1 - bad message
     *  -2 - internal error
     * */
}

/*
 * function that queries 'active_watchers' table for stored subscription dialog
 *	- sets reply_code and reply_str in error case if different than server error
 * */
int get_stored_info(struct sip_msg *msg, subs_t *subs, int *reply_code,
                    str *reply_str) {

    if (checkSusbcriptionInCache(subs) <= 0) {
        //LM_DBG("Check Database.\n");
        return get_database_info(msg, subs, reply_code, reply_str);
    }
    return 1;

}

int get_database_info(struct sip_msg *msg, subs_t *subs, int *reply_code,
                      str *reply_str) {

    //LM_DBG("In get_database_info.");
//	static db_ps_t my_ps = NULL;
    db_key_t query_cols[10], return_cols[10];
    db_val_t query_vals[10];
//	db_key_t result_cols[9];
    db_res_t *result = NULL;
    db_row_t *row;
    db_val_t *row_vals;
    int n_query_cols = 0;
    int n_result_cols = 0;
    int remote_cseq_col = 0, local_cseq_col = 0, status_col, reason_col;
    int record_route_col, version_col;
    int pres_uri_col;
    unsigned int remote_cseq;
    str pres_uri, record_route;
    str reason;
    /*
     int len = subs->to_user.len + subs->to_domain.len + 2;

     len = subs->from_user.len + subs->from_domain.len + 2;
     char watcher_uri[len];


     snprintf(watcher_uri, len, "%.*s@", subs->from_user.len, subs->from_user.s);
     snprintf(watcher_uri + subs->from_user.len + 1, len, "%.*s",
     subs->from_domain.len, subs->from_domain.s);
     */
    /*char temp_key[200] = "";
    char *tk = my_strcpy(temp_key, "", 0, 0);
    char *watcher_uri = tk;

    tk = my_strcpy(tk, subs->from_user.s, 1, subs->from_user.len);
    tk = my_strcpy(tk, "@", 0, 0);
    tk = my_strcpy(tk, subs->from_domain.s, 1, subs->from_domain.len);
    *tk = '\0';
*///	LM_DBG("!!!!!!!!!!!!!!!!!!!watcher_uri %s**", watcher_uri);

    query_cols[n_query_cols] = &str_watcher_username_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = subs->from_user;
    n_query_cols++;

    query_cols[n_query_cols] = &str_watcher_domain_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = subs->from_domain;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_user_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->to_user;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_domain_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->to_domain;
    n_query_cols++;
    query_cols[n_query_cols] = &str_event_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->event->name;
    n_query_cols++;

    query_cols[n_query_cols] = &str_event_id_col;
    query_vals[n_query_cols].type = DB_STR;
    if (subs->event_id.s != NULL) {
        query_vals[n_query_cols].val.str_val.s = subs->event_id.s;
        query_vals[n_query_cols].val.str_val.len = subs->event_id.len;
    } else {
        query_vals[n_query_cols].val.str_val.s = "";
        query_vals[n_query_cols].val.str_val.len = 0;
    }
    n_query_cols++;

    query_cols[n_query_cols] = &str_callid_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->callid;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_tag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->to_tag;
    n_query_cols++;

    query_cols[n_query_cols] = &str_from_tag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = subs->from_tag;
    n_query_cols++;

    return_cols[n_result_cols] = &str_presentity_uri_col;
    pres_uri_col = n_result_cols++;

    return_cols[n_result_cols] = &str_local_cseq_col;
    local_cseq_col = n_result_cols++;

    return_cols[n_result_cols] = &str_remote_cseq_col;
    remote_cseq_col = n_result_cols++;

    return_cols[n_result_cols] = &str_status_col;
    status_col = n_result_cols++;

    return_cols[n_result_cols] = &str_reason_col;
    reason_col = n_result_cols++;

    return_cols[n_result_cols] = &str_record_route_col;
    record_route_col = n_result_cols++;

    return_cols[n_result_cols] = &str_version_col;
    version_col = n_result_cols++;

    if (getResource(query_cols, query_vals, n_query_cols, &result, SUBSCRIPTION,
                    NULL, NULL, return_cols, n_result_cols) < 0) {
        LM_ERR("querying subscription dialog\n");
        if (result)
            free_result(result);
//		pkg_free(watcher_uri);
        return -1;
    }
//	pkg_free(watcher_uri);
    if (result == NULL)
        return -1;

    if (result && result->n <= 0) {
        LM_ERR("No matching subscription dialog found in database\n");

        free_result(result);
        *reply_code = 481;
        *reply_str = pu_481_rpl;

        return -1;
    }

    row = &result->rows[0];
    row_vals = ROW_VALUES(row);
    remote_cseq = row_vals[remote_cseq_col].val.int_val;

    if (subs->remote_cseq <= remote_cseq) {
        LM_ERR("wrong sequence number received: %d - stored: %d\n",
               subs->remote_cseq, remote_cseq);
        *reply_code = 400;
        *reply_str = pu_400_rpl;
        free_result(result);
        return -1;
    }

    subs->status = row_vals[status_col].val.int_val;
    reason.s = (char *) row_vals[reason_col].val.string_val;
    if (reason.s) {
        reason.len = strlen(reason.s);
        subs->reason.s = (char *) pkg_malloc(reason.len);
        if (subs->reason.s == NULL) {
            ERR_MEM(PKG_MEM_STR);
        }
        memcpy(subs->reason.s, reason.s, reason.len);
        subs->reason.len = reason.len;
    }

    subs->local_cseq = row_vals[local_cseq_col].val.int_val;
    subs->version = row_vals[version_col].val.int_val;

    if (subs->event->evp->parsed != EVENT_DIALOG_SLA) {
        pres_uri.s = (char *) row_vals[pres_uri_col].val.string_val;
        pres_uri.len = strlen(pres_uri.s);
        subs->pres_uri.s = (char *) pkg_malloc(pres_uri.len);
        if (subs->pres_uri.s == NULL) {
            if (subs->reason.s)
                pkg_free(subs->reason.s);
            ERR_MEM(PKG_MEM_STR);
        }
        memcpy(subs->pres_uri.s, pres_uri.s, pres_uri.len);
        subs->pres_uri.len = pres_uri.len;
    }

    record_route.s = (char *) row_vals[record_route_col].val.string_val;
    if (record_route.s) {
        record_route.len = strlen(record_route.s);
        subs->record_route.s = (char *) pkg_malloc(record_route.len);
        if (subs->record_route.s == NULL) {
            ERR_MEM(PKG_MEM_STR);
        }
        memcpy(subs->record_route.s, record_route.s, record_route.len);
        subs->record_route.len = record_route.len;
    }

    free_result(result);
    result = NULL;

    return 0;
    error:
    if (result)
        free_result(result);

    return -1;
}

int handle_expired_subs(subs_t *s) {
    if (s->event->mandatory_timeout_notification) {
        /* send Notify with state=terminated;reason=timeout */
        s->status = TERMINATED_STATUS;
        s->reason.s = "timeout";
        s->reason.len = 7;
        s->expires = 0;

        LM_INFO("notify\n");
        if (send_notify_request(s, NULL, NULL, 1, NULL, 0) < 0) {
            LM_ERR("send Notify not successful\n");
            return -1;
        }
    }

    return 0;
}

void timer_db_update(unsigned int ticks, void *param) {
    /*int no_lock = 0;

     if (ticks == 0 && param == NULL)
     no_lock = 1;
     */

    db_key_t update_cols[1];
    db_val_t update_vals[1];
    //--LM_DBG("delete expired\n");
    update_cols[0] = &str_expires_col;
    update_vals[0].type = DB_INT;
    update_vals[0].val.int_val = (int) time(NULL);

    if (deleteResource(update_cols, update_vals, 1, SUBSCRIPTION, NULL, NULL)
        < 0)
        LM_ERR("deleting expired information from database\n");

//	update_db_subs(subs_htable, shtable_size, no_lock, handle_expired_subs);

}



int insert_subs_db(subs_t *s, char* jsonBuffer) {
//	static db_ps_t my_ps = NULL;
    db_key_t query_cols[22];
    db_val_t query_vals[22];
    int n_query_cols = 0;

    //used for mongodb
    /*char temp_value[200] = "";
    char *tv = my_strcpy(temp_value, "", 0, 0);
    char *subs_cache_value = tv;

    tv = my_strcpy(tv, s->to_tag.s, 1, s->to_tag.len);
    tv = my_strcpy(tv, ":", 0, 0);
    tv = my_strcpy(tv, s->from_tag.s, 1, s->from_tag.len);
    tv = my_strcpy(tv, ":", 0, 0);
    tv = my_strcpy(tv, s->callid.s, 1, s->callid.len);
    *tv = '\0';


    unsigned int hash = get_hash(temp_value);

    LM_DBG("\n*********************\n\n\n%d\n*********************\n\n\n\n",hash);
    query_cols[n_query_cols] = &str__id_col;
    query_vals[n_query_cols].type = DB_BITMAP;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.bitmap_val = hash;
    n_query_cols++;*/

    query_cols[n_query_cols] = &str_presentity_uri_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->pres_uri;
    n_query_cols++;

    query_cols[n_query_cols] = &str_callid_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->callid;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_tag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->to_tag;
    n_query_cols++;

    query_cols[n_query_cols] = &str_from_tag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->from_tag;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_user_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->to_user;
    n_query_cols++;

    query_cols[n_query_cols] = &str_to_domain_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->to_domain;
    n_query_cols++;

    query_cols[n_query_cols] = &str_watcher_username_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->from_user;
    n_query_cols++;

    query_cols[n_query_cols] = &str_watcher_domain_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->from_domain;
    n_query_cols++;

    query_cols[n_query_cols] = &str_event_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->event->name;
    n_query_cols++;

    query_cols[n_query_cols] = &str_event_id_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->event_id;
    n_query_cols++;

    query_cols[n_query_cols] = &str_local_cseq_col;
    query_vals[n_query_cols].type = DB_INT;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.int_val = s->local_cseq;
    n_query_cols++;

    query_cols[n_query_cols] = &str_remote_cseq_col;
    query_vals[n_query_cols].type = DB_INT;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.int_val = s->remote_cseq;
    n_query_cols++;

    query_cols[n_query_cols] = &str_expires_col;
    query_vals[n_query_cols].type = DB_INT;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.int_val = s->expires + (int) time(NULL);
    n_query_cols++;

    query_cols[n_query_cols] = &str_status_col;
    query_vals[n_query_cols].type = DB_INT;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.int_val = s->status;
    n_query_cols++;

    query_cols[n_query_cols] = &str_reason_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->reason;
    n_query_cols++;

    query_cols[n_query_cols] = &str_record_route_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->record_route;
    n_query_cols++;

    query_cols[n_query_cols] = &str_contact_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->contact;
    n_query_cols++;

    query_cols[n_query_cols] = &str_local_contact_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = s->local_contact;
    n_query_cols++;

    query_cols[n_query_cols] = &str_version_col;
    query_vals[n_query_cols].type = DB_INT;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.int_val = s->version;
    n_query_cols++;

    query_cols[n_query_cols] = &str_socket_info_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    if (s->sockinfo)
        query_vals[n_query_cols].val.str_val = s->sockinfo->sock_str;
    else {
        query_vals[n_query_cols].val.str_val.s = 0;
        query_vals[n_query_cols].val.str_val.len = 0;
    }
    n_query_cols++;

//	LM_DBG("BEFORE INSERT IN ACTIVE WATCHERS.\n");
//	insert into active_watchers (presentity_uri,callid,to_tag,from_tag,to_user,to_domain,watcher_username,"
// "watcher_domain,event,event_id,local_cseq,remote_cseq,expires,status,reason,record_route,contact,local_contact,version,socket_info )
    if (insertResource(query_cols, query_vals, n_query_cols, SUBSCRIPTION, NULL,jsonBuffer)
        <= 0) {
        LM_ERR("unsuccessful sql insert\n");
        return -1;
    }

    return 0;
}

int insert_db_subs_auth(subs_t *subs) {
//	static db_ps_t my_ps = NULL;
    db_key_t db_keys[10];
    db_val_t db_vals[10];
    int n_query_cols = 0;

    db_keys[n_query_cols] = &str_presentity_uri_col;
    db_vals[n_query_cols].type = DB_STR;
    db_vals[n_query_cols].val.str_val = subs->pres_uri;
    n_query_cols++;

    db_keys[n_query_cols] = &str_watcher_username_col;
    db_vals[n_query_cols].type = DB_STR;
    db_vals[n_query_cols].val.str_val = subs->from_user;
    n_query_cols++;

    db_keys[n_query_cols] = &str_watcher_domain_col;
    db_vals[n_query_cols].type = DB_STR;
    db_vals[n_query_cols].val.str_val = subs->from_domain;
    n_query_cols++;

    db_keys[n_query_cols] = &str_event_col;
    db_vals[n_query_cols].type = DB_STR;
    db_vals[n_query_cols].val.str_val = subs->event->name;
    n_query_cols++;

    db_keys[n_query_cols] = &str_status_col;
    db_vals[n_query_cols].type = DB_INT;
    db_vals[n_query_cols].val.int_val = subs->status;
    n_query_cols++;

    db_keys[n_query_cols] = &str_inserted_time_col;
    db_vals[n_query_cols].type = DB_INT;
    db_vals[n_query_cols].val.int_val = (int) time(NULL);
    n_query_cols++;

    db_keys[n_query_cols] = &str_reason_col;
    db_vals[n_query_cols].type = DB_STR;

    if (subs->reason.s && subs->reason.len) {
        db_vals[n_query_cols].val.str_val = subs->reason;
    } else {
        db_vals[n_query_cols].val.str_val.s = "";
        db_vals[n_query_cols].val.str_val.len = 0;
    }
    n_query_cols++;
    //LM_DBG("BEFORE INSERT IN WATCHERS.\n");
//insert into watchers (presentity_uri,watcher_username,watcher_domain,event,status,inserted_time,reason )
    if (insertResource(db_keys, db_vals, n_query_cols, WATCHER, NULL, NULL) <= 0) {
        LM_ERR("Inserting watcher in database.\n");
        return -1;
    }
    //LM_DBG("AFTER INSERT IN WATCHERS.\n");

    return 0;
}
