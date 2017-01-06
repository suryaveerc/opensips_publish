/*
 * $Id: presentity.c 10354 2013-11-20 18:40:16Z opensipsrelease $
 *
 * presence module - presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 *
 * This file is part of opensips, a free SIP server.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../db/db.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../str.h"
#include "../../receive.h"
#include "../../usr_avp.h"
#include "../alias_db/alias_db.h"
#include "../../data_lump_rpl.h"
#include "presentity.h"
#include "presence.h" 
#include "notify.h"
#include "publish.h"
#include "hash.h"
#include "utils_func.h"
#include "RepositoryHandler.h"
#include "Util.h"
#include "Common.h"
#include "RedisDBUtils.h"
#include "queue_publisher.h"

#define DLG_STATES_NO  4
char *dialog_states[] = {"trying", "early", "confirmed", "terminated"};
char *presence_notes[] = {"Calling", "Calling", "On the phone", ""};

unsigned char *xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name);

xmlNodePtr xmlNodeGetNodeByName(xmlNodePtr node, const char *name,
                                const char *ns);

static str pu_200_rpl = str_init("OK");
static str pu_412_rpl = str_init("Conditional request failed");

static char etag_buf[ETAG_LEN];

redisReply *reply;

int generate_ETag(int publ_count, str *etag) {
    etag->s = etag_buf;
    memset(etag_buf, 0, ETAG_LEN);

    etag->len = sprintf(etag_buf, "%c.%d.%d.%d.%d", prefix, (int) startup_time,
                        pid, counter, publ_count);
    if (etag->len < 0) {
        LM_ERR("unsuccessfull sprintf\n ");
        return -1;
    }
    if (etag->len > ETAG_LEN) {
        LM_ERR("buffer size overflown\n");
        return -1;
    }
    //--LM_DBG("etag= %.*s\n", etag->len, etag->s);
    return 0;
}

int publ_send200ok(struct sip_msg *msg, int lexpire, str etag) {
    char buf[128];
    int buf_len = 128, size;
    str hdr_append = {0, 0}, hdr_append2 = {0, 0};

    //--LM_DBG("send 200OK reply, etag= %.*s\n", etag.len, etag.s);

    hdr_append.s = buf;
    hdr_append.s[0] = '\0';

    hdr_append.len = sprintf(hdr_append.s, "Expires: %d\r\n",
                             ((lexpire < expires_offset) ? 0 : (lexpire - expires_offset)));
    if (hdr_append.len < 0) {
        LM_ERR("unsuccessful sprintf\n");
        goto error;
    }
    if (hdr_append.len > buf_len) {
        LM_ERR("buffer size overflown\n");
        goto error;
    }
    hdr_append.s[hdr_append.len] = '\0';

    if (add_lump_rpl(msg, hdr_append.s, hdr_append.len, LUMP_RPL_HDR) == 0) {
        LM_ERR("unable to add lump_rl\n");
        goto error;
    }

    size = 20 + etag.len;
    hdr_append2.s = (char *) pkg_malloc(size);
    if (hdr_append2.s == NULL) {
        ERR_MEM(PKG_MEM_STR);
    }
    hdr_append2.s[0] = '\0';
    hdr_append2.len = sprintf(hdr_append2.s, "SIP-ETag: %.*s\r\n", etag.len,
                              etag.s);
    if (hdr_append2.len < 0) {
        LM_ERR("unsuccessful sprintf\n ");
        goto error;
    }
    if (hdr_append2.len + 1 > size) {
        LM_ERR("buffer size overflown\n");
        goto error;
    }

    hdr_append2.s[hdr_append2.len] = '\0';
    if (add_lump_rpl(msg, hdr_append2.s, hdr_append2.len, LUMP_RPL_HDR) == 0) {
        LM_ERR("unable to add lump_rl\n");
        goto error;
    }

    if (sigb.reply(msg, 200, &pu_200_rpl, 0) == -1) {
        LM_ERR("sending reply\n");
        goto error;
    }

    pkg_free(hdr_append2.s);
    return 0;

    error:

    if (hdr_append2.s)
        pkg_free(hdr_append2.s);

    return -1;
}

xmlAttrPtr xmlNodeGetAttrByName(xmlNodePtr node, const char *name) {
    xmlAttrPtr attr = node->properties;
    while (attr) {
        if (xmlStrcasecmp(attr->name, (unsigned char *) name) == 0)
            return attr;
        attr = attr->next;
    }
    return NULL;
}

unsigned char *xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name) {
    xmlAttrPtr attr = xmlNodeGetAttrByName(node, name);
    if (attr)
        return xmlNodeGetContent(attr->children);
    else
        return NULL;
}

xmlNodePtr xmlNodeGetChildByName(xmlNodePtr node, const char *name) {
    xmlNodePtr cur = node->children;
    while (cur) {
        if (xmlStrcasecmp(cur->name, (unsigned char *) name) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

#define bla_extract_dlginfo(node, callid, fromtag, totag) \
    do {\
    callid  = xmlNodeGetAttrContentByName(node, "call-id");\
    dir     = xmlNodeGetAttrContentByName(node, "direction");\
    if(dir == NULL) {\
        LM_ERR("Dialog direction not specified\n");\
        goto error;\
    }\
    if(xmlStrcasecmp(dir, (unsigned char*)"initiator") == 0) {\
        fromtag = xmlNodeGetAttrContentByName(node, "local-tag");\
        totag   = xmlNodeGetAttrContentByName(node, "remote-tag");\
    } else {\
        totag   = xmlNodeGetAttrContentByName(node, "local-tag");\
        fromtag = xmlNodeGetAttrContentByName(node, "remote-tag");\
    }\
    xmlFree(dir);\
    dir = NULL;\
    }while(0)

int bla_same_dialog(unsigned char *n_callid, unsigned char *n_fromtag,
                    unsigned char *n_totag, unsigned char *o_callid,
                    unsigned char *o_fromtag, unsigned char *o_totag) {
    if (n_callid && o_callid && xmlStrcasecmp(n_callid, o_callid))
        return 0;
    if (n_fromtag && o_fromtag && xmlStrcasecmp(n_fromtag, o_fromtag))
        return 0;
    if (n_totag && o_totag && xmlStrcasecmp(n_totag, o_totag))
        return 0;
    return 1;
}

int dialog_fix_remote_target(str *body, str *fixed_body) {
    xmlDocPtr doc = NULL;
    xmlNodePtr n_dlg_node;
    xmlNodePtr remote_node;
    xmlNodePtr identity_node;
    xmlNodePtr node;
    xmlErrorPtr xml_error;
    unsigned char *attr;

    if (!fixed_body) {
        LM_ERR("invalid NULL fixed_body pointer\n");
        goto error;
    }

    doc = xmlParseMemory(body->s, body->len);
    if (!doc) {
        xml_error = xmlGetLastError();
        LM_ERR("Failed to parse xml dialog body: %s\n",
               xml_error ? xml_error->message : "unknown error");
        goto error;
    }

    n_dlg_node = xmlNodeGetChildByName(doc->children, "dialog");
    for (; n_dlg_node; n_dlg_node = n_dlg_node->next) {
        if (xmlStrcasecmp(n_dlg_node->name, (unsigned char *) "dialog") != 0)
            continue;

        /* change the remote target - don't let it pass contact on the other side */
        remote_node = xmlNodeGetChildByName(n_dlg_node, "remote");
        if (remote_node) {
            node = xmlNodeGetChildByName(remote_node, "target");
            if (node) {
                xmlUnlinkNode(node);
                xmlFreeNode(node);
                /* add another target node */
                identity_node = xmlNodeGetChildByName(remote_node, "identity");
                if (identity_node == NULL) {
                    LM_ERR("No remote identity node found\n");
                    goto error;
                }
                attr = xmlNodeGetContent(identity_node);
                if (attr == NULL) {
                    LM_ERR("No identity node content\n");
                    goto error;
                }
                node = xmlNewChild(remote_node, 0, (unsigned char *) "target",
                                   0);
                if (node == NULL) {
                    LM_ERR("Failed to add new node target\n");
                    xmlFree(attr);
                    goto error;
                }
                xmlNewProp(node, BAD_CAST
                "uri", attr);
                xmlFree(attr);
            }
        }
    }

    xmlDocDumpMemory(doc, (xmlChar * *)(
    void *) &fixed_body->s,
            &fixed_body->len);

    xmlFreeDoc(doc);

    return 0;

    error:
    if (doc)
        xmlFreeDoc(doc);

    return -1;
}

int get_dialog_state(str body, int *dialog_state) {
    xmlDocPtr doc;
    xmlNodePtr node;
    unsigned char *state = NULL;
    int i;

    doc = xmlParseMemory(body.s, body.len);
    if (doc == NULL) {
        LM_ERR("failed to parse xml document\n");
        return -1;
    }

    node = doc->children;
    node = xmlNodeGetChildByName(node, "dialog");

    if (node == NULL) {
        *dialog_state = DLG_DESTROYED;
        xmlFreeDoc(doc);
        return 0;
    }

    node = xmlNodeGetChildByName(node, "state");
    if (node == NULL) {
        LM_ERR("Malformed document - no state found\n");
        goto error;
    }
    state = xmlNodeGetContent(node);
    if (state == NULL) {
        LM_ERR("Malformed document - null state\n");
        goto error;
    }
    //--LM_DBG("state = %s\n", state);
    for (i = 0; i < DLG_STATES_NO; i++) {
        if (xmlStrcasecmp(state, BAD_CAST dialog_states[i])==0) {
            break;
        }
    }
    xmlFree(state);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();

    if (i == DLG_STATES_NO) {
        LM_ERR("Wrong dialog state\n");
        return -1;
    }

    *dialog_state = i;

    return 0;
    error:
    xmlFreeDoc(doc);
    return -1;
}

int check_if_dialog(str body, int *is_dialog) {
    xmlDocPtr doc;
    xmlNodePtr node;

    doc = xmlParseMemory(body.s, body.len);
    if (doc == NULL) {
        LM_ERR("failed to parse xml document\n");
        return -1;
    }

    node = doc->children;
    node = xmlNodeGetChildByName(node, "dialog");

    if (node == NULL)
        *is_dialog = 0;
    else
        *is_dialog = 1;

    xmlFreeDoc(doc);
    return 0;
}

int update_presentity(struct sip_msg *msg, presentity_t *presentity,
                      int *sent_reply) {
    //	static db_ps_t my_ps_insert = NULL, my_ps_update_no_body = NULL,
    //		   my_ps_update_body = NULL;
    //	static db_ps_t my_ps_delete = NULL, my_ps_query = NULL;
    db_key_t query_cols[13], update_keys[8], result_cols[1];
    //db_op_t query_ops[13];
    db_val_t query_vals[13], update_vals[8];
    int n_query_cols = 0;
    int n_update_cols = 0;
    str etag = {NULL, 0};
    str notify_body = {NULL, 0};
    str cur_etag = {NULL, 0};
    str *rules_doc = NULL;
    str pres_uri = {NULL, 0};
    pres_entry_t *p = NULL;
    unsigned int hash_code;
//	unsigned int turn;
    str body = presentity->body;
    str *extra_hdrs = presentity->extra_hdrs;
    db_res_t *result = NULL;
    int return_status = 0;
    int found_in_cache = 0;
    str pres_cache_key = {NULL, 0};
    str pres_cache_value = {NULL, 0};
    char *jsonBuffer;
//	char **listFromCache;
    //int cache_record_count = 0;
    *sent_reply = 0;
    if (presentity->event->req_auth) {
        /* get rules_document */
        if (presentity->event->get_rules_doc(&presentity->user,
                                             &presentity->domain, &rules_doc)) {
            LM_ERR("getting rules doc\n");
            goto error;
        }
    }

    if (uandd_to_uri(presentity->user, presentity->domain, &pres_uri) < 0) {
        LM_ERR("constructing uri from user and domain\n");
        goto error;
    }

    if (generatePresentitySetNameValue(presentity, &pres_cache_key,
                                       &pres_cache_value, &pres_uri, NULL,
                                       GENERATE_KEY) < 0) {
        LM_ERR("Creating KV pair for presentity.\n");
        goto error;
    }

    query_cols[n_query_cols] = &str_username_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = presentity->user;
    n_query_cols++;

    query_cols[n_query_cols] = &str_domain_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = presentity->domain;

    // Assigning username & domain not working directly somehow. Using below method for moving on.
    //	get_user_from_sip_uri(query_vals[n_query_cols - 1].val.str_val.s,
    //			query_vals[n_query_cols].val.str_val.s, pres_uri.s);

    n_query_cols++;

    query_cols[n_query_cols] = &str_event_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = presentity->event->name;
    n_query_cols++;

    query_cols[n_query_cols] = &str_etag_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].val.str_val = presentity->etag;
    n_query_cols++;
    /*LM_DBG("\n\n\n---------------------key: %s\n\n",pres_cache_key.s);
    LM_DBG("\n\n\n---------------------value: %s\n\n",pres_cache_value.s);
*/
    //unsigned int hash = get_hash(pres_cache_key.s);

    result_cols[0] = &str_etag_col;

    if (presentity->etag_new) {
        LM_DBG("\n\n**************************************New Presentity*************************************\n\n");
        if (publ_send200ok(msg, presentity->expires, presentity->etag) < 0) {
            LM_ERR("sending 200OK\n");
            goto error;
        }
        *sent_reply = 1;

        /* insert new record in cache */

        if(!micro_srv_arch)
        {
            LM_DBG("Adding to cache. \n");
            return_status = addPresentityInCache(presentity, &pres_uri,
                                                 &pres_cache_key, &pres_cache_value,
                                                 READ_RESPONSE);
        }

        /* insert new record into database */
        query_cols[n_query_cols] = &str_expires_col;
        query_vals[n_query_cols].type = DB_INT;
        query_vals[n_query_cols].val.int_val = presentity->expires
                                               + (int) time(NULL);
        n_query_cols++;

        query_cols[n_query_cols] = &str_sender_col;
        query_vals[n_query_cols].type = DB_STR;

        if (presentity->sender) {
            query_vals[n_query_cols].val.str_val = *presentity->sender;
        } else {
            query_vals[n_query_cols].val.str_val.s = "";
            query_vals[n_query_cols].val.str_val.len = 0;
        }
        n_query_cols++;

        query_cols[n_query_cols] = &str_body_col;
        query_vals[n_query_cols].type = DB_BLOB;
        query_vals[n_query_cols].val.str_val = body;
        n_query_cols++;

        query_cols[n_query_cols] = &str_received_time_col;
        query_vals[n_query_cols].type = DB_INT;
        query_vals[n_query_cols].val.int_val = presentity->received_time;
        n_query_cols++;

        if (extra_hdrs) {
            query_cols[n_query_cols] = &str_extra_hdrs_col;
            query_vals[n_query_cols].type = DB_BLOB;
            query_vals[n_query_cols].val.str_val = *extra_hdrs;
            n_query_cols++;
        } else {
            query_cols[n_query_cols] = &str_extra_hdrs_col;
            query_vals[n_query_cols].type = DB_BLOB;
            query_vals[n_query_cols].val.str_val.s = "";
            query_vals[n_query_cols].val.str_val.len = 0;
            n_query_cols++;
        }

        LM_DBG("Inserting %d cols into table %s\n", n_query_cols, "Presentity");
//insert into presentity (domain,username,event,etag,expires,sender,body,received_time )

        jsonBuffer = (char *) pkg_malloc(JSON_BUF_LEN);
        if(!jsonBuffer)
            LM_ERR("No more pkg memory\n");
        if (insertResource(query_cols, query_vals, n_query_cols, PRESENTITY,
                           NULL, jsonBuffer) <= 0) {
            LM_ERR("inserting new record in database\n");
            goto error;
        }
        goto send_notify;

    } else {
        //LM_DBG("EXISTING ETAG FOUND.\n");

        if ((found_in_cache = checkPresentityInCache(pres_cache_key.s,
                                                     pres_cache_value.s, NO_FETCH_VALUES, NULL)) <= 0) {
            //--LM_DBG("Not found in cache. Check DB\n");
        }
        found_in_cache = 1;
        if (!found_in_cache) {

            /* search also in db */
            //		LM_DBG("Checking DB for etag.\n");

//select etag from presentity where domain=? AND username=? AND event=? AND etag=?
//This is to check existence of the record.
//return_status -1: request failed before sending to the DB.
//return_status 0: No records found in DB.
//return_status 1: Records found in DB.

            //return_status = checkResource(query_cols, query_vals, n_query_cols,
            //PRESENTITY, pres_uri.s + 4);
            if (getResource(query_cols, query_vals, n_query_cols, &result,
                            PRESENTITY, NULL, NULL, result_cols, 1) < 0) {
                LM_ERR("unsuccessful sql query\n");
                goto error;
            }

            if (result == NULL) {
                LM_ERR("Null result\n");
                goto error;
            }

            if (result->n <= 0) {
                LM_ERR("No E_Tag match [%.*s]\n", presentity->etag.len,
                       presentity->etag.s);
                if (sigb.reply(msg, 412, &pu_412_rpl, 0) == -1) {
                    LM_ERR("sending '412 Conditional request failed' reply\n");
                    goto error;
                }
                *sent_reply = 1;
                goto done;
            }

            LM_INFO("*** found in db but not in htable [%.*s]\n",
                    presentity->etag.len, presentity->etag.s);
        }

        /* record found */
        if (presentity->expires == 0) {

            if (publ_send200ok(msg, presentity->expires, presentity->etag)
                < 0) {
                LM_ERR("sending 200OK reply\n");
                goto error;
            }
            *sent_reply = 1;
            if (micro_srv_arch)
                publish_pub_queue(pres_cache_value.s);
            else if (publ_notify(presentity, pres_uri, body.s ? &body : 0,
                                 &presentity->etag, rules_doc, NULL, 1) < 0) {
                LM_ERR("while sending notify\n");
                goto error;
            }
            /* delete from hash table */
            if (found_in_cache) {
                deletePresentityFromCache(&pres_cache_key, &pres_cache_value,
                                          READ_RESPONSE);
            }
//delete from presentity where domain=? AND username=? AND event=? AND etag=?
            return_status = deleteResource(query_cols, query_vals, n_query_cols,
                                           PRESENTITY, NULL, NULL);
            if (return_status < 0) {
                LM_ERR("unsuccessful sql delete operation");
                goto error;
            }
            //	LM_DBG("Expires=0, deleted from db %.*s\n", presentity->user.len,
            //		presentity->user.s);

            goto done;
        }

        if (presentity->event->etag_not_new == 0) {
            //last digits after . is etag count
            char *temp = presentity->etag.s + presentity->etag.len;
            while (*temp != '.') {
                temp--;
            }
            temp++;
            //LM_DBG("%s\n", temp);
            if (generate_ETag(atoi(temp) + 1, &etag) < 0) {
                LM_ERR("while generating etag\n");
                //lock_release(&pres_htable[hash_code].lock);
                goto error;
            }
            cur_etag = etag;

            if (found_in_cache) {

                if ((return_status = updatePresentityInCache(presentity,
                                                             &pres_cache_key, &pres_cache_value, &pres_uri, &etag))
                    < 0) {
                    LM_ERR("Updating cache.\n");
                    goto error;
                }
            } else {
                if (generatePresentitySetNameValue(presentity, &pres_cache_key,
                                                   &pres_cache_value, &pres_uri, NULL,
                                                   GENERATE_KEY) < 0) {
                    LM_ERR("Creating KV pair for presentity.\n");

                }
                return_status = addPresentityInCache(presentity, &pres_uri,
                                                     &pres_cache_key, &pres_cache_value,
                                                     READ_RESPONSE);
            }

        } else {
            cur_etag = presentity->etag;
        }

        n_update_cols = 0;
        update_keys[n_update_cols] = &str_etag_col;
        update_vals[n_update_cols].type = DB_STR;
        update_vals[n_update_cols].val.str_val = cur_etag;
        n_update_cols++;

        update_keys[n_update_cols] = &str_expires_col;
        update_vals[n_update_cols].type = DB_INT;
        update_vals[n_update_cols].val.int_val = presentity->expires
                                                 + (int) time(NULL);
        n_update_cols++;

        update_keys[n_update_cols] = &str_received_time_col;
        update_vals[n_update_cols].type = DB_INT;
        update_vals[n_update_cols].val.int_val = presentity->received_time;
        n_update_cols++;

        update_keys[n_update_cols] = &str_sender_col;
        update_vals[n_update_cols].type = DB_STR;

        if (presentity->sender) {
            update_vals[n_update_cols].val.str_val = *presentity->sender;
        } else {
            update_vals[n_update_cols].val.str_val.s = "";
            update_vals[n_update_cols].val.str_val.len = 0;
        }
        n_update_cols++;

        if (extra_hdrs) {
            update_keys[n_update_cols] = &str_extra_hdrs_col;
            update_vals[n_update_cols].type = DB_BLOB;
            update_vals[n_update_cols].nul = 0;
            update_vals[n_update_cols].val.str_val = *extra_hdrs;
            n_update_cols++;
        }

        if (body.s) {
            if (fix_remote_target) {
                if (dialog_fix_remote_target(&body, &notify_body) == 0) {
                    body.s = notify_body.s;
                    body.len = notify_body.len;
                } else {
                    LM_ERR("Failed to fix remote target\n");
                }
            }
            update_keys[n_update_cols] = &str_body_col;
            update_vals[n_update_cols].type = DB_BLOB;
            update_vals[n_update_cols].val.str_val = body;
            n_update_cols++;

        }
        //LM_DBG("Updating %d cols into table %s\n", n_query_cols, "Presentity");
//update presentity set etag=?,expires=?,received_time=?,sender=?,body=? where domain=? AND username=? AND event=? AND etag=?
        if (updateResource(query_cols, query_vals, update_keys, update_vals,
                           n_query_cols, n_update_cols,
                           PRESENTITY, NULL, NULL) <= 0) {
            LM_ERR("updating published info in database\n");
            goto error;
        }

        /* send 200OK */
        if (publ_send200ok(msg, presentity->expires, cur_etag) < 0) {
            LM_ERR("sending 200OK reply\n");
            goto error;
        }
        *sent_reply = 1;

        if (!body.s && !extra_hdrs)
            goto done;
    }

    send_notify:

    if (micro_srv_arch) {

        if(avail_subs) {
            char *temp = jsonBuffer;
            temp = my_strcpy(temp, pres_uri.s, 1, pres_uri.len);
            temp = my_strcpy(temp, ":", 1, 1);
            temp = my_strcpy(temp, presentity->body.s, 1, presentity->body.len);
            *temp = '\0';

            LM_DBG("\n***************Publishing to queue: %s\n", jsonBuffer);
            publish_pub_queue(jsonBuffer);
        }
        // If new presentity add in cache after publishing to queue.
        // TODO: Do same for publish refresh.
        if(presentity->etag_new)
        {
            LM_DBG("Adding to cache. \n");
            return_status = addPresentityInCache(presentity, &pres_uri,
                                                 &pres_cache_key, &pres_cache_value,
                                                 READ_RESPONSE);
        }
    }else if (publ_notify(presentity, pres_uri, body.s ? &body : 0,
                    NULL, rules_doc, NULL, 1) < 0) {
        LM_ERR("while sending Notify requests to watchers\n");
        goto error;
    }
	LM_DBG("NOTIFY SENT\n");

    done:

    LM_DBG("************************** D  O  N  E  ************************\n");

    if (jsonBuffer)
        pkg_free(jsonBuffer);
    if (notify_body.s)
        xmlFree(notify_body.s);

    if (rules_doc) {
        if (rules_doc->s)
            pkg_free(rules_doc->s);
        pkg_free(rules_doc);
    }
    if (etag.s)
        pkg_free(etag.s);
    if (pres_uri.s)
        pkg_free(pres_uri.s);
    if (pres_cache_key.s)
        pkg_free(pres_cache_key.s);
    if (pres_cache_value.s)
        pkg_free(pres_cache_value.s);
    return 0;

    error:
    /* allow next publish to be handled */
    LM_ERR("In error");
    if (result)
        free_result(result);
    if (etag.s)
        pkg_free(etag.s);
    if (notify_body.s)
        xmlFree(notify_body.s);

    if (rules_doc) {
        if (rules_doc->s)
            pkg_free(rules_doc->s);
        pkg_free(rules_doc);
    }

    if (pres_uri.s)
        pkg_free(pres_uri.s);

    if (pres_cache_key.s)
        pkg_free(pres_cache_key.s);

    if (pres_cache_value.s)
        pkg_free(pres_cache_value.s);
    return -1;
}

/*
 int pres_htable_restore(void) {
 query all records from presentity table and insert records
 * in presentity table
 //	db_key_t result_cols[6];
 LM_DBG("ENTER INTO pres_htable_restore\n");
 db_res_t *result = NULL;
 db_row_t *rows = NULL;
 db_val_t *row_vals;
 int i;
 str user, domain, ev_str, uri, body;
 int user_col = 0, domain_col = 1, event_col = 2, etag_col = 3, expires_col =
 4, body_col = 7;
 int event;
 event_t ev;
 char* sphere = NULL;
 int nr_rows;
 str etag;
 int result_status = 0;


 result_cols[user_col= n_result_cols++]= &str_username_col;
 result_cols[domain_col= n_result_cols++]= &str_domain_col;
 result_cols[event_col= n_result_cols++]= &str_event_col;
 result_cols[expires_col= n_result_cols++]= &str_expires_col;
 result_cols[etag_col= n_result_cols++]= &str_etag_col;
 if(sphere_enable)
 result_cols[body_col= n_result_cols++]= &str_body_col;



 //	select username,domain,event,expires,etag from presentity
 result_status = getResource(NULL, NULL, 0, &result, PRESENTITY, NULL, NULL);
 LM_DBG("result_status: %d\n", result_status);
 if (result_status <= 0) {
 LM_ERR("querying presentity\n");
 //			goto error;
 } else if (result) {
 nr_rows = RES_ROW_N(result);

 do {
 LM_DBG("loading information from database for %i records\n",
 nr_rows);

 rows = RES_ROWS(result);

 for every row
 for (i = 0; i < nr_rows; i++) {
 row_vals = ROW_VALUES(rows + i);

 LM_DBG("%d Row: Columns: %d", i, rows->n);
 LM_DBG("pUser: %s, type: %d, %d", (row_vals)->val.string_val,
 (row_vals)->type, (row_vals)->nul);
 LM_DBG("pDomain: %s, type: %d, %d",
 (row_vals + 1)->val.string_val, (row_vals + 1)->type,
 (row_vals + 1)->nul);
 LM_DBG("pEvent: %s, type: %d, %d",
 (row_vals + 2)->val.string_val, (row_vals + 2)->type,
 (row_vals + 2)->nul);
 LM_DBG("pEtag: %s, type: %d, %d",
 (row_vals + 3)->val.string_val, (row_vals + 3)->type,
 (row_vals + 3)->nul);
 LM_DBG("pExpires: %d, type: %d, %d",
 (row_vals + 4)->val.int_val, (row_vals + 4)->type,
 (row_vals + 4)->nul);

 if (VAL_NULL(row_vals) || VAL_NULL(row_vals + 1)) {
 LM_ERR("columns %s or/and %s cannot be null -> skipping\n",
 "username", "domain");
 continue;
 }

 if (VAL_NULL(row_vals+2) || VAL_NULL(row_vals + 3)) {
 LM_ERR("columns %s or/and %s cannot be null -> skipping\n",
 "event", "etag");
 continue;
 }

 if (row_vals[expires_col].val.int_val < (int) time(NULL)) {
 continue;
 }

 sphere = NULL;
 user.s = (char*) row_vals[user_col].val.string_val;
 user.len = strlen(user.s);
 domain.s = (char*) row_vals[domain_col].val.string_val;
 domain.len = strlen(domain.s);
 ev_str.s = (char*) row_vals[event_col].val.string_val;
 ev_str.len = strlen(ev_str.s);
 etag.s = (char*) row_vals[etag_col].val.string_val;
 etag.len = strlen(etag.s);

 if (event_parser(ev_str.s, ev_str.len, &ev) < 0) {
 LM_ERR("parsing event\n");
 free_event_params(ev.params, PKG_MEM_TYPE);
 goto error;
 }
 event = ev.parsed;
 free_event_params(ev.params, PKG_MEM_TYPE);

 if (uandd_to_uri(user, domain, &uri) < 0) {
 LM_ERR("constructing uri\n");
 goto error;
 }
 insert in hash_table

 if (sphere_enable && event == EVENT_PRESENCE) {
 body.s = (char*) row_vals[body_col].val.string_val;
 body.len = strlen(body.s);
 sphere = extract_sphere(body);
 }

 if (insert_phtable(&uri, event, &etag, sphere, 0) == NULL) {
 LM_ERR("inserting record in presentity hash table");
 pkg_free(uri.s);
 if (sphere)
 pkg_free(sphere);
 goto error;
 }
 if (sphere)
 pkg_free(sphere);
 pkg_free(uri.s);
 }

 nr_rows = 0;

 } while (nr_rows > 0);
 //	pa_dbf.free_result(pa_db, result);
 LM_DBG("OUT OF DO WHILE");
 free_result(result);
 }
 LM_DBG("EXITING....\n");
 return 0;

 error: if (result)
 //		pa_dbf.free_result(pa_db, result);
 free_result(result);
 return -1;
 }
 */

char *extract_sphere(str body) {

    /* check for a rpid sphere element */
    xmlDocPtr doc = NULL;
    xmlNodePtr node;
    char *cont, *sphere = NULL;

    doc = xmlParseMemory(body.s, body.len);
    if (doc == NULL) {
        LM_ERR("failed to parse xml body\n");
        return NULL;
    }

    node = xmlNodeGetNodeByName(doc->children, "sphere", "rpid");

    if (node == NULL)
        node = xmlNodeGetNodeByName(doc->children, "sphere", "r");

    if (node) {
        //LM_DBG("found sphere definition\n");
        cont = (char *) xmlNodeGetContent(node);
        if (cont == NULL) {
            LM_ERR("failed to extract sphere node content\n");
            goto error;
        }
        sphere = (char *) pkg_malloc(strlen(cont) + 1);
        if (sphere == NULL) {
            xmlFree(cont);
            ERR_MEM(PKG_MEM_STR);
        }
        strcpy(sphere, cont);
        xmlFree(cont);
    } else
        //--LM_DBG("didn't find sphere definition\n");

        error:
        xmlFreeDoc(doc);
    return sphere;
}

xmlNodePtr xmlNodeGetNodeByName(xmlNodePtr node, const char *name,
                                const char *ns) {
    xmlNodePtr cur = node;
    while (cur) {
        xmlNodePtr match = NULL;
        if (xmlStrcasecmp(cur->name, (unsigned char *) name) == 0) {
            if (!ns
                || (cur->ns
                    && xmlStrcasecmp(cur->ns->prefix,
                                     (unsigned char *) ns) == 0))
                return cur;
        }
        match = xmlNodeGetNodeByName(cur->children, name, ns);
        if (match)
            return match;
        cur = cur->next;
    }
    return NULL;
}

char *get_sphere(str *pres_uri) {
//	static db_ps_t my_ps = NULL;
    //--LM_DBG("*************IN GET_SPHERE************\n");
//	unsigned int hash_code;
    char *sphere = NULL;
//	pres_entry_t* p;
    db_key_t query_cols[6];
    db_val_t query_vals[6];
//	db_key_t result_cols[6];
    db_res_t *result = NULL;
    db_row_t *row = NULL;
    db_val_t *row_vals;
//	int n_result_cols = 0;
    int n_query_cols = 0;
    struct sip_uri uri;
    str body;
//	static str query_str = str_init("received_time");

    if (!sphere_enable)
        return NULL;

    /* search in hash table*/
    /*hash_code = core_hash(pres_uri, NULL, phtable_size);

     lock_get(&pres_htable[hash_code].lock);

     p = search_phtable(pres_uri, EVENT_PRESENCE, hash_code);

     if (p) {
     if (p->sphere) {
     sphere = (char*) pkg_malloc(strlen(p->sphere));
     if (sphere == NULL) {
     lock_release(&pres_htable[hash_code].lock);
     ERR_MEM(PKG_MEM_STR);
     }
     strcpy(sphere, p->sphere);
     }
     lock_release(&pres_htable[hash_code].lock);
     return sphere;
     }
     lock_release(&pres_htable[hash_code].lock);
     */
    /* if record not found and fallback2db query database*/
    if (!fallback2db) {
        return NULL;
    }

    if (parse_uri(pres_uri->s, pres_uri->len, &uri) < 0) {
        LM_ERR("failed to parse presentity uri\n");
        goto error;
    }

    query_cols[n_query_cols] = &str_domain_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = uri.host;
    n_query_cols++;

    query_cols[n_query_cols] = &str_username_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val = uri.user;
    n_query_cols++;

    query_cols[n_query_cols] = &str_event_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val.s = "presence";
    query_vals[n_query_cols].val.str_val.len = 8;
    n_query_cols++;

//	result_cols[n_result_cols++] = &str_body_col;
//	result_cols[n_result_cols++] = &str_extra_hdrs_col;

    // CON_PS_REFERENCE(pa_db) = &my_ps;

    if (getResource(query_cols, query_vals, n_query_cols, &result, PRESENTITY,
                    NULL, NULL, NULL, 0) < 0) {
        LM_ERR("failed to query %.*s table\n", presentity_table.len,
               presentity_table.s);
        if (result)
            free_result(result);
        return NULL;
    }

    if (result == NULL)
        return NULL;

    if (result->n <= 0) {
        //LM_DBG("no published record found in database\n");
        free_result(result);
        return NULL;
    }

    row = &result->rows[result->n - 1];
    row_vals = ROW_VALUES(row);
    if (row_vals[0].val.string_val == NULL) {
        LM_ERR("NULL notify body record\n");
        goto error;
    }

    body.s = (char *) row_vals[0].val.string_val;
    body.len = strlen(body.s);
    if (body.len == 0) {
        LM_ERR("Empty notify body record\n");
        goto error;
    }

    sphere = extract_sphere(body);

    free_result(result);

    return sphere;

    error:
    if (result)
        free_result(result);
    return NULL;

}

int contains_presence(str *pres_uri) {
//	unsigned int hash_code;
    db_key_t query_cols[6];
    db_val_t query_vals[6];
//	db_key_t result_cols[6];
//	db_res_t *result = NULL;
//	int n_result_cols = 0;
    int n_query_cols = 0;
//	struct sip_uri uri;
//	static str query_str = str_init("received_time");
    int ret = -1;
    int result_status = 0;
    /*	hash_code = core_hash(pres_uri, NULL, phtable_size);

     lock_get(&pres_htable[hash_code].lock);

     if (search_phtable(pres_uri, EVENT_PRESENCE, hash_code) != NULL) {
     ret = 1;
     }
     lock_release(&pres_htable[hash_code].lock);*/
    int length = 0;
    length = pres_uri->len + 11 + PRESENTITY_SET_PREFIX_LEN;//11 = strlen(PRESENCE) + : + - +'\0'
    char *pres_cache_key = pkg_malloc(length);
    if (pres_cache_key == NULL) {
        LM_ERR("no more memory\n");
        return -1;
    }
    snprintf(pres_cache_key, length, "%s-%.*s:%s", PRESENTITY_SET_PREFIX,
             pres_uri->len, pres_uri->s, "presence");
    if ((ret = hasPublication(&pres_cache_key)) <= 0) {
        //--LM_DBG("Not found in cache. Check DB\n");
    }
    pkg_free(pres_cache_key);
    /*	if (ret == -1 && fallback2db) {
     if (parse_uri(pres_uri->s, pres_uri->len, &uri) < 0) {
     LM_ERR("failed to parse presentity uri\n");
     goto done;
     }*/
    /*
     query_cols[n_query_cols] = &str_domain_col;
     query_vals[n_query_cols].type = DB_STR;
     query_vals[n_query_cols].nul = 0;
     query_vals[n_query_cols].val.str_val = uri.host;
     n_query_cols++;

     query_cols[n_query_cols] = &str_username_col;
     query_vals[n_query_cols].type = DB_STR;
     query_vals[n_query_cols].nul = 0;
     query_vals[n_query_cols].val.str_val = uri.user;
     n_query_cols++;
     */

    query_cols[n_query_cols] = &str_event_col;
    query_vals[n_query_cols].type = DB_STR;
    query_vals[n_query_cols].nul = 0;
    query_vals[n_query_cols].val.str_val.s = "presence";
    query_vals[n_query_cols].val.str_val.len = 8;
    n_query_cols++;

    /*
     result_cols[n_result_cols++] = &str_body_col;
     result_cols[n_result_cols++] = &str_extra_hdrs_col;
     */
//		select count(*) from presentity where domain=? AND username=? AND event=?
//Later change to getResource
    result_status = checkResource(query_cols, query_vals, n_query_cols,
                                  PRESENTITY, (pres_uri->s) + 4);

    if (result_status < 0) {
        LM_ERR("failed to query %.*s table\n", presentity_table.len,
               presentity_table.s);
        goto done;
    }
    if (result_status == 0) {
        //--LM_DBG("no published record found in database\n");
        goto done;
    }
    ret = 1;
//	}
    done:
    return ret;
}

str *xml_dialog_gen_presence(str *pres_uri, int dlg_state) {
    char *pres_note;
    xmlDocPtr pres_doc;
    xmlNodePtr node, root_node;
    xmlNodePtr tuple_node, person_node;
    str *dialog_body = NULL;
    char *entity;

    //--LM_DBG("dlg_state = %d\n", dlg_state);

    pres_note = presence_notes[dlg_state];

    /* if state is terminated, do not add anything */
    if (pres_note && strlen(pres_note) == 0) {
        //--LM_DBG("NULL pres note\n");
        return FAKED_BODY;
    }

    pres_doc = xmlNewDoc(BAD_CAST
    "1.0");
    if (pres_doc == NULL) {
        LM_ERR("allocating new xml doc\n");
        goto error;
    }

    root_node = xmlNewNode(NULL, BAD_CAST
    "presence");
    if (root_node == NULL) {
        LM_ERR("Failed to create xml node\n");
        goto error;
    }
    xmlDocSetRootElement(pres_doc, root_node);

    xmlNewProp(root_node, BAD_CAST
    "xmlns",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf");
    xmlNewProp(root_node, BAD_CAST
    "xmlns:dm",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf:data-model");
    xmlNewProp(root_node, BAD_CAST
    "xmlns:rpid",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf:rpid" );
    xmlNewProp(root_node, BAD_CAST
    "xmlns:c",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf:cipid");

    entity = (char *) pkg_malloc(pres_uri->len + 1);
    if (entity == NULL) {
        LM_ERR("No more memory\n");
        goto error;
    }
    memcpy(entity, pres_uri->s, pres_uri->len);
    entity[pres_uri->len] = '\0';
    xmlNewProp(root_node, BAD_CAST
    "entity", BAD_CAST
    entity);
    pkg_free(entity);

    tuple_node = xmlNewChild(root_node, NULL, BAD_CAST
    "tuple", NULL);
    if (tuple_node == NULL) {
        LM_ERR("while adding child\n");
        goto error;
    }

    xmlNewProp(tuple_node, BAD_CAST
    "id", BAD_CAST
    "tuple_mixingid");

    node = xmlNewChild(tuple_node, NULL, BAD_CAST
    "status", NULL);
    if (node == NULL) {
        LM_ERR("while adding child\n");
        goto error;
    }
    node = xmlNewChild(node, NULL, BAD_CAST
    "basic", BAD_CAST
    "open");
    if (node == NULL) {
        LM_ERR("while adding child\n");
        goto error;
    }

    if (pres_note && strlen(pres_note)) {
        node = xmlNewChild(root_node, NULL, BAD_CAST
        "note",
                BAD_CAST
        pres_note);
        if (node == NULL) {
            LM_ERR("while adding child\n");
            goto error;
        }
        /* put also the person node - to get status indication */
        person_node = xmlNewChild(root_node, 0, BAD_CAST
        "dm:person", NULL);
        if (person_node == NULL) {
            LM_ERR("while adding child\n");
            goto error;
        }
        /* now put the id for tuple and person */
        xmlNewProp(person_node, BAD_CAST
        "id", BAD_CAST
        "pers_mixingid");

        node = xmlNewChild(person_node, 0, BAD_CAST
        "rpid:activities", NULL);
        if (node == NULL) {
            LM_ERR("Failed to add person activities node\n");
            goto error;
        }

        if (xmlNewChild(node, 0, BAD_CAST "rpid:on-the-phone", NULL) == NULL) {
            LM_ERR("Failed to add activities child\n");
            goto error;
        }

        if (xmlNewChild(person_node, 0, BAD_CAST
            "dm:note",
                    BAD_CAST
        pres_note) == NULL) {
            LM_ERR("Failed to add activities child\n");
            goto error;
        }
    }

    dialog_body = (str *) pkg_malloc(sizeof(str));
    if (dialog_body == NULL) {
        LM_ERR("No more memory\n");
        goto error;
    }
    xmlDocDumpMemory(pres_doc, (xmlChar * *)(
    void*) &dialog_body->s,
            &dialog_body->len);

    //--LM_DBG("Generated dialog body: %.*s\n", dialog_body->len, dialog_body->s);

    error:
    if (pres_doc)
        xmlFreeDoc(pres_doc);
    xmlCleanupParser();
    xmlMemoryDump();

    return dialog_body;
}

str *xml_dialog2presence(str *pres_uri, str *body) {
    xmlDocPtr dlg_doc = NULL;
    xmlNodePtr node, dialog_node;
    unsigned char *state;
    int i;

    if (body->len == 0)
        return NULL;

    dlg_doc = xmlParseMemory(body->s, body->len);
    if (dlg_doc == NULL) {
        LM_ERR("Wrong formated xml document\n");
        return NULL;
    }
    dialog_node = xmlNodeGetNodeByName(dlg_doc->children, "dialog", 0);
    if (!dialog_node) {
        goto done;
    }

    node = xmlNodeGetNodeByName(dialog_node, "state", 0);
    if (!node)
        goto done;

    state = xmlNodeGetContent(node);
    if (!state)
        goto done;

    for (i = 0; i < DLG_STATES_NO; i++) {
        if (xmlStrcasecmp(state, BAD_CAST dialog_states[i])==0) {
            break;
        }
    }
    xmlFree(state);
    xmlFreeDoc(dlg_doc);
    xmlCleanupParser();
    xmlMemoryDump();

    if (i == DLG_STATES_NO) {
        LM_ERR("Unknown dialog state\n");
        return 0;
    }

    return xml_dialog_gen_presence(pres_uri, i);

    done:
    xmlFreeDoc(dlg_doc);
    return 0;
}

str *build_offline_presence(str *pres_uri) {
    xmlDocPtr pres_doc = NULL;
    xmlNodePtr root_node, tuple_node, node;
    char *entity;
    str *body = NULL;

    pres_doc = xmlNewDoc(BAD_CAST
    "1.0");
    if (pres_doc == NULL) {
        LM_ERR("allocating new xml doc\n");
        goto error;
    }

    root_node = xmlNewNode(NULL, BAD_CAST
    "presence");
    if (root_node == NULL) {
        LM_ERR("Failed to create xml node\n");
        goto error;
    }
    xmlDocSetRootElement(pres_doc, root_node);

    xmlNewProp(root_node, BAD_CAST
    "xmlns",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf");
    xmlNewProp(root_node, BAD_CAST
    "xmlns:dm",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf:data-model");
    xmlNewProp(root_node, BAD_CAST
    "xmlns:rpid",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf:rpid" );
    xmlNewProp(root_node, BAD_CAST
    "xmlns:c",
            BAD_CAST
    "urn:ietf:params:xml:ns:pidf:cipid");

    entity = (char *) pkg_malloc(pres_uri->len + 1);
    if (entity == NULL) {
        LM_ERR("No more memory\n");
        goto error;
    }
    memcpy(entity, pres_uri->s, pres_uri->len);
    entity[pres_uri->len] = '\0';
    xmlNewProp(root_node, BAD_CAST
    "entity", BAD_CAST
    entity);
    pkg_free(entity);

    tuple_node = xmlNewChild(root_node, NULL, BAD_CAST
    "tuple", NULL);
    if (tuple_node == NULL) {
        LM_ERR("while adding child\n");
        goto error;
    }

    xmlNewProp(tuple_node, BAD_CAST
    "id", BAD_CAST
    "tuple_mixingid");

    node = xmlNewChild(tuple_node, NULL, BAD_CAST
    "status", NULL);
    if (node == NULL) {
        LM_ERR("while adding child\n");
        goto error;
    }
    node = xmlNewChild(node, NULL, BAD_CAST
    "basic",
            BAD_CAST
    "closed");
    if (node == NULL) {
        LM_ERR("while adding child\n");
        goto error;
    }

    body = (str *) pkg_malloc(sizeof(str));
    if (body == NULL) {
        LM_ERR("No more memory\n");
        goto error;
    }
    xmlDocDumpMemory(pres_doc, (xmlChar * *)(
    void*) &body->s, &body->len);

    //--LM_DBG("Generated dialog body: %.*s\n", body->len, body->s);

    error:
    if (pres_doc)
        xmlFreeDoc(pres_doc);
    xmlCleanupParser();
    xmlMemoryDump();

    return body;
}

