//
// Created by suryaveer on 2016-10-04.
//


#include "queue_publisher.h"
#include "queue.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
//natsConnection  *conn  = NULL;
//natsStatus      s;

int queue_connect(const char  **serverUrls) {
    if (natsOptions_Create(&opts) != NATS_OK)
        s = NATS_NO_MEMORY;

    LM_DBG("In queueconnect*********\n");
    LM_DBG("%s\n", serverUrls[0]);

    if (s == NATS_OK)
        s = natsOptions_SetServers(opts, (const char **) serverUrls, 1);


    s = natsConnection_Connect(&conn, opts);

    if (s == NATS_OK)
    {
        LM_DBG("Connection..\n");
        return 0;
    }
    else
    {
        LM_DBG("No Connection..\n");
        return -1;
    }
}
int setQueue( const char* pub_subject, const char* sub_subject)
{

    if(pub_subject) {
        LM_DBG("*********************** In setQueue %s...........\n", pub_subject);
        //pub_subj = pkg_malloc(sizeof(char) * strlen(pub_subject) + 1);
        strcpy(pub_subj, pub_subject);
     //   LM_DBG("*********************** Queue set %s...........\n", pub_subj);
      //  publish_pub_queue("hello Publish.\n");

    }
    if(sub_subject) {
       LM_DBG("*********************** In setQueue %s...........\n", sub_subject);
        //sub_subj = pkg_malloc(sizeof(char) * strlen(sub_subject) + 1);
        strcpy(sub_subj, sub_subject);
    //    LM_DBG("*********************** Queue set %s...........\n", sub_subj);
      //  publish_sub_queue("hello Subscribe.\n");
    }

    return 0;
}
int publish_msg(const char* txt, const char* subj){


    s = natsConnection_PublishString(conn, subj, txt);
    if (s == NATS_OK)
    {
        LM_DBG("Msg sending.. %s \n",txt);
        return 0;
    }
    else
    {
        LM_ERR("Error: %d - %s\n", s, natsStatus_GetText(s));
        nats_PrintLastErrorStack(stderr);
        return -1;
    }
    /*if (s == NATS_OK)
        s = natsConnection_FlushTimeout(conn, 1000);
    else
        LM_DBG("Not flushing..");*/
}
void publish_pub_queue(const char* msg)
{
    publish_msg(msg, pub_subj);
}
void publish_sub_queue(const char* msg)
{
    publish_msg(msg, sub_subj);
}
void queue_disconnect()
{
    // Destroy all our objects to avoid report of memory leak
    natsConnection_Destroy(conn);
    natsOptions_Destroy(opts);
    // To silence reports of memory still in used with valgrind
    nats_Close();
}
