//
// Created by suryaveer on 2016-10-04.
//



int queue_connect(const char **serverUrls);
int publish_msg(const char* txt, const char* subj);
void queue_disconnect();
int setQueue( const char* pub_subject, const char* sub_subject);
void publish_pub_queue(const char* msg);
void publish_sub_queue(const char* msg);