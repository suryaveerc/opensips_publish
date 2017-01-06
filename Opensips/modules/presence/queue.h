//
// Created by suryaveer on 2016-10-04.
//

#include <nats.h>
#include <stdio.h>
#include <string.h>

char  pub_subj[15];
char  sub_subj[15];
natsOptions      *opts   = NULL;
natsConnection  *conn  = NULL;
natsStatus      s=NATS_OK;