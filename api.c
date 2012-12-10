/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_API

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "p0f.h"
#include "api.h"
#include "process.h"
#include "readfp.h"

#include "json.h"

/* Process API queries. */

void handle_query(struct p0f_api_query* q, struct p0f_api_response* r) {

  struct host_data* h;

  memset(r, 0, sizeof(struct p0f_api_response));

  r->magic = P0F_RESP_MAGIC;

  if (q->magic != P0F_QUERY_MAGIC) {

    WARN("Query with bad magic (0x%x).", q->magic);

    r->status = P0F_STATUS_BADQUERY;

    return;

  }

  switch (q->addr_type) {

    case P0F_ADDR_IPV4:
    case P0F_ADDR_IPV6:
      h = lookup_host(q->addr, q->addr_type);
      break;

    default:

      WARN("Query with unknown address type %u.\n", q->addr_type);
      r->status = P0F_STATUS_BADQUERY;
      return;

  }

  if (!h) {
    r->status = P0F_STATUS_NOMATCH;
    return;
  }

  r->status     = P0F_STATUS_OK;
  r->first_seen = h->first_seen;
  r->last_seen  = h->last_seen;
  r->total_conn = h->total_conn;

  if (h->last_name_id != -1) {

    strncpy((char*)r->os_name, (char*)fp_os_names[h->last_name_id],
            P0F_STR_MAX + 1);

    if (h->last_flavor)
       strncpy((char*)r->os_flavor, (char*)h->last_flavor, P0F_STR_MAX + 1);

  }

  if (h->http_name_id != -1) {

    strncpy((char*)r->http_name, (char*)fp_os_names[h->http_name_id],
            P0F_STR_MAX + 1);

    if (h->http_flavor)
      strncpy((char*)r->http_flavor, (char*)h->http_flavor, P0F_STR_MAX + 1);

  }

  if (h->link_type)
    strncpy((char*)r->link_type, (char*)h->link_type, P0F_STR_MAX + 1);

  if (h->language)
    strncpy((char*)r->language, (char*)h->language, P0F_STR_MAX + 1);

  r->bad_sw      = h->bad_sw;
  r->last_nat    = h->last_nat;
  r->last_chg    = h->last_chg;
  r->up_mod_days = h->up_mod_days;
  r->distance    = h->distance;
  r->os_match_q  = h->last_quality;

  if (h->last_up_min != -1) r->uptime_min = h->last_up_min;

}


void handle_json_query(struct p0f_api_query* q, char** jr) {

#define JSON_FIELD(fname, type, val) \
  json_object_object_add(obj, fname, json_object_new_##type(val));

#define JSON_TCP_FIELD(fname, type, val) \
  json_object_object_add(ts_obj, fname, json_object_new_##type(val));

  struct host_data* h;
  struct tcp_sig* ts = NULL;
  json_object *obj, *ts_obj;
  char *tmp;

  obj = json_object_new_object();

  /* represent all uint32 fields as int64 to avoid signedness issues */
  JSON_FIELD("magic", int64, P0F_RESP_MAGIC);

  if (q->magic != P0F_QUERY_MAGIC) {
    WARN("Query with bad magic (0x%x).", q->magic);
    JSON_FIELD("status", int64, P0F_STATUS_BADQUERY);
    goto finalize;
  }

  switch (q->addr_type) {
    case P0F_ADDR_IPV4:
    case P0F_ADDR_IPV6:
      h = lookup_host(q->addr, q->addr_type);
      break;

    default:
      WARN("Query with unknown address type %u.\n", q->addr_type);
      JSON_FIELD("status", int64, P0F_STATUS_BADQUERY);
      goto finalize;
  }

  if (!h) {
    JSON_FIELD("status", int64, P0F_STATUS_NOMATCH);
    goto finalize;
  }

  JSON_FIELD("status", int64, P0F_STATUS_OK);
  JSON_FIELD("first_seen", int64, h->first_seen);
  JSON_FIELD("last_seen", int64, h->last_seen);
  JSON_FIELD("total_conn", int64, h->total_conn);

  JSON_FIELD("bad_sw", boolean, h->bad_sw);
  JSON_FIELD("last_nat", int64, h->last_nat);
  JSON_FIELD("last_chg", int64, h->last_chg);

  if (h->last_up_min != -1) JSON_FIELD("last_up_min", int, h->last_up_min);
  JSON_FIELD("up_mod_days", int64, h->up_mod_days);
  JSON_FIELD("distance", int, h->distance);
  JSON_FIELD("os_match_q", boolean, h->last_quality);

  if (h->last_name_id != -1) {
    JSON_FIELD("os_name", string, (char*)fp_os_names[h->last_name_id]);

    if (h->last_flavor)
      JSON_FIELD("os_flavor", string, (char*)h->last_flavor);
  }

  if (h->http_name_id != -1) {
    JSON_FIELD("http_name", string, (char*)fp_os_names[h->http_name_id]);

    if (h->http_flavor)
      JSON_FIELD("http_flavor", string, (char*)h->http_flavor);
  }

  if (h->link_type)
    JSON_FIELD("link_type", string, (char*)h->link_type);

  if (h->language)
    JSON_FIELD("language", string, (char*)h->language);

  if (h->last_syn) {
    ts = h->last_syn;
  } else if (h->newer && h->newer->last_synack) {/* XXX - not sure about this */
    ts = h->newer->last_synack;
  }

  if (ts) {
    ts_obj = json_object_new_object();

    JSON_TCP_FIELD("opt_hash", int64, ts->opt_hash);
    JSON_TCP_FIELD("quirks", int64, ts->quirks);

    JSON_TCP_FIELD("opt_eol_pad", int, ts->opt_eol_pad);
    JSON_TCP_FIELD("ip_opt_len", int, ts->ip_opt_len);
    JSON_TCP_FIELD("ip_ver", int, ts->ip_ver);

    JSON_TCP_FIELD("ttl", int, ts->ttl);
    JSON_TCP_FIELD("mss", int64, ts->mss);
    JSON_TCP_FIELD("win", int, ts->win);
    JSON_TCP_FIELD("win_type", int, ts->win_type);
    JSON_TCP_FIELD("wscale", int, ts->wscale);

    JSON_TCP_FIELD("pay_class", int, ts->pay_class);
    JSON_TCP_FIELD("tot_hdr", int, ts->tot_hdr);
    JSON_TCP_FIELD("ts1", int64, ts->ts1);
    JSON_TCP_FIELD("recv_ms", int64, ts->recv_ms);
    /* XXX - this field is unsigned int64, but JSON-C allows only signed int64.
             if the value is received negative, it got overflowed */

    JSON_TCP_FIELD("matched", boolean, ts->matched != NULL);
    JSON_TCP_FIELD("fuzzy", int, ts->fuzzy);
    JSON_TCP_FIELD("dist", int, ts->dist);

    json_object_object_add(obj, "tcp_sig", ts_obj);
  }

  if (h->tcp_raw_sig) JSON_FIELD("tcp_raw_sig", string, (char*)h->tcp_raw_sig);
  if (h->http_raw_sig) JSON_FIELD("http_raw_sig", string, (char*)h->http_raw_sig);

finalize:
  /* copy the serialized string, before json_object_put() destroys it */
  tmp = (char*)json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
  *jr = (char*)ck_alloc(strlen(tmp)+1);
  strncpy(*jr, tmp, strlen(tmp));

  if (ts) json_object_put(ts_obj);
  json_object_put(obj);
}
