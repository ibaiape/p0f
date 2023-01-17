See docs/README for original readme of p0f v3.

This fork integrates p0f [http://lcamtuf.coredump.cx/p0f3/]
with json-c [https://github.com/json-c/json-c],
enabling to stream JSON-serialized data via the UNIX socket.

In addition, more fields are exposed through JSON, such as
raw TCP and HTTP signatures and a number of TCP metrics.

Use new command line argument "-j" to enable JSON output.

Sample output (formatted):

  {
    "magic":1345340930,
    "status":16,
    "first_seen":1354940857,
    "last_seen":1354940863,
    "total_conn":8,
    "bad_sw":false,
    "last_nat":0,
    "last_chg":0,
    "up_mod_days":0,
    "distance":0,
    "os_match_q":false,
    "os_name":"Windows",
    "os_flavor":"7 or 8",
    "http_name":"Chrome",
    "http_flavor":"11 or newer",
    "link_type":"Ethernet or modem",
    "language":"English",
    "tcp_sig":{
      "opt_hash":1862996884,
      "quirks":6,
      "opt_eol_pad":0,
      "ip_opt_len":0,
      "ip_ver":4,
      "ttl":128,
      "mss":1460,
      "win":8192,
      "win_type":0,
      "wscale":2,
      "pay_class":0,
      "tot_hdr":52,
      "ts1":0,
      "recv_ms":1354940863453,
      "matched":true,
      "fuzzy":0,
      "dist":0
    },
    "tcp_raw_sig":"4:64+0:0:1460:mss*10,3:mss,nop,nop,sok,nop,ws:df:0",
    "http_raw_sig":"1:Host,Connection=[keep-alive],Accept=[*\/*],User-Agent,Accept-Encoding=[gzip,deflate,sdch],Accept-Language=[en-US,en;q=0.8],Accept-Charset=[ISO-8859-1,utf-8;q=0.7,*;q=0.3]:Keep-Alive:Mozilla\/5.0 (Windows NT 6.1; WOW64) AppleWebKit\/537.11 (KHTML, like Gecko) Chrome\/23.0.1271.95 Safari\/537.11"
  }