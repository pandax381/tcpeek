# tcpeek

## Introduction

tcpeek is a Network Monitor that monitors and aggregates the errors that occur when a TCP session is established (3way handshake).

It has the following features:

### Error detection

You can aggregate TCP sessions that failed to connect

+ Counts Sessions rejected by RST
+ ICMP Unreach counts the sessions that have detected inaccessibility
+ The connection counts the sessions that timed out

### Resending detection

You can aggregate TCP sessions where retransmissions occur

+ Counts sessions where the retransmission of the SYN segment occurred
+ SYN / ACK counts the sessions where the segment retransmission occurred

### Filter

You can specify a filter to summarize individually

+ Direction of communication・specify the filter in the combination of IP address and port number
+ Multiple filters can be specified
+ * You can also specify a filter such as excluding this port

### Data output

Outputs the aggregated data via UNIX domain socket

+ Output in JSON format that is easy to handle with scripts
+ Comes with a script (tcpeekstat) to output rrd via Ganglia gmetric

## How to install

 ```
$ git clone git://github.com/pandax381/tcpeek.git
$ cd tcpeek
$ ./configure
$ make
$ sudo make install
 ```

## How to use

```
usage: tcpeek [option]... [expression]...
  option:
    -u --user=uid         # it works setuid to the specified user
    -i --interface=dev    # specifies the interface name (for example, eth0)
    -U --socket=path      # UNIX specifies the path of the domain socket (default:/var/run/tcpeek/tcpeek.sock)
    -c --checksum=[0|1|2] # Specify the checksum verification mode 0=No verification 1 = only IP header 2 = IP header+TCP header (default: 0)
    -t --timeout=sec      # Session timeout (default: 60)
    -B --buffer           # specify the buffer size of libpcap in MB (default: 2)
    -l --loglevel=LEVEL   # SYSLOG level (default: LOG_NOTICE) ※ status is not working
    -q --quiet            # Specify this option to suppress real-time session information output
       --promisc          # Specify this option to operate in promiscuous mode
       --icmp             # Specify this option to interpret ICMP unreachable messages
    -h --help             # Exit with help
    -v --version          # Display the version and exit
  expression:
    [filter]:dir@addr:port[:port...][,...]
  example) '%' is the same as wildcard '*'
    tcpeek -i eth0 filter:RX@%:80:443
    tcpeek -i eth0 filter:TX@192.168.0.0/24:%
    tcpeek -i eth0 filter1:RX@%:80:443 filter2:TX@192.168.0.0/24:%
```

if you specify only the interface in the `-i` option, it will work anyway (by default, the filters `RX:RX@*:*` and `TX:TX@*:*` are specified).

```
$ sudo ./tcpeek -i eth0
```

`expression` It is a bit more complicated to specify, but it is specified as follows.

``` Filter name: communication direction (RX|TX)@IP address: port number ```

+ Multiple filters can be specified.

  ```filter1:RX@192.168.0.1:80 filter2:TX@192.168.0.2:80```

+ The IP address and port number are `%` and the World card can be specified.

  ```filter:TX@%:%```

+ The IP address can also be a network address.

  ```filter:TX@192.168.0.0/24:%```

+ You can specify multiple port numbers with a `:` separator.

  ```filter:TX@192.168.0.1:80:443:8080```

+ You can specify more than one combination of IP address and port number separated by `,`.

  ```filter:TX@192.168.0.1:80:443:8080,192.168.0.2:80,192.168.0.3:80:8080```

+ If you omit the filter name, it becomes an exclusion filter, the session that matches the condition will not be recorded in all filters (the order of description does not matter).

  ```:RX@*:22 :TX@*:22```

> Sessions that match more than one filter will be aggregated across all applicable filters

## Result output

when tcpeek is executed, the information of the TCP session is output to the standard error in real time.

```
$ sudo ./tcpeek -i eth0
listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes

 TIME(s) |       TIMESTAMP       |      SRC IP:PORT            DST IP:PORT     |      RESULTS      | DUP SYN  DUP S/A
----------------------------------------------------------------------------------------------------------------------
   0.002 | 12-07-06 16:39:02.552 |   192.168.2.227:48967   192.168.2.202:80    |      success      |       0        0 
   0.002 | 12-07-06 16:39:02.559 |   192.168.2.227:48968   192.168.2.202:80    |      success      |       0        0 
   0.002 | 12-07-06 16:39:11.219 |   192.168.2.227:42031   192.168.2.202:443   |      success      |       0        0 
   0.002 | 12-07-06 16:39:11.273 |   192.168.2.227:48970   192.168.2.202:80    |      success      |       0        0 
   0.002 | 12-07-06 16:39:11.279 |   192.168.2.227:42033   192.168.2.202:443   |      success      |       0        0 
   0.002 | 12-07-06 16:39:11.309 |   192.168.2.227:48972   192.168.2.202:80    |      success      |       0        0 
   0.002 | 12-07-06 16:39:11.323 |   192.168.2.227:42035   192.168.2.202:443   |      success      |       0        0 
   0.001 | 12-07-06 16:39:11.354 |   192.168.2.227:42036   192.168.2.202:443   |      success      |       0        0 
   0.002 | 12-07-06 16:39:11.385 |   192.168.2.227:42037   192.168.2.202:443   |      success      |       0        0 
   0.001 | 12-07-06 16:39:36.254 |   192.168.2.228:62876   192.168.2.227:80    | failure (reject)  |       0        0 
   0.000 | 12-07-06 16:39:38.160 |   192.168.2.228:62877   192.168.2.227:80    | failure (reject)  |       0        0 
   0.000 | 12-07-06 16:39:44.689 |   192.168.2.227:56371   192.168.2.228:8080  | failure (reject)  |       0        0
  39.947 | 12-07-06 16:41:29.723 |   192.168.2.227:58376   192.168.2.207:8080  | failure (timeout) |       2        0   
```

+ TIME(s)

  Time (in seconds) spent on establishing a TCP session (3way handshake)

+ TIMESTAMP

  The time when the TCP session started

+ SRC IP:PORT

  IP address and port number of the beginning of the TCP session (client)

+ DST IP:PORT

  TCP session termination (server) IP address and port number

+ RESULTS

  TCP session availability

+ DUP SYN

  The number of times the SYN segment was retransmitted (0 if no retransmissions occur)

+ DUP S/A

  The number of times the SYN/ACK segment was retransmitted (0 if no retransmissions occur)

### Statistical output

Output the above statistics by `Ctrl+C` and exit.

```
========== TCPEEK SUMMARY ==========
     from : 2012-07-02 16:48:33      # aggregate start-time
       to : 2012-07-02 16:49:59      # aggregate end-time
     time :        86.106 (sec)      # Time (seconds)
------------------------------------
 RX                                  # filter name
   Success: 0 session                # 3way number of successful sessions
     SYN Segment Duplicate :      0  # the number of sessions for which the retransmission of the SYN segment occurred
     S/A Segment Duplicate :      0  # SYN/ACK the number of sessions in which the segment was resent
   Failure: 10 session               # 3way number of sessions where the handshake failed
     Connection Timed Out  :      0  # number of Sessions the connection timed out
     Connection Rejected   :     10  # the number of sessions that the connection was denied
------------------------------------
 TX
   Success: 783 session
     SYN Segment Duplicate :      0
     S/A Segment Duplicate :      0
   Failure: 0 session
     Connection Timed Out  :      0
     Connection Rejected   :      0
------------------------------------
 http-rx
   Success: 0 session
     SYN Segment Duplicate :      0
     S/A Segment Duplicate :      0
   Failure: 10 session
     Connection Timed Out  :      0
     Connection Rejected   :     10
------------------------------------
 http-tx
   Success: 767 session
     SYN Segment Duplicate :      0
     S/A Segment Duplicate :      0
   Failure: 0 session
     Connection Timed Out  :      0
     Connection Rejected   :      0
====================================
```

This statistic can also be obtained while tcpeek is running by using the tcpeekstat command described below.

## tcpeekstat

```
usage: tcpeekstat [OPTION]
  [OPTION]
    -g  --gmetric      # exec gmetric
    -U  --socket=path  # unix domain socket (default: /var/run/tcpeek/tcpeek.sock)
    -v  --version      # version
    -h  --help         # help
```

you can run tcpeekstat to get statistics from a running tcpeek.

```
$ sudo ./tcpeekstat
```

run with the `-g` option to output the rrd via Ganglia's 'gmetric' command.

```
$ sudo ./tcpeekstat -g
```

> when `-g` option is not selected, the difference is output from the accumulated data at startup, and when it was last executed with `-g` option if there is a `-g` option

## Notes

`libpcap` must be installed (libpcap recommends the latest version http://www.tcpdump.org/#latest-release).

The author is not responsible for any damage caused by using this software.
