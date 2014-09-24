#include "tcpeek.h"

#define DEFAULT_PCAP_SNAPLEN 138

static void
tcpeek_init_global(void);
static void
tcpeek_init_option(int argc, char *argv[]);
static void
tcpeek_init_signal(void);
static void
tcpeek_init_log(void);
static void
tcpeek_init_session(void);
static void
tcpeek_init_filter_and_stat(void);
static void
tcpeek_init_pcap(void);
static void
tcpeek_init_addr(void);
static void
tcpeek_init_setuid(void);
static void
tcpeek_init_socket(void);
static void
usage(void); 
static void
version(void); 

void
tcpeek_init(int argc, char *argv[]) {
	tcpeek_init_global();
	tcpeek_init_option(argc, argv);
	tcpeek_init_signal();
	tcpeek_init_log();
	tcpeek_init_session();
	tcpeek_init_filter_and_stat();
	tcpeek_init_pcap();
	tcpeek_init_addr();
	tcpeek_init_setuid();
	tcpeek_init_socket();
}

static void
tcpeek_init_global(void) {
	memset(&g, 0x00, sizeof(g));
	g.option.timeout = 30;
	g.option.buffer = 2;
	g.option.checksum = TCPEEK_CKSUM_IP;
	strncpy(g.option.socket, TCPEEK_SOCKET_FILE, sizeof(g.option.socket) - 1);
	g.option.expression = lnklist_create();
	lnklist_add_tail(g.option.expression, strdup("RX:RX@%:%"));
	lnklist_add_tail(g.option.expression, strdup("TX:TX@%:%"));
	g.filter = lnklist_create();
	g.soc = -1;
}

static void
tcpeek_init_option(int argc, char *argv[]) {
	int opt;
	static struct option long_options[] = {
		{"user",      1, NULL, 'u'},
		{"interface", 1, NULL, 'i'},
		{"checksum",  1, NULL, 'c'},
		{"socket",    1, NULL, 'U'},
		{"timeout",   1, NULL, 't'},
		{"buffer",    1, NULL, 'B'},
		{"loglevel",  1, NULL, 'l'},
		{"quiet",     0, NULL, 'q'},
		{"promisc",   0, NULL, 500},
		{"icmp",      0, NULL, 501},
		{"help",      0, NULL, 'h'},
		{"version",   0, NULL, 'v'},
		{ NULL,       0, NULL,  0 }
	};

	while((opt = getopt_long_only(argc, argv, "u:i:c:U:t:B:l:qhv", long_options, NULL)) != -1) {
		switch(opt) {
			case 'u':
				strncpy(g.option.user, optarg, sizeof(g.option.user) - 1);
				break;
			case 'i':
				strncpy(g.option.ifname, optarg, sizeof(g.option.ifname) - 1);
				break;
			case 'c':
				if(!strisequal(optarg, "0") && !strisequal(optarg, "1") && !strisequal(optarg, "2")) {
					usage();
					tcpeek_terminate(0);
				}
				g.option.checksum = strtol(optarg, NULL, 10);
				break;
			case 'U':
				strncpy(g.option.socket, optarg, sizeof(g.option.socket) - 1);
				break;
            case 'B':
				if(!strisdigit(optarg)) {
					usage();
					tcpeek_terminate(0);
				}
				g.option.buffer = strtol(optarg, NULL, 10);
                break;
			case 't':
				if(!strisdigit(optarg)) {
					usage();
					tcpeek_terminate(0);
				}
				g.option.timeout = strtol(optarg, NULL, 10);
				break;
			case 'q':
				g.option.quiet = 1;
				break;
			case 500:
				g.option.promisc = 1;
				break;
			case 501:
				g.option.icmp = 1;
				break;
			case 'h':
				usage();
				tcpeek_terminate(0);
			case 'v':
				version();
				tcpeek_terminate(0);
			default:
				usage();
				tcpeek_terminate(1);
		}
	}
	while(optind < argc) {
		lnklist_add_tail(g.option.expression, strdup(argv[optind++]));
	}
}

static void
tcpeek_init_signal(void) {
	static int signals[] = {SIGINT, SIGTERM, SIGPIPE, SIGUSR1, SIGUSR2, SIGALRM, 0};
	struct sigaction sig;
	int offset;

	memset(&sig, 0, sizeof(sig));
	sig.sa_handler = tcpeek_signal_handler;
	for(offset = 0; signals[offset]; offset++) {
		if(sigaction(signals[offset], &sig, NULL) == -1){
			error_abort("sigaction: '%d' %s", signals[offset], strerror(errno));
		}
	}
}

static void
tcpeek_init_log(void) {
	//openlog(PACKAGE_NAME, LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
}

static void
tcpeek_init_session(void) {
	g.session.table = hashtable_create(TCPEEK_SESSION_TABLE_SIZE);
	if(!g.session.table) {
		error_abort("hashtable can't create.");
	}
	pthread_mutex_init(&g.session.mutex, NULL);
}

static void
tcpeek_init_filter_and_stat(void) {
	char *expression;
	struct tcpeek_filter *filter;

	lnklist_iter_init(g.option.expression);
	while(lnklist_iter_hasnext(g.option.expression)) {
		expression = lnklist_iter_next(g.option.expression);
		filter = tcpeek_filter_create();
		if(tcpeek_filter_parse(filter, expression) == -1) {
			tcpeek_filter_destroy(filter);
			error_abort("filter '%s' parse error.", expression);
		}
		if(!lnklist_add(g.filter, filter, filter->stat ? lnklist_size(g.filter) : 0)) {
			tcpeek_filter_destroy(filter);
			error_abort("can't allocate.");
		}
	}
}

static void
tcpeek_init_pcap(void) {
	char *ifname, errmsg[PCAP_ERRBUF_SIZE], expression[] = "tcp or icmp";
	struct bpf_program bpf;

	if(strisempty(g.option.ifname)) {
		ifname = pcap_lookupdev(errmsg);
		if(!ifname) {
			error_abort("%s", errmsg);
		}
		strncpy(g.option.ifname, ifname, sizeof(g.option.ifname) - 1);
	}
    g.pcap.pcap = pcap_create(g.option.ifname, errmsg);
	if(!g.pcap.pcap) {
		error_abort("%s", errmsg);
	}
    if(pcap_set_buffer_size(g.pcap.pcap, g.option.buffer * 1024 * 1024) != 0) {
        error_abort("%s", "can not set buffer size");
    }
    if(pcap_set_snaplen(g.pcap.pcap, DEFAULT_PCAP_SNAPLEN) != 0) {
        error_abort("%s", "can not set snaplen");
    }
    if(pcap_set_promisc(g.pcap.pcap, g.option.promisc) != 0) {
        error_abort("%s", "can not set promiscuous mode");
    }
    if(pcap_set_timeout(g.pcap.pcap, 1) != 0) {
        error_abort("%s", "can not set timeout");
    }
    if(pcap_activate(g.pcap.pcap) != 0) {
        error_abort("%s", pcap_geterr(g.pcap.pcap));
    }
	if(pcap_compile(g.pcap.pcap, &bpf, expression, 0, 0) == -1) {
		error_abort("%s '%s'", pcap_geterr(g.pcap.pcap), expression);
	}
	if(pcap_setfilter(g.pcap.pcap, &bpf) == -1){
		error_abort("%s", pcap_geterr(g.pcap.pcap));
	}
	pcap_freecode(&bpf);
	g.pcap.snapshot = pcap_snapshot(g.pcap.pcap);
	g.pcap.datalink = pcap_datalink(g.pcap.pcap);
	if(g.pcap.datalink != DLT_EN10MB && g.pcap.datalink != DLT_LINUX_SLL) {
		error_abort("not support datalink %s (%s)",
			pcap_datalink_val_to_name(g.pcap.datalink),
			pcap_datalink_val_to_description(g.pcap.datalink)
		);
	}
}

static void
tcpeek_init_addr(void) {
	struct ifaddrs *ifap, *ifa = NULL;

	if(getifaddrs(&ifap) != -1) {
		for(ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if(strisequal(ifa->ifa_name, g.option.ifname) && ifa->ifa_addr->sa_family == AF_INET) {
				g.addr.unicast.s_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
				break;
			}
		}
	}
	freeifaddrs(ifap);
	if(!ifa) {
		error_abort("'%s' not found", g.option.ifname);
	}
}

static void
tcpeek_init_setuid(void) {
	struct passwd *passwd;
	gid_t groups[128];
	int ngroups;

	if(strisempty(g.option.user)) {
		return;
	}
	passwd = strisdigit(g.option.user) ? getpwuid((uid_t)strtol(g.option.user, NULL, 10)) : getpwnam(g.option.user);
	if(!passwd) {
		error_abort("%s", strerror(errno));
	}
	ngroups = sizeof(groups);
	if(getgrouplist(g.option.user, passwd->pw_gid, groups, &ngroups) == -1) {
		error_abort("getgrouplist: %s", strerror(errno));
	}
	if(setgroups(ngroups, groups) == -1) {
		error_abort("setgroups: %s", strerror(errno));
	}
	if(setgid(passwd->pw_gid) == -1) {
		error_abort("setgid: %s", strerror(errno));
	}
	if(setuid(passwd->pw_uid) == -1) {
		error_abort("setuid: %s", strerror(errno));
	}
}

static void
tcpeek_init_socket(void) {
	struct sockaddr_un sockaddr;

	g.soc = socket(PF_UNIX, SOCK_STREAM, 0);
	if(g.soc == -1) {
		error_abort("socket: %s", strerror(errno));
	}
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sun_family = PF_UNIX;
	strcpy(sockaddr.sun_path, g.option.socket);
	if(bind(g.soc, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
        close(g.soc);
        g.soc = -1;
		error_abort("bind: %s", strerror(errno));
	}
}

static void
usage(void) {
	printf("usage: %s [option]... [expression]...\n", PACKAGE_NAME);
	printf("  option:\n");
	printf("    -u --user=uid         # set uid\n");
	printf("    -i --interface=dev    # network device (ex: eth0)\n");
	printf("    -U --socket=path      # unix domain socket (default: /var/run/tcpeek/tcpeek.sock)\n");
	printf("    -c --checksum=[0|1|2] # ckecksum lookup mode 0=none 1=ip 2=tcp (default: 0)\n");
	printf("    -t --timeout=sec      # session timeout (default: 60)\n");
	printf("    -B --buffer=MB        # libpcap buffer size (default: 2)\n");
	printf("    -l --loglevel=LEVEL   # see man syslog (default: LOG_NOTICE)\n");
	printf("    -q --quiet            # quiet mode\n");
	printf("       --promisc          # enable promiscuous capture\n");
	printf("       --icmp             # enable icmp port unreachable lookup\n");
	printf("    -h --help             # help\n");
	printf("    -v --version          # version\n");
	printf("  expression:\n");
	printf("    filter:dir@addr:port[,port...]\n");
	printf("  example) '%%' is the same as wildcard '*'\n");
	printf("    tcpeek -i eth0 filter:IN@%%:80:443\n");
	printf("    tcpeek -i eth0 filter:OUT@192.168.0.0/24:%%\n");
	printf("    tcpeek -i eth0 inbound-filter:IN@%%:%% outbound-filter:OUT@192.168.0.100:%%,192.168.0.200:%%\n");
}

static void
version(void) {
	printf("%s %s (with %s)\n",PACKAGE_NAME, PACKAGE_VERSION, pcap_lib_version());
}
