#include "tcpeek.h"

static void
tcpeek_init_global(void);
static void
tcpeek_init_option(int argc, char *argv[]);
static void
tcpeek_init_signal(void);
static void
tcpeek_init_syslog(void);
static void
tcpeek_init_addr(void);
static void
tcpeek_init_session(void);
static void
tcpeek_init_filter_and_stat(void);
static void
tcpeek_init_pcap(void);
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
	tcpeek_init_syslog();
	tcpeek_init_addr();
	tcpeek_init_session();
	tcpeek_init_filter_and_stat();
	tcpeek_init_pcap();
	tcpeek_init_socket();
}

static void
tcpeek_init_global(void) {
	memset(&g, 0x00, sizeof(g));
	g.option.timeout = 60;
	g.option.checksum = TCPEEK_CKSUM_IP;
	g.option.expression = lnklist_create();
	g.stat = lnklist_create();
	g.filter = lnklist_create();
}

static void
tcpeek_init_option(int argc, char *argv[]) {
	int opt, index;
	static struct option optlist[] = {
		{"help",      0, NULL, 'h'},
		{"version",   0, NULL, 'V'},
		{"interface", 0, NULL, 'i'},
		{"checksum",  0, NULL, 'c'},
		{0, 0, 0, 0}
	};

	while((opt = getopt_long_only(argc, argv, "+hVi:c:", optlist, NULL)) != -1) {
		switch(opt) {
			case 'h':
				usage();
				tcpeek_terminate(0);
				break; // does not reached.
			case 'V':
				version();
				tcpeek_terminate(0);
				break; // does not reached.
			case 'i':
				strncpy(g.option.ifname, optarg, sizeof(g.option.ifname) - 1);
				break;
			case 'c':
				// TODO
				break;
			default:
				usage();
				tcpeek_terminate(1);
				break; // does not reached.
		}
	}
	for(index = optind; index < argc; index++){
		lnklist_add(g.option.expression, strdup(argv[index]), lnklist_size(g.option.expression));
	}
	if(lnklist_size(g.option.expression) < 1) {
		usage();
		tcpeek_terminate(1);
		// does not reached.
	}
}

static void
tcpeek_init_signal(void) {
	struct sigaction sig;

	memset(&sig, 0, sizeof(sig));
	sig.sa_handler = tcpeek_signal_handler;
	if(sigaction(SIGINT,  &sig, NULL) == -1){
		fprintf(stderr, "%s: sigaction error SIGINT\n", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
	if(sigaction(SIGTERM, &sig, NULL) == -1){
		fprintf(stderr, "%s: sigaction error SIGTERM\n", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
	if(sigaction(SIGPIPE, &sig, NULL) == -1){
		fprintf(stderr, "%s: sigaction error SIGPIPE\n", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
	if(sigaction(SIGUSR1, &sig, NULL) == -1){
		fprintf(stderr, "%s: sigaction error SIGUSR1\n", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
/*
	if(sigaction(SIGUSR2, &sig, NULL) == -1){
		fprintf(stderr, "%s: sigaction error SIGUSR2\n", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
*/
	if(sigaction(SIGALRM, &sig, NULL) == -1){
		fprintf(stderr, "%s: sigaction error SIGALRM\n", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
}

static void
tcpeek_init_syslog(void) {
	openlog(PACKAGE_NAME, LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
}

static void
tcpeek_init_addr(void) {
	struct ifaddrs *ifap, *ifa = NULL;

	if(getifaddrs(&ifap) != -1) {
		for(ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if(strisequal(ifa->ifa_name, g.option.ifname) && ifa->ifa_addr->sa_family == AF_INET) {
				g.addr.unicast.s_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
				syslog(LOG_DEBUG, "%s: [debug] unicast: %s\n", __func__, inet_ntoa(g.addr.unicast));
				break;
			}
		}
	}
	freeifaddrs(ifap);
	if(!ifa) {
		tcpeek_terminate(1);
		// does not reached.
	}
}

static void
tcpeek_init_session(void) {
	g.session.table = hashtable_create(TCPEEK_SESSION_TABLE_SIZE);
	if(!g.session.table) {
		syslog(LOG_ERR, "%s: [error] hashtable can't create.\n", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
	pthread_mutex_init(&g.session.mutex, NULL);
}

static void
tcpeek_init_filter_and_stat(void) {
	struct tcpeek_stat *stat;
	struct tcpeek_filter *filter;
	char *expression;

	if(!(g.stat = lnklist_create())) {
		syslog(LOG_ERR, "%s: [error] alloc error.", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
	if(!(g.filter = lnklist_create())) {
		syslog(LOG_ERR, "%s: [error] alloc error.", __func__);
		tcpeek_terminate(1);
		// does not reached.
	}
	lnklist_iter_init(g.option.expression);
	while(lnklist_iter_hasnext(g.option.expression)) {
		expression = lnklist_iter_next(g.option.expression);
		stat = tcpeek_stat_create();
		if(!lnklist_add_tail(g.stat, stat)) {
			tcpeek_stat_destroy(stat);
			syslog(LOG_ERR, "%s: [error] alloc error.", __func__);
			tcpeek_terminate(1);
			// does not reached.
		}
		filter = tcpeek_filter_create();
		if(!lnklist_add_tail(g.filter, filter)) {
			tcpeek_filter_destroy(filter);
			syslog(LOG_ERR, "%s: [error] alloc error.", __func__);
			tcpeek_terminate(1);
			// does not reached.
		}
		if(tcpeek_filter_parse(filter, expression) == -1) {
			syslog(LOG_ERR, "%s: [error] filter '%s' parse error.", __func__, expression);
			tcpeek_terminate(1);
			// does not reached.
		}
		filter->stat = stat;
	}
}

static void
tcpeek_init_pcap(void) {
	char errmsg[PCAP_ERRBUF_SIZE], *ifname, *expression;
	struct bpf_program bpf;

	if(g.option.ifname[0] == '\0') {
		ifname = pcap_lookupdev(errmsg);
		if(!ifname) {
			syslog(LOG_ERR, "%s: [error] %s\n", __func__, errmsg);
			tcpeek_terminate(1);
			// does not reached.
		}
		strncpy(g.option.ifname, ifname, sizeof(g.option.ifname) - 1);
	}
	g.pcap.pcap = pcap_open_live(g.option.ifname, 65535, g.option.promisc, 1, errmsg);
	if(!g.pcap.pcap) {
		syslog(LOG_ERR, "%s: [error] %s\n", __func__, errmsg);
		tcpeek_terminate(1);
		// does not reached.
	}
	expression = "tcp";
	if(pcap_compile(g.pcap.pcap, &bpf, expression, 0, 0) == -1) {
		syslog(LOG_ERR, "%s: [error] %s '%s'\n", __func__, pcap_geterr(g.pcap.pcap), expression);
		tcpeek_terminate(1);
		// does not reached.
	}
	if(pcap_setfilter(g.pcap.pcap, &bpf) == -1){
		syslog(LOG_ERR, "%s: [error] %s\n", __func__, pcap_geterr(g.pcap.pcap));
		tcpeek_terminate(1);
		// does not reached.
	}
	g.pcap.snapshot = pcap_snapshot(g.pcap.pcap);
	g.pcap.datalink = pcap_datalink(g.pcap.pcap);
	if(g.pcap.datalink != DLT_EN10MB && g.pcap.datalink != DLT_LINUX_SLL) {
		syslog(LOG_ERR, "%s: [error] not support datalink %s (%s)\n", __func__,
			pcap_datalink_val_to_name(g.pcap.datalink), pcap_datalink_val_to_description(g.pcap.datalink));
		tcpeek_terminate(1);
		// does not reached.
	}
}

static void
tcpeek_init_socket(void) {

}

static void
usage(void) {
	printf("usage: %s [option] [expression]\n", PACKAGE_NAME);
}

static void
version(void) {
	printf("%s %s (with %s)\n",PACKAGE_NAME, PACKAGE_VERSION, pcap_lib_version());
}
