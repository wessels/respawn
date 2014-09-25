#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/wait.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <signal.h>
#include <sys/signal.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <err.h>
#include <pwd.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN 512
#endif
#define DEFAULT_PID_FMT "/var/run/%s.pid"
int failcount = 5;
int failtime = 10;
char *pidfile = NULL;
char *userid = NULL;
char *ch_dir = NULL;
char *output = NULL;
int quit_signal = 0;
int opt_loop = 0;

void 
unlink_pid(void)
{
    if (pidfile)
	unlink(pidfile);
}

void
write_pid(const char *p)
{
    FILE *pf;
    char tb[128];
    pid_t pid;
    if (NULL == pidfile) {
	static char pid_path[MAXPATHLEN];
	const char *t = strrchr(p, '/');
	if (t)
	    p = t;
	snprintf(pid_path, MAXPATHLEN, DEFAULT_PID_FMT, p);
	pidfile = pid_path;
    }
    pf = fopen(pidfile, "r");
    if (NULL != pf) {
	fgets(tb, 128, pf);
	fclose(pf);
	strtok(tb, "\r\n");
	pid = strtol(tb, NULL, 10);
	if (pid > 0 && 0 == kill(pid, 0)) {
	    syslog(LOG_NOTICE, "Process %d already running\n", pid);
	    exit(0);
	}
    }
    pf = fopen(pidfile, "w");
    if (NULL != pf) {
	fprintf(pf, "%d\n", (int)getpid());
	atexit(unlink_pid);
	fclose(pf);
    }
}

void
usage(const char *me)
{
    fprintf(stderr, "usage: %s\n"
	"\t--loop\n"
	"\t--user=login\n"
	"\t--pidfile=path\n"
	"\t--fail-count=N\n"
	"\t--fail-time=N\n"
	"\t--stdouterr=file\n"
	"\t--chdir=dir\n"
	"\t--quit-signal=num\n", me);
    exit(1);
}

static struct option longopts[] = {
    {"loop", no_argument, &opt_loop, 1},
    {"user", required_argument, NULL, 'u'},
    {"pidfile", required_argument, NULL, 'p'},
    {"chdir", required_argument, NULL, 'c'},
    {"stdouterr", required_argument, NULL, 's'},
    {"quit-signal", required_argument, NULL, 'q'},
    {"fail-count", required_argument, NULL, 1001},
    {"fail-time", required_argument, NULL, 1002},
    {NULL, 0, NULL, 0}
};

int
main(int argc, char *argv[])
{
    pid_t pid = -1;
    int fd = -1;
    time_t start = 0;
    time_t stop = 0;
    int fails = 0;
    int status;
    char *appname;
    char *t;
    uid_t uid = 0;
    int ch;

    if ((t = strrchr(argv[0], '/')))
	appname = t + 1;
    else
	appname = argv[0];
    openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_DAEMON);

    while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
	switch (ch) {
	case 0:
	    /* e.g. --loop */
	    break;
	case 'u':
	    userid = strdup(optarg);
	    break;
	case 'p':
	    pidfile = strdup(optarg);
	    break;
	case 'c':
	    ch_dir = strdup(optarg);
	    break;
	case 's':
	    output = strdup(optarg);
	    break;
	case 'q':
	    quit_signal = atoi(optarg);
	    break;
	case 1001:
	    failcount = atoi(optarg);
	    break;
	case 1002:
	    failtime = atoi(optarg);
	    break;
	default:
	    usage(appname);
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if (userid) {
	struct passwd *p = getpwnam(userid);
	if (NULL == p)
	    errx(1, "Unknown user '%s'", userid);
	uid = p->pw_uid;
	setenv("HOME", p->pw_dir, 1);
    }
    if ((pid = fork()) < 0)
	syslog(LOG_ALERT, "fork failed: %s", strerror(errno));
    else if (pid > 0)
	exit(0);
    if (setsid() < 0)
	syslog(LOG_ALERT, "setsid failed: %s", strerror(errno));
    closelog();
#ifdef TIOCNOTTY
    if ((fd = open("/dev/tty", O_RDWR)) >= 0) {
	ioctl(fd, TIOCNOTTY, NULL);
	close(fd);
    }
#endif

    fd = open("/dev/null", O_RDWR);
    if (fd < 0)
	syslog(LOG_ERR, "/dev/null: %s\n", strerror(errno));
    else {
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	close(fd);
    }
    openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_DAEMON);

    for (;;) {
	if ((pid = fork()) == 0) {
	    /* child */
	    if (output) {
		fd = open(output, O_CREAT | O_WRONLY | O_APPEND, 0660);
		syslog(LOG_ERR, "output is %s\n", output);
		if (fd < 0)
		    syslog(LOG_ERR, "output: %s\n", strerror(errno));
		else {
		    dup2(fd, 1);
		    dup2(fd, 2);
		    close(fd);
		}
	    }
	    write_pid(argv[0]);
	    if (uid > 0) {
		syslog(LOG_NOTICE, "changing to user %s/%d", userid, uid);
		setuid(uid);
	    }
	    if (ch_dir)
		chdir(ch_dir);
	    syslog(LOG_NOTICE, "running '%s'", argv[0]);
	    execvp(argv[0], &argv[0]);
	    syslog(LOG_ALERT, "execvp '%s' failed: %s", argv[0], strerror(errno));
	}
	/* parent */
	openlog(appname, LOG_PID | LOG_NDELAY | LOG_CONS, LOG_DAEMON);
	time(&start);
	pid = waitpid(-1, &status, 0);
	time(&stop);

	if (WIFEXITED(status)) {
	    syslog(LOG_NOTICE, "child process %d exited with status %d",
		pid, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
	    syslog(LOG_NOTICE, "child process %d exited due to signal %d",
		pid, WTERMSIG(status));
	} else {
	    syslog(LOG_NOTICE, "child process %d exited", pid);
	}

	if (stop - start < failtime) {
	    fails++;
	    syslog(LOG_ALERT, "child process ran for %d seconds, fails=%d\n", stop-start,fails);
	} else
	    fails = 0;
	if (fails == failcount) {
	    syslog(LOG_ALERT, "Exiting due to repeated, frequent failures");
	    exit(1);
	}
	if (WIFEXITED(status))
	    if (0 == WEXITSTATUS(status) && 0 == opt_loop)
		exit(0);
	if (WIFSIGNALED(status)) {
	    if (quit_signal == WTERMSIG(status))
		exit(0);
	    switch (WTERMSIG(status)) {
	    case SIGKILL:
		exit(0);
		break;
	    default:
		break;
	    }
	}
    }
}
