#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#ifdef NDEBUG
#error These tests require assertions.
#endif

#define TRUE 1
#define FALSE 0
#define NAT_RULES "/simulated/nat_rules"
#define REDIRECT_RULES "/simulated/redirect_rules"
#define _dprintf(...) ((void)0)
#include "states.inc"

/* Only NVRAM, the ruleset and sysctl values are shared between test processes. */
static struct {
	int nat_state, rules_state;
	unsigned udp_timeout, udp_stream_timeout, icmp_timeout;
	int redirect_enabled, first_use;
	int missing_rules, restore_error, lock_error;
	int hooks, restores, signals_handled;
	int rules_version, applied_version;
	char configured_udp[32];
} *state;

enum pause_point { NO_PAUSE, ICMP_WAIT, UDP_WRITE, RULES_APPLIED };
static enum pause_point pause_at;
static int paused, lock_held, announce_lock_attempt;
static int ready[2], resume_pipe[2], contender[2];
int start_nat_rules(void);
int stop_nat_rules(void);

static void notify_process(int fd)
{
	assert(write(fd, "x", 1) == 1);
}

static void wait_for_process(int fd)
{
	char byte;
	struct pollfd event = {fd, POLLIN, 0};
	assert(poll(&event, 1, 5000) == 1);
	assert(read(fd, &byte, 1) == 1);
}

static void pause_transition(enum pause_point point)
{
	if (pause_at != point || paused)
		return;
	paused = 1;
	notify_process(ready[1]);
	wait_for_process(resume_pipe[0]);
}

/* The firmware lock implementation, including its preprocessor configuration. */
#include "locks.inc"
static int file_lock(const char *tag)
{
	int fd;
	if (state->lock_error)
		return -1;
	if (announce_lock_attempt) {
		announce_lock_attempt = 0;
		notify_process(contender[1]);
	}
	fd = _file_lock(".", tag);
	if (fd >= 0)
		lock_held++;
	return fd;
}

static void file_unlock(int fd)
{
	assert(lock_held == 1);
	lock_held--;
	assert(_file_unlock(fd) == 0);
}

static int nvram_get_int(const char *key)
{
	if (!strcmp(key, "nat_state"))
		return state->nat_state;
	if (!strcmp(key, "nat_redirect_enable"))
		return state->redirect_enabled;
	return 0;
}

static void nvram_set_int(const char *key, int value)
{
	assert(!strcmp(key, "nat_state"));
	state->nat_state = value;
}

static int nvram_match(const char *key, const char *value)
{
	return !strcmp(key, "x_Setting") && !strcmp(value, "0") && state->first_use;
}

static const char *nvram_safe_get(const char *key)
{
	return !strcmp(key, "ct_udp_timeout") ? state->configured_udp : "600 30";
}

static void nvram_set(const char *key, const char *value)
{
	assert(!strcmp(key, "ct_udp_timeout"));
	assert(strlen(value) < sizeof(state->configured_udp));
	strcpy(state->configured_udp, value);
}

static void write_udp_timeout(const char *name, unsigned value)
{
	pause_transition(UDP_WRITE);
	if (name)
		state->udp_stream_timeout = value;
	else
		state->udp_timeout = value;
}

static unsigned read_udp_timeout(const char *name)
{
	return name ? state->udp_stream_timeout : state->udp_timeout;
}

static void write_ct_timeout(const char *protocol, const char *name, unsigned value)
{
	(void)protocol;
	(void)name;
	state->icmp_timeout = value;
}

static unsigned read_ct_timeout(const char *protocol, const char *name)
{
	(void)protocol;
	(void)name;
	return state->icmp_timeout;
}

static int scan_icmp_unreplied_conntrack(void)
{
	return pause_at == ICMP_WAIT && !paused;
}

static unsigned fake_sleep(unsigned seconds)
{
	(void)seconds;
	pause_transition(ICMP_WAIT);
	return 0;
}
#define sleep fake_sleep
#include "timeouts.inc"

static int fake_lstat(const char *path, struct stat *info)
{
	(void)path;
	if (state->missing_rules)
		return -1;
	memset(info, 0, sizeof(*info));
	info->st_mode = S_IFREG;
	info->st_size = 100;
	return 0;
}
#define lstat fake_lstat

static int eval(const char *command, const char *path)
{
	assert(!strcmp(command, "iptables-restore"));
	if (state->restore_error)
		return 1;
	state->rules_state = !strcmp(path, NAT_RULES) ? NAT_STATE_NORMAL : NAT_STATE_REDIRECT;
	if (state->rules_state == NAT_STATE_NORMAL)
		state->applied_version = state->rules_version;
	state->restores++;
	pause_transition(RULES_APPLIED);
	return 0;
}

static void rule_apply_checking(const char *file, int line, const char *rules, int result)
{
	(void)file;
	(void)line;
	(void)rules;
	(void)result;
}

static void run_custom_script(const char *name, int timeout, void *arg1, void *arg2)
{
	(void)name;
	(void)timeout;
	(void)arg1;
	(void)arg2;
	assert(!lock_held);
	state->hooks++;
}
#include "services.inc"

#ifndef HAVE_RELOAD_NAT_RULES
/* The old callers requested a reload by writing NVRAM before calling start. */
static int reload_nat_rules(void)
{
	nvram_set_int("nat_state", NAT_STATE_UPDATE);
	return start_nat_rules();
}
#endif

static int term_blocked(void)
{
	sigset_t mask;
	assert(sigprocmask(SIG_SETMASK, NULL, &mask) == 0);
	return sigismember(&mask, SIGTERM);
}

static void assert_normal(void)
{
	assert(state->nat_state == NAT_STATE_NORMAL);
	assert(state->rules_state == NAT_STATE_NORMAL);
	assert(state->udp_timeout == 30 && state->udp_stream_timeout == 180);
}

static void assert_redirected(void)
{
	assert(state->nat_state == NAT_STATE_REDIRECT);
	assert(state->rules_state == NAT_STATE_REDIRECT);
	assert(state->udp_timeout == 1 && state->udp_stream_timeout == 6);
}

static void test_stop_and_start(void)
{
	assert(stop_nat_rules() == NAT_STATE_REDIRECT);
	assert_redirected();
	assert(start_nat_rules() == NAT_STATE_NORMAL);
	assert_normal();
	assert(state->hooks == 1);
}

static void test_restore_stale_timeouts(void)
{
	state->udp_timeout = 1;
	state->udp_stream_timeout = 6;
	start_nat_rules();
	assert_normal();
	assert(state->restores == 0 && state->hooks == 0);
}

static void test_custom_timeouts(void)
{
	strcpy(state->configured_udp, "42 300");
	start_nat_rules();
	assert(state->udp_timeout == 42 && state->udp_stream_timeout == 300);
}

static void test_redirect_disabled(void)
{
	state->redirect_enabled = 0;
	assert(stop_nat_rules() == NAT_STATE_NORMAL);
	assert_normal();
	assert(state->restores == 0);
}

static void test_first_use(void)
{
	state->first_use = 1;
	assert(start_nat_rules() == NAT_STATE_REDIRECT);
	assert(reload_nat_rules() == NAT_STATE_REDIRECT);
	assert_redirected();
	assert(state->restores == 1 && state->hooks == 0);
}

static void test_already_redirected(void)
{
	stop_nat_rules();
	stop_nat_rules();
	assert_redirected();
	assert(state->restores == 1);
}

static void test_stop_restore_error(void)
{
	state->restore_error = 1;
	assert(stop_nat_rules() == NAT_STATE_NORMAL);
	assert_normal();
	state->restore_error = 0;
	stop_nat_rules();
	assert_redirected();
}

static void test_start_restore_error(void)
{
	stop_nat_rules();
	state->restore_error = 1;
	assert(start_nat_rules() == NAT_STATE_REDIRECT);
	assert_redirected();
	assert(state->hooks == 0);
	state->restore_error = 0;
	start_nat_rules();
	assert_normal();
}

static void test_missing_rules(void)
{
	stop_nat_rules();
	state->missing_rules = 1;
	assert(start_nat_rules() == NAT_STATE_REDIRECT);
	assert_redirected();
	state->missing_rules = 0;
	start_nat_rules();
	assert_normal();
}

static void test_lock_error(void)
{
	state->lock_error = 1;
	stop_nat_rules();
	assert_normal();
	assert(!term_blocked());
	state->lock_error = 0;
	stop_nat_rules();
	state->lock_error = 1;
	start_nat_rules();
	assert_redirected();
	assert(!term_blocked());
	state->lock_error = 0;
	start_nat_rules();
	assert_normal();
}

static void test_preserve_signal_mask(void)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	assert(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
	stop_nat_rules();
	start_nat_rules();
	assert_normal();
	assert(term_blocked());
	assert(sigprocmask(SIG_UNBLOCK, &mask, NULL) == 0);
}

static void test_reload_normal(void)
{
	state->rules_version = 2;
	assert(reload_nat_rules() == NAT_STATE_NORMAL);
	assert_normal();
	assert(state->applied_version == 2 && state->hooks == 1);
}

static void test_reload_restore_error(void)
{
	state->restore_error = 1;
	assert(reload_nat_rules() == NAT_STATE_UPDATE);
	assert(state->hooks == 0);
	state->restore_error = 0;
	start_nat_rules();
	assert_normal();
	assert(state->hooks == 1);
}

static void reenter_on_term(int signal_number)
{
	(void)signal_number;
	state->signals_handled++;
	pause_at = NO_PAUSE;
	reload_nat_rules(); /* wanduck's safe_leave forces a reload before exiting. */
	_exit(0);
}

static void joined(pid_t pid)
{
	int status;
	assert(waitpid(pid, &status, 0) == pid);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static pid_t start_paused_transition(int (*transition)(void), enum pause_point point)
{
	pid_t pid;
	assert(pipe(ready) == 0 && pipe(resume_pipe) == 0 && pipe(contender) == 0);
	pid = fork();
	assert(pid >= 0);
	if (!pid) {
		alarm(10);
		pause_at = point;
		assert(signal(SIGTERM, reenter_on_term) != SIG_ERR);
		transition();
		_exit(0);
	}
	wait_for_process(ready[0]);
	return pid;
}

static pid_t start_waiting_transition(int (*transition)(void))
{
	pid_t pid = fork();
	assert(pid >= 0);
	if (!pid) {
		alarm(10);
		assert(signal(SIGTERM, reenter_on_term) != SIG_ERR);
		announce_lock_attempt = 1;
		transition();
#ifdef TEST_BASELINE
		/* No lock in the original code: complete start before resuming stop. */
		notify_process(contender[1]);
#endif
		_exit(0);
	}
	wait_for_process(contender[0]);
	return pid;
}

static void test_start_during_stop(void)
{
	pid_t stopping = start_paused_transition(stop_nat_rules, ICMP_WAIT);
	pid_t starting = start_waiting_transition(start_nat_rules);
	notify_process(resume_pipe[1]);
	joined(stopping);
	joined(starting);
	assert_normal();
}

static void test_stop_during_start(void)
{
	pid_t starting, stopping;
	stop_nat_rules();
	starting = start_paused_transition(start_nat_rules, UDP_WRITE);
	stopping = start_waiting_transition(stop_nat_rules);
	notify_process(resume_pipe[1]);
	joined(starting);
	joined(stopping);
	assert_redirected();
}

static void test_reload_during_start(void)
{
	pid_t starting, reloading;
	stop_nat_rules();
	starting = start_paused_transition(start_nat_rules, RULES_APPLIED);
	/* nat_setting publishes a new rules file while the old one is being applied. */
	state->rules_version = 2;
	reloading = start_waiting_transition(reload_nat_rules);
	notify_process(resume_pipe[1]);
	joined(starting);
	joined(reloading);
	assert_normal();
	assert(state->applied_version == 2);
}

static void test_reload_during_stop(void)
{
	pid_t stopping = start_paused_transition(stop_nat_rules, ICMP_WAIT);
	pid_t reloading;
	state->rules_version = 2;
	reloading = start_waiting_transition(reload_nat_rules);
	notify_process(resume_pipe[1]);
	joined(stopping);
	joined(reloading);
	assert_normal();
	assert(state->applied_version == 2);
}

static void test_sigterm_while_locked(void)
{
	pid_t stopping = start_paused_transition(stop_nat_rules, ICMP_WAIT);
	assert(kill(stopping, SIGTERM) == 0);
	assert(state->signals_handled == 0);
	notify_process(resume_pipe[1]);
	joined(stopping);
	assert_normal();
	assert(state->signals_handled == 1);
}

static void test_sigterm_while_waiting(void)
{
	pid_t stopping = start_paused_transition(stop_nat_rules, ICMP_WAIT);
	pid_t starting = start_waiting_transition(start_nat_rules);
	assert(kill(starting, SIGTERM) == 0);
	assert(state->signals_handled == 0);
	notify_process(resume_pipe[1]);
	joined(stopping);
	joined(starting);
	assert_normal();
	assert(state->signals_handled == 1);
}

static void test_stress(void)
{
	pid_t starting, stopping;
	int i;
	starting = fork();
	assert(starting >= 0);
	if (!starting) {
		alarm(10);
		for (i = 0; i < 200; i++) {
			stop_nat_rules();
			start_nat_rules();
		}
		_exit(0);
	}
	stopping = fork();
	assert(stopping >= 0);
	if (!stopping) {
		alarm(10);
		for (i = 0; i < 200; i++) {
			start_nat_rules();
			stop_nat_rules();
		}
		_exit(0);
	}
	joined(starting);
	joined(stopping);
	if (state->nat_state == NAT_STATE_NORMAL)
		assert_normal();
	else
		assert_redirected();
}

static const struct {
	const char *name;
	void (*run)(void);
} tests[] = {
    {"stop_and_start", test_stop_and_start},
    {"restore_stale_timeouts", test_restore_stale_timeouts},
    {"custom_timeouts", test_custom_timeouts},
    {"redirect_disabled", test_redirect_disabled},
    {"first_use", test_first_use},
    {"already_redirected", test_already_redirected},
    {"stop_restore_error", test_stop_restore_error},
    {"start_restore_error", test_start_restore_error},
    {"missing_rules", test_missing_rules},
    {"lock_error", test_lock_error},
    {"preserve_signal_mask", test_preserve_signal_mask},
    {"reload_normal", test_reload_normal},
    {"reload_restore_error", test_reload_restore_error},
    {"start_during_stop", test_start_during_stop},
    {"stop_during_start", test_stop_during_start},
    {"reload_during_start", test_reload_during_start},
    {"reload_during_stop", test_reload_during_stop},
    {"sigterm_while_locked", test_sigterm_while_locked},
    {"sigterm_while_waiting", test_sigterm_while_waiting},
    {"stress", test_stress},
};

int main(int argc, char **argv)
{
	size_t i;
	if (argc == 2 && !strcmp(argv[1], "--list")) {
		for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
			puts(tests[i].name);
		return 0;
	}
	if (argc != 2)
		return 2;
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		if (strcmp(argv[1], tests[i].name))
			continue;
		alarm(10);
		state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
			     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		assert(state != MAP_FAILED);
		state->nat_state = state->rules_state = NAT_STATE_NORMAL;
		state->udp_timeout = 30;
		state->udp_stream_timeout = 180;
		state->icmp_timeout = 30;
		state->redirect_enabled = 1;
		state->rules_version = state->applied_version = 1;
		strcpy(state->configured_udp, "30 180");
		tests[i].run();
		assert(!lock_held && !term_blocked());
		return 0;
	}
	fprintf(stderr, "Unknown test: %s\n", argv[1]);
	return 2;
}
