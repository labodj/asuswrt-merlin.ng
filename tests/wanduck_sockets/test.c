#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "socket.inc"

static void check_transport(int listener, int protocol)
{
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    assert(getsockname(listener, (void *)&address, &length) == 0);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int client = socket(AF_INET, protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, 0);
    assert(client >= 0);
    assert(connect(client, (void *)&address, length) == 0);
    assert(send(client, "x", 1, 0) == 1);
    int receiver = protocol == IPPROTO_TCP ? accept(listener, NULL, NULL) : listener;
    assert(receiver >= 0);
    char byte;
    assert(recv(receiver, &byte, 1, 0) == 1 && byte == 'x');
    if (receiver != listener)
        assert(close(receiver) == 0);
    assert(close(client) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "--child") == 0) {
        int ready = atoi(argv[2]), release = atoi(argv[3]);
        int socket_type;
        socklen_t length = sizeof(socket_type);
        char byte = getsockopt(atoi(argv[4]), SOL_SOCKET, SO_TYPE,
                              &socket_type, &length) == 0 ? 'i' : 'c';
        assert(write(ready, &byte, 1) == 1);
        assert(read(release, &byte, 1) == 1);
        return 0;
    }
    assert(argc == 2);
    int protocol = strcmp(argv[1], "tcp") == 0 ? IPPROTO_TCP : IPPROTO_UDP;
    int type = protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM;
    struct sockaddr_in address = { .sin_family = AF_INET };
    socklen_t length = sizeof(address);
    int probe = socket(AF_INET, type, protocol);
    assert(probe >= 0);
    assert(bind(probe, (void *)&address, length) == 0);
    assert(getsockname(probe, (void *)&address, &length) == 0);
    assert(close(probe) == 0);
    char port[16];
    snprintf(port, sizeof(port), "%u", ntohs(address.sin_port));
    int listener = passivesock(port, protocol, 1);
    assert(listener >= 0);
    int flags = fcntl(listener, F_GETFD);
    check_transport(listener, protocol);

    int ready[2], release[2];
    assert(pipe(ready) == 0 && pipe(release) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(close(ready[0]) == 0 && close(release[1]) == 0);
        char ready_fd[16], release_fd[16], listener_fd[16];
        snprintf(ready_fd, sizeof(ready_fd), "%d", ready[1]);
        snprintf(release_fd, sizeof(release_fd), "%d", release[0]);
        snprintf(listener_fd, sizeof(listener_fd), "%d", listener);
        execl(argv[0], argv[0], "--child", ready_fd, release_fd, listener_fd, (char *)NULL);
        _exit(127);
    }
    assert(close(ready[1]) == 0 && close(release[0]) == 0);
    char byte;
    assert(read(ready[0], &byte, 1) == 1);
    assert(close(ready[0]) == 0);
    assert(close(listener) == 0);
    /* The child has executed and remains alive until the parent releases it. */
    int replacement = passivesock(port, protocol, 1);
    assert(write(release[1], "x", 1) == 1);
    assert(close(release[1]) == 0);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (byte != 'c' || replacement < 0) {
        if (replacement >= 0)
            assert(close(replacement) == 0);
        fprintf(stderr, "FAIL: listener retained across exec\n");
        return 42;
    }
    assert(flags >= 0 && (flags & FD_CLOEXEC));
    check_transport(replacement, protocol);
    assert(close(replacement) == 0);
    return 0;
}
