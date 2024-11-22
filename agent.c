#define _GNU_SOURCE

#include <stdlib.h>
#include <systemd/sd-bus.h>

static int begin_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  char *cookie = NULL;

  sd_bus_message_skip(m, "sssa{ss}");
  sd_bus_message_read(m, "s", &cookie);

  int p[2];
  pipe(p);

  if (fork() == 0) {
    dup2(p[0], STDIN_FILENO);

    close(p[0]);
    close(p[1]);

    execlp("polkit-agent-helper-1", "polkit-agent-helper-1", getenv("USER"), NULL);

    _exit(EXIT_FAILURE);
  }

  write(p[1], cookie, strlen(cookie));
  write(p[1], "\n", 1);

  close(p[0]);
  close(p[1]);

  wait(NULL);

  return sd_bus_reply_method_return(m, NULL);
}

int main() {
  sd_bus *bus = NULL;

  sd_bus_open_system(&bus);

  sd_bus_add_object_vtable(bus, 
    NULL, 
    "/org/freedesktop/PolicyKit1/AuthenticationAgent", 
    "org.freedesktop.PolicyKit1.AuthenticationAgent", 
    (sd_bus_vtable[]){ SD_BUS_VTABLE_START(0), SD_BUS_METHOD("BeginAuthentication", "sssa{ss}sa(sa{sv})", "", begin_authentication, SD_BUS_VTABLE_UNPRIVILEGED), SD_BUS_VTABLE_END }, 
    NULL);

  sd_bus_call_method(bus, 
    "org.freedesktop.PolicyKit1", 
    "/org/freedesktop/PolicyKit1/Authority",
    "org.freedesktop.PolicyKit1.Authority", 
    "RegisterAuthenticationAgent", 
    NULL, 
    NULL,
    "(sa{sv})ss", 
    "unix-session", 1, "session-id", "s", getenv("XDG_SESSION_ID"),
    NULL /* locale */, 
    "/org/freedesktop/PolicyKit1/AuthenticationAgent");

  for (;;) {
    sd_bus_wait(bus, -1);
    sd_bus_process(bus, NULL);
  }
}
