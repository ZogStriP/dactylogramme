#define _GNU_SOURCE

#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

// TODO: write a small "agent-helper" that 
// - gets the UID as args and cookie as stdin
// - uses setuid to gain `root` privileges
// - calls `AuthenticationAgentResponse2`

// TODO: directly calls fprintd to do the auth in "begin_authentication"
// - Claim -> VerifyStart("any") -> VerifyStop -> Release

// TODO: listen to VerifyStatus event
// - change the led color
// - call the helper when 'status' == 'verify-match'

static bool has_prefix(const char* str, const char* prefix) {
  return strncmp(str, prefix, strlen(prefix)) == 0;
}

static int begin_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  char *cookie;

  sd_bus_message_skip(m, "sssa{ss}");
  sd_bus_message_read(m, "s", &cookie);

  // TODO: Claim -> VerifyStart
}

static int cancel_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  // TODO:
}

int main() {
  sd_bus *bus;

  sd_bus_open_system(&bus);

  sd_bus_add_object_vtable(bus, 
    NULL,
    "/org/freedesktop/PolicyKit1/AuthenticationAgent",
    "org.freedesktop.PolicyKit1.AuthenticationAgent",
    (sd_bus_vtable[]) {
      SD_BUS_VTABLE_START(0),
      SD_BUS_METHOD("BeginAuthentication", "sssa{ss}sa(sa{sv})", "", begin_authentication, SD_BUS_VTABLE_UNPRIVILEGED),
      SD_BUS_METHOD("CancelAuthentication", "s", "", cancel_authentication, SD_BUS_VTABLE_UNPRIVILEGED),
      SD_BUS_VTABLE_END
    },
    NULL);

  sd_bus_call_method(bus, 
    "org.freedesktop.PolicyKit1", 
    "/org/freedesktop/PolicyKit1/Authority",
    "org.freedesktop.PolicyKit1.Authority", 
    "RegisterAuthenticationAgent", 
    NULL, 
    NULL,
    "(sa{sv})ss", 
    "unix-session", 
    1, 
    "session-id", "s", getenv("XDG_SESSION_ID"),
    "" /* locale */, 
    "/org/freedesktop/PolicyKit1/AuthenticationAgent");

  for (;;) {
    sd_bus_wait(bus, -1);
    sd_bus_process(bus, NULL);
  }
}
