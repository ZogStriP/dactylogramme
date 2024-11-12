#include <stdlib.h>
#include <systemd/sd-bus.h>

int main(int argc, char *argv[]) {
  sd_bus *bus = NULL;

  int uid = atoi(argv[1]);

  char cookie[100];
  fgets(cookie, sizeof(cookie), stdin);
  cookie[strcspn(cookie, "\n")] = 0;

  sd_bus_open_system(&bus);

  int r = sd_bus_call_method(bus,
    "org.freedesktop.PolicyKit1",
    "/org/freedesktop/PolicyKit1/Authority",
    "org.freedesktop.PolicyKit1.Authority",
    "AuthenticationAgentResponse2",
    NULL,
    NULL,
    "us(sa{sv})",
    uid,
    cookie,
    "unix-user", 1, "uid", "u", uid
  );

  sd_bus_unref(bus);

  return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
