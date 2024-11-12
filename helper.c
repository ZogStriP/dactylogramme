#include <systemd/sd-bus.h>

int main(int argc, char *argv[]) {
  sd_bus *bus = NULL;

  int uid = atoi(argv[1]);

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
    argv[2],
    "unix-user", 1, "uid", "u", uid
  );

  sd_bus_unref(bus);

  return -r;
}
