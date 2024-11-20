#define _GNU_SOURCE

#include <systemd/sd-bus.h>

static int fprint_cb(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  char *member = sd_bus_message_get_member(m);

  // TODO: control the power LED using syfs
  // -> /sys/class/leds/chromeos:multicolor:power/

  if (strcmp(member, "VerifyFingerSelected") == 0) {
    printf("FINGER\n");
  } else if (strcmp(member, "VerifyStatus") == 0) {
    char *result = NULL;
    sd_bus_message_read(m, "s", &result);

    if (strcmp(result, "verify-match") == 0) {
      printf("YES!\n");
    }
  }

  return 0;
}

int main() {
  sd_bus *bus = NULL;
  sd_bus_open_system(&bus);
  sd_bus_add_match(bus, NULL, "interface='net.reactivated.Fprint.Device'", fprint_cb, NULL);

  for (;;) {
    sd_bus_wait(bus, -1);
    sd_bus_process(bus, NULL);
  }
}
