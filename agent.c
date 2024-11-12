#define _GNU_SOURCE

#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

static sd_bus *bus = NULL;

static char *fp_device = NULL;
static char *cookie = NULL;
static char *result = NULL;

static sd_bus_message *pending_auth = NULL;

static bool str_equal(const char *a, const char *b) {
  if (a == NULL && b == NULL) return true;
  if (a == NULL || b == NULL) return false;
  return strcmp(a, b) == 0;
}

static bool has_prefix(const char *str, const char *prefix) {
  if (str == NULL || prefix == NULL) return false;
  return strncmp(str, prefix, strlen(prefix)) == 0;
}

static int verify_status(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  sd_bus_message_read(m, "s", &result);

  if (str_equal(result, "verify-match")) {
    int pid = fork();

    if (pid == 0) {
      char uid[20];
      snprintf(uid, sizeof(uid), "%d", getuid());

      // TODO: pass the cookie via stdin (pipe)
      execl("/persist/z/poetry/dactylogramme-c/build/dactylogramme-helper", "dactylogramme-helper", uid, cookie, NULL);

      _exit(1);
    }

    // TODO: check exit status code
    wait(NULL);

    sd_bus_reply_method_return(pending_auth, NULL);
  } else {
    sd_bus_reply_method_errorf(pending_auth, "org.freedesktop.PolicyKit1.Error.Failed", "Auth failed");
  }

  sd_bus_message_unref(pending_auth);

  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "VerifyStop", NULL, NULL, NULL);
  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "Release", NULL, NULL, NULL);

  return 0;
}

static int begin_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  pending_auth = sd_bus_message_ref(m);

  sd_bus_message_skip(m, "sssa{ss}");
  sd_bus_message_read(m, "s", &cookie);
  
  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "Claim", NULL, NULL, "s", getlogin());
  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "VerifyStart", NULL, NULL, "s", "any");

  return 1;
}

static int cancel_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "VerifyStop", NULL, NULL, NULL);
  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "Release", NULL, NULL, NULL);

  return 0;
}

int main() {
  sd_bus_message *m;

  sd_bus_open_system(&bus);

  sd_bus_call_method(bus, "net.reactivated.Fprint", "/net/reactivated/Fprint/Manager", "net.reactivated.Fprint.Manager", "GetDefaultDevice", NULL, &m, NULL);

  sd_bus_message_read(m, "o", &fp_device);

  sd_bus_match_signal(bus, NULL, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "VerifyStatus", verify_status, NULL);

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
    "unix-session", 1, "session-id", "s", getenv("XDG_SESSION_ID"),
    NULL /* locale */, 
    "/org/freedesktop/PolicyKit1/AuthenticationAgent");

  for (;;) {
    sd_bus_wait(bus, -1);
    sd_bus_process(bus, NULL);
  }
}
