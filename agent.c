#define _GNU_SOURCE

#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

static sd_bus *bus = NULL;
static sd_event *event = NULL;

static int helper_cb(sd_event_source *s, const siginfo_t *si, void *userdata) {
  sd_bus_message *m = userdata;

  if (si->si_code == CLD_EXITED && si->si_status == EXIT_SUCCESS) {
    sd_bus_reply_method_return(m, NULL);
  } else {
    sd_bus_reply_method_errorf(m, "org.freedesktop.PolicyKit1.Error.Failed", "Authentication failed");
  }

  sd_bus_message_unref(m);

  return 0;
}

static int begin_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  char *cookie = NULL;

  sd_bus_message_skip(m, "sssa{ss}");
  sd_bus_message_read(m, "s", &cookie);

  int p[2];
  pipe(p);

  pid_t pid = fork();

  if (pid == 0) {
    dup2(p[0], STDIN_FILENO);

    close(p[0]);
    close(p[1]);

    execlp("polkit-agent-helper-1", "polkit-agent-helper-1", getlogin(), NULL);

    _exit(EXIT_FAILURE);
  }

  dprintf(p[1], "%s\n", cookie);

  close(p[0]);
  close(p[1]);

  sd_bus_message_ref(m);
  sd_event_add_child(event, NULL, pid, WEXITED, helper_cb, m);

  return 1;
}

static int cancel_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  printf("CANCEL!\n");
  return 0;
}

static int fprint_cb(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  const char *member = sd_bus_message_get_member(m);

  if (strcmp(member, "VerifyFingerSelected") == 0) {
    printf("FINGER\n"); // red
  } else if (strcmp(member, "VerifyStatus") == 0) {
    char *result = NULL;
    sd_bus_message_read(m, "s", &result);

    if (strcmp(result, "verify-match") == 0) {
      printf("YES!\n"); // green
      // sleep(500ms)
    }

    // white
  }

  return 0;
}

static const sd_bus_vtable vtable[] = {
  SD_BUS_VTABLE_START(0),
  SD_BUS_METHOD("BeginAuthentication", "sssa{ss}sa(sa{sv})", "", begin_authentication, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("CancelAuthentication", "s", "", cancel_authentication, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_VTABLE_END
};

int main() {
  sigset_t ss = { SIGCHLD };
  sigprocmask(SIG_BLOCK, &ss, NULL);

  sd_event_default(&event);
  sd_bus_open_system(&bus);
  sd_bus_attach_event(bus, event, 0);

  sd_bus_add_match(bus, NULL, "interface='net.reactivated.Fprint.Device'", fprint_cb, NULL);

  sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/PolicyKit1/AuthenticationAgent", "org.freedesktop.PolicyKit1.AuthenticationAgent", vtable, NULL);

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

  sd_event_loop(event);

  sd_bus_unref(bus);
  sd_event_unref(event);

  return EXIT_SUCCESS;
}
