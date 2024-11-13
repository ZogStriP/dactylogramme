#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <unistd.h>

static sd_event *event = NULL;

static sd_bus *bus = NULL;
static sd_bus_message *pending_auth = NULL;

static char *fp_device = NULL;
static char *cookie = NULL;

static void cleanup(void) {
  if (cookie) free(cookie);
  if (fp_device) free(fp_device);
  if (pending_auth) sd_bus_message_unref(pending_auth);
  if (bus) sd_bus_flush_close_unref(bus);
  if (event) sd_event_unref(event);
}

static void release_device(void) {
  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "VerifyStop", NULL, NULL, NULL);
  sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "Release", NULL, NULL, NULL);
}

static int verify_status(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  (void)userdata;
  (void)error;

  char *result = NULL;
  bool success = false;
  int p[2] = { -1, -1 };
  int r;

  r = sd_bus_message_read(m, "s", &result);
  if (r < 0) {
    fprintf(stderr, "Failed to read fingerprint result: %s\n", strerror(-r));
    goto finish;
  }

  if (strcmp(result, "verify-match") == 0) {
    if (pipe(p) == -1) {
      fprintf(stderr, "Failed to create pipe: %s\n", strerror(errno));
      goto finish;
    }

    int pid = fork();

    if (pid == -1) {
      fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
      goto finish;
    }

    if (pid == 0) {
      char uid[20];
      snprintf(uid, sizeof(uid), "%d", getuid());

      if (dup2(p[0], STDIN_FILENO) == -1) {
        fprintf(stderr, "Failed to duplicate stdin: %s\n", strerror(errno));
        _exit(EXIT_FAILURE);
      }

      close(p[0]);
      close(p[1]);

      execl("/persist/z/poetry/dactylogramme-c/build/dactylogramme-helper", "dactylogramme-helper", uid, NULL);

      _exit(EXIT_FAILURE);
    }

    dprintf(p[1], "%s\n", cookie);

    close(p[0]);
    close(p[1]);

    int status;
    if (waitpid(pid, &status, 0) == -1) {
      fprintf(stderr, "Failed to wait: %s\n", strerror(errno));
      goto finish;
    }

    success = WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
  }

finish:
  if (p[0] != -1) close(p[0]);
  if (p[1] != -1) close(p[1]);

  if (success) {
    sd_bus_reply_method_return(pending_auth, NULL);
  } else {
    sd_bus_reply_method_errorf(pending_auth, "org.freedesktop.PolicyKit1.Error.Failed", "Authentication failed");
  }

  sd_bus_message_unref(pending_auth);
  pending_auth = NULL;

  release_device();

  return 0;
}

static int begin_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  (void)userdata;
  (void)error;

  int r;

  if (pending_auth) {
    fprintf(stderr, "Can only handle one authentication at a time.\n");
    return -1;
  }

  pending_auth = sd_bus_message_ref(m);

  r = sd_bus_message_skip(m, "sssa{ss}");
  if (r < 0) {
    fprintf(stderr, "Failed to skip begin authentication message arguments: %s\n", strerror(-r));
    return r;
  }

  r = sd_bus_message_read(m, "s", &cookie);
  if (r < 0) {
    fprintf(stderr, "Failed to read cookie: %s\n", strerror(-r));
    return r;
  }

  const char* username = getlogin();
  if (!username) {
    fprintf(stderr, "Failed to get username: %s\n", strerror(errno));
    return -errno;
  }
  
  r = sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "Claim", NULL, NULL, "s", username);
  if (r < 0) {
    fprintf(stderr, "Failed to claim fingerprint device: %s\n", strerror(-r));
    return r;
  }

  r = sd_bus_call_method(bus, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "VerifyStart", NULL, NULL, "s", "any");
  if (r < 0) {
    fprintf(stderr, "Failed to start fingerprint verification: %s\n", strerror(-r));
    release_device();
    return r;
  }

  return 1;
}

static int cancel_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  (void)m;
  (void)userdata;
  (void)error;

  release_device();

  return 0;
}

static const sd_bus_vtable vtable[] = {
  SD_BUS_VTABLE_START(0),
  SD_BUS_METHOD("BeginAuthentication", "sssa{ss}sa(sa{sv})", "", begin_authentication, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_METHOD("CancelAuthentication", "s", "", cancel_authentication, SD_BUS_VTABLE_UNPRIVILEGED),
  SD_BUS_VTABLE_END
};

int main(void) {
  int r;

  r = sd_event_default(&event);
  if (r < 0) {
    fprintf(stderr, "Failed to create event loop: %s\n", strerror(-r));
    goto finish;
  }

  r = sd_bus_open_system(&bus);
  if (r < 0) {
    fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
    goto finish;
  }

  r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
  if (r < 0) {
    fprintf(stderr, "Failed to attach bus to event loop: %s\n", strerror(-r));
    goto finish;
  }

  sd_bus_message *m = NULL;

  r = sd_bus_call_method(bus, "net.reactivated.Fprint", "/net/reactivated/Fprint/Manager", "net.reactivated.Fprint.Manager", "GetDefaultDevice", NULL, &m, NULL);
  if (r < 0) {
    fprintf(stderr, "Failed to get default fingerprint reader device: %s\n", strerror(-r));
    goto finish;
  }

  r = sd_bus_message_read(m, "o", &fp_device);
  if (r < 0) {
    fprintf(stderr, "Failed to read device path: %s\n", strerror(-r));
    goto finish;
  }

  sd_bus_message_unref(m);

  r = sd_bus_match_signal(bus, NULL, "net.reactivated.Fprint", fp_device, "net.reactivated.Fprint.Device", "VerifyStatus", verify_status, NULL);
  if (r < 0) {
    fprintf(stderr, "Failed to setup 'VerifyStatus' signal handler: %s\n", strerror(-r));
    goto finish;
  }

  r = sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/PolicyKit1/AuthenticationAgent", "org.freedesktop.PolicyKit1.AuthenticationAgent", vtable, NULL);
  if (r < 0) {
    fprintf(stderr, "Failed to add object vtable: %s\n", strerror(-r));
    goto finish;
  }

  const char *session_id = getenv("XDG_SESSION_ID");
  if (!session_id) {
    session_id = "1";
  }

  r = sd_bus_call_method(bus, 
    "org.freedesktop.PolicyKit1", 
    "/org/freedesktop/PolicyKit1/Authority",
    "org.freedesktop.PolicyKit1.Authority", 
    "RegisterAuthenticationAgent", 
    NULL, 
    NULL,
    "(sa{sv})ss", 
    "unix-session", 1, "session-id", "s", session_id,
    NULL /* locale */, 
    "/org/freedesktop/PolicyKit1/AuthenticationAgent");
  if (r < 0) {
    fprintf(stderr, "Failed to register authentication agent: %s\n", strerror(-r));
    goto finish;
  }

  r = sd_event_loop(event);
  if (r < 0) {
    fprintf(stderr, "Event loop failed: %s\n", strerror(-r));
  }

finish:
  cleanup();

  return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

