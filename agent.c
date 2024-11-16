#define _GNU_SOURCE

#include <stdlib.h>
#include <systemd/sd-bus.h>

#define FP_SERVICE "net.reactivated.Fprint"
#define FP_DEVICE_INTERFACE "net.reactivated.Fprint.Device"
#define FP_MANAGER_INTERFACE "net.reactivated.Fprint.Manager"
#define FP_MANAGER_PATH "/net/reactivated/Fprint/Manager"

#define PK_SERVICE "org.freedesktop.PolicyKit1"
#define PK_AUTHORITY_INTERFACE "org.freedesktop.PolicyKit1.Authority"
#define PK_AUTHORITY_PATH "/org/freedesktop/PolicyKit1/Authority"
#define PK_AUTH_AGENT_INTERFACE "org.freedesktop.PolicyKit1.AuthenticationAgent"
#define PK_AUTH_AGENT_PATH "/org/freedesktop/PolicyKit1/AuthenticationAgent"
#define PK_ERROR_FAILED "org.freedesktop.PolicyKit1.Error.Failed"

#define HELPER_PATH "/persist/z/poetry/dactylogramme-c/build/dactylogramme-helper"
#define HELPER_NAME "dactylogramme-helper"

static volatile sig_atomic_t running = 1;

static sd_bus *bus = NULL;
static sd_bus_message *pending_auth = NULL;

static char *fp_device = NULL;
static char *cookie = NULL;

static void exit_handler(const int signal) {
  (void)signal;
  running = 0;
}

static void release_device(void) {
  if (pending_auth) {
    sd_bus_message_unref(pending_auth);
    pending_auth = NULL;
  }

  sd_bus_call_method(bus, FP_SERVICE, fp_device, FP_DEVICE_INTERFACE, "VerifyStop", NULL, NULL, NULL);
  sd_bus_call_method(bus, FP_SERVICE, fp_device, FP_DEVICE_INTERFACE, "Release", NULL, NULL, NULL);
}

static int verify_status(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  (void)userdata;
  (void)error;

  int success = 0;
  int p[2] = { -1, -1 };
  char *result = NULL;

  sd_bus_message_read(m, "s", &result);

  if (strcmp(result, "verify-match") == 0) {
    pipe(p);

    if (fork() == 0) {
      char uid[20];
      snprintf(uid, sizeof(uid), "%d", getuid());

      dup2(p[0], STDIN_FILENO);

      close(p[0]);
      close(p[1]);

      execl(HELPER_PATH, HELPER_NAME, uid, NULL);

      _exit(EXIT_FAILURE);
    }

    dprintf(p[1], "%s\n", cookie);

    close(p[0]);
    close(p[1]);

    int status;
    wait(&status);

    success = WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
  }

  if (success) {
    sd_bus_reply_method_return(pending_auth, NULL);
  } else {
    sd_bus_reply_method_errorf(pending_auth, PK_ERROR_FAILED, "Authentication failed");
  }

  release_device();

  return 0;
}

static int begin_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  (void)userdata;
  (void)error;

  if (pending_auth) return -1;
  pending_auth = sd_bus_message_ref(m);
  
  sd_bus_message_skip(m, "sssa{ss}");
  sd_bus_message_read(m, "s", &cookie);

  sd_bus_call_method(bus, FP_SERVICE, fp_device, FP_DEVICE_INTERFACE, "Claim", NULL, NULL, "s", getlogin());
  sd_bus_call_method(bus, FP_SERVICE, fp_device, FP_DEVICE_INTERFACE, "VerifyStart", NULL, NULL, "s", "any");

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

int main() {
  struct sigaction sa = { .sa_handler = exit_handler, .sa_flags = SA_RESTART };
  sigaction(SIGINT,  &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  const char *session_id = getenv("XDG_SESSION_ID");
  if (!session_id) session_id = "1";

  sd_bus_open_system(&bus);

  sd_bus_message *m = NULL;
  sd_bus_call_method(bus, FP_SERVICE, FP_MANAGER_PATH, FP_MANAGER_INTERFACE, "GetDefaultDevice", NULL, &m, NULL);
  sd_bus_message_read(m, "o", &fp_device);
  sd_bus_message_unref(m);

  sd_bus_match_signal(bus, NULL, FP_SERVICE, fp_device, FP_DEVICE_INTERFACE, "VerifyStatus", verify_status, NULL);

  sd_bus_add_object_vtable(bus, NULL, PK_AUTH_AGENT_PATH, PK_AUTH_AGENT_INTERFACE, vtable, NULL);

  sd_bus_call_method(bus, 
    PK_SERVICE, 
    PK_AUTHORITY_PATH,
    PK_AUTHORITY_INTERFACE, 
    "RegisterAuthenticationAgent", 
    NULL, 
    NULL,
    "(sa{sv})ss", 
    "unix-session", 1, "session-id", "s", session_id,
    NULL /* locale */, 
    PK_AUTH_AGENT_PATH);

  while (running) {
    sd_bus_wait(bus, -1);
    sd_bus_process(bus, NULL);
  }

  sd_bus_unref(bus);

  return EXIT_SUCCESS;
}
