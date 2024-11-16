#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>

static bool running = true;
static sd_bus* bus = NULL;

static void exit_handler(const int signal) {
  (void)signal;
  running = false;
}

int main(void) {
  printf("WAT!\n");

  struct sigaction exit_action = { .sa_handler = exit_handler, .sa_flags = SA_RESTART };
  sigaction(SIGINT, &exit_action, NULL);
  sigaction(SIGTERM, &exit_action, NULL);

  printf("EXIT!\n");

  sd_bus_open_system(&bus);

  printf("LOOPING!\n");

  while (running) {
    printf(".");
    fflush(stdout);
    sd_bus_wait(bus, -1);
    sd_bus_process(bus, NULL);
  }

  printf("CLEANING!\n");

  sd_bus_unref(bus);

  printf("END!\n");

  return EXIT_SUCCESS;
}
