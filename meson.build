project('dactylogramme', 'c', version: '0.0.1', default_options: ['warning_level=3', 'c_std=c11'])
systemd = dependency('libsystemd')
executable('dactylogramme-agent', 'agent.c', dependencies: [systemd])
executable('dactylogramme-helper', 'helper.c', dependencies: [systemd])
