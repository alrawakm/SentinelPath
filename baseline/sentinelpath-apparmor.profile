#include <tunables/global>

profile sentinelpath-apparmor flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  /usr/bin/bash ix,
  /usr/bin/cat ix,
  /usr/bin/dash ix,
  /usr/bin/mv ix,
  /usr/bin/rm ix,

  /tmp/sentinelpath_apparmor_trials/ r,
  /tmp/sentinelpath_apparmor_trials/** rwkl,

  # The baseline policy names the protected path. Explicit deny rules override
  # the broader fixture permission above.
  deny /tmp/sentinelpath_apparmor_trials/protected.json wkl,
}
