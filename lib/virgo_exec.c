/*
 *  Copyright 2012 Rackspace
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "virgo.h"
#include "virgo__types.h"
#include "virgo_error.h"
#include "virgo_paths.h"
#include "virgo_exec.h"
#include "virgo_versions.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

static char**
copy_args(virgo_t *v) {
  int i, index = 1;
  char **args;

  args = malloc((v->argc + 10) * sizeof(char*));

  for(i=1; i<v->argc; i++) {
    args[index++] = strdup(v->argv[i]);
  }

#ifndef _WIN32
  args[index++] = strdup("-o");
#else
  if (v->service_status.dwCurrentState == SERVICE_RUNNING) {
    args[index++] = strdup("--service-upgrade");
  } else {
    args[index++] = strdup("-o");
  }
#endif
  args[index++] = NULL;

  return args;
}

static void
free_args(char** args) {
  char** i;
  for (i = args; (*i) != NULL; ++i) {
    free(*i);
  }
  free(args);
}

extern char **environ;

static virgo_error_t*
virgo__exec(virgo_t *v, char *exe_path) {
  char **args = copy_args(v);
  int rc;
  int win_sc_started = 0;
  const char* name = "execve";

  args[0] = strdup(exe_path);

#ifdef _WIN32
  /* when running windows from the service manager */
  if (v->service_status.dwCurrentState == SERVICE_RUNNING) {
    win_sc_started = 1;
    name = "spawnve";
  }
  /* a child process must stop the service and perform the upgrade */
  if (!win_sc_started) {
    rc = execve(exe_path, args, environ);
  } else {
    rc = spawnve(P_NOWAIT, exe_path, args, environ);
  }
#else
  rc = execve(exe_path, args, environ);
#endif
  free_args(args);
  if (rc < 0) {
    return virgo_error_createf(VIRGO_ENOFILE, "%s failed errno=%i", name, errno);
  }
  return VIRGO_SUCCESS;
}

int
virgo__is_new_exe(const char* exe_path, const char* version)
{
  virgo_error_t *err = VIRGO_SUCCESS;
  const char* exe_path_version;
  const char* trailing_name = "-agent-";
  const int trailing_name_len = strlen(trailing_name);
  int ret = 0;
  /* Double check the upgraded version is greater than the running process */
  exe_path_version = strstr(exe_path, trailing_name);
  if (exe_path_version) {
    char* duped_exe_version = strdup(exe_path_version + trailing_name_len); /* skip -agent- and duplicate */
    char* extension = strstr(duped_exe_version, ".exe");
    if (extension) {
      *extension = '\0';
    }
    if (virgo__versions_compare(duped_exe_version, version) > 0) {
      /* Perform the upgrade if the exe is greater-than the currently running process. */
      ret = 1;
    }
    free(duped_exe_version);
  }
  return ret;
}

virgo_error_t*
virgo__exec_upgrade(virgo_t *v, int *perform_upgrade, virgo__exec_upgrade_cb status) {
  virgo_error_t *err;
  char latest_in_exe_path[VIRGO_PATH_MAX] = { '\0' };

  *perform_upgrade = FALSE;

  /* get the latest exe from the upgrade path */
  virgo__paths_get(v, VIRGO_PATH_EXE_DIR_LATEST, latest_in_exe_path, sizeof(latest_in_exe_path));

  /* Double check the upgraded version is greater than the running process */
  if (!virgo__is_new_exe(latest_in_exe_path, VIRGO_VERSION_FULL)) {
    /* Skip the upgrade if the exe is less-than or equal than the currently
     * running process.
     */
    return VIRGO_SUCCESS;
  }

  *perform_upgrade = TRUE;

  /* now we definately have an upgrade to run */

  /* a bit of info for the user */
  if (status) {
    status(v, "Attempting upgrade using new file(s):");
    status(v, "    exe: %s", latest_in_exe_path);
  }

#ifdef _WIN32
  if (v->service_status.dwCurrentState == SERVICE_RUNNING) {
    /* we're running as a service so we need to upgrade the exe into its proper place */
    if (status) {
      status(v, "Service Upgrading");
    }

    /* we run a child of the new exe to shut this service down and upgrade this exe file */
    err = virgo__exec(v, latest_in_exe_path);
    if (!err) {
      /* wait for the child to shut me down*/
      Sleep(INFINITE);
    }
  } else {
    /* we're not a service, behave like unix and execve the new exe */
    err = virgo__exec(v, latest_in_exe_path);
  }
#else
  /* execve the new exe */
  err = virgo__exec(v, latest_in_exe_path);
#endif
  return err;
}
