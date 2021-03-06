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
#include "virgo__agent_conf.h"
#include "virgo__conf.h"
#include "virgo__types.h"
#include "virgo__lua.h"
#include "virgo__util.h"
#include "uv.h"
#include "luv.h"
#include "luvit_init.h"
#include <stdlib.h>
#include <assert.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#endif

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * We hard code a check here for the version of OpenSSL we bundle inside deps, because its
 * too easily to accidently pull in an older version of OpenSSL on random platforms with
 * weird include paths.
 */
#if OPENSSL_VERSION_NUMBER != VIRGO_OPENSSL_VERSION_NUMBER
#error Invalid OpenSSL version number. Busted Include Paths?
#endif

static int global_virgo_init = 0;

#ifndef __linux__

void virgo__crash_reporter_init(virgo_t *p_v, const char *path)
{

}

void virgo__crash_reporter_destroy()
{

}

void virgo__force_dump()
{

}

#endif

static void
virgo__global_init(virgo_t **p_v) {
  if (global_virgo_init++) {
    return;
  }
  luvit_init_ssl();
}

static void
virgo__global_terminate(void)
{
    global_virgo_init--;
    /* TODO: cleanup more */
    if (global_virgo_init == 0) {
      virgo__crash_reporter_destroy();
    }
}

virgo_error_t*
virgo_create(virgo_t **p_v, const char *default_module, int argc, char** argv)
{
  virgo_t *v = NULL;

  virgo__global_init(&v);

  v = calloc(1, sizeof(virgo_t));
  v->lua_default_module = strdup(default_module);
  v->log_level = VIRGO_LOG_INFO;
  v->try_upgrade = TRUE;
  v->pid_fd = -1;

  v->argc = argc;
  v->argv = argv;

  *p_v = v;

  return VIRGO_SUCCESS;
}

short
virgo_try_upgrade(virgo_t *v) {
  return v->try_upgrade;
}

virgo_error_t*
virgo_init(virgo_t *v)
{
  virgo_error_t* err;

  if (virgo__argv_has_flag(v, "-v", "--version") == 1) {
    return virgo_error_create(VIRGO_EVERSIONREQ, "--version was passed");
  }

#ifdef _WIN32
  if (virgo__argv_has_flag(v, NULL, "--service-install") == 1) {
    return virgo__service_install(v);
  }

  if (virgo__argv_has_flag(v, NULL, "--service-delete") == 1) {
    return virgo__service_delete(v);
  }

  if (virgo__argv_has_flag(v, NULL, "--service-upgrade") == 1) {
    return virgo__service_upgrade(v);
  }
#endif

  err = virgo__lua_init(v);

  if (err ) {
    return err;
  }

  err = virgo__agent_conf_init(v);

  if (err) {
    return err;
  }

  return VIRGO_SUCCESS;
}

virgo_error_t*
virgo_run(virgo_t *v)
{
  virgo_error_t* err;

#ifndef _WIN32
  if (virgo__argv_has_flag(v, "-D", "--detach") == 1) {
    err = virgo_detach();
    if (err != VIRGO_SUCCESS) {
      return err;
    }
  }
#endif

  err = virgo__conf_init(v);

  if (err) {
    return err;
  }

  /* TOOD: restart support */
  err = virgo__lua_run(v);

  if (err) {
    return err;
  }

  return VIRGO_SUCCESS;
}

uv_loop_t* virgo_get_loop(virgo_t *v) {
  return luv_get_loop(v->L);
}

void
virgo_destroy(virgo_t *v)
{
  virgo__lua_destroy(v);

  if (v->config) {
    virgo__conf_destroy(v);
  }
  if (v->lua_load_path) {
    free((void*)v->lua_load_path);
  }
  if (v->lua_default_module) {
    free((void*)v->lua_default_module);
  }

  if (v->log_path) {
    free((void*)v->log_path);
  }
  if (v->log_fp && v->log_fp != stderr) {
    fclose(v->log_fp);
  }
  if (v->pid_fd >= 0) {
    close(v->pid_fd);
  }

  free((void*)v);

  virgo__global_terminate();
}

const char*
virgo_get_load_path(virgo_t *ctxt) {
  return ctxt->lua_load_path;
}
