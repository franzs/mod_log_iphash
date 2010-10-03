/*
 * mod_log_iphash.c
 * $Id$
 *
 * Copyright 2010 Franz Schwartau <franz at electromail.org>
 *
 * based on mod_logio by Bojan Smojver
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This module adds new '%' directives to LogFormat:
 *
 * %Z:  md5 hashed ip address looking like IPv6 address
 *
 */

#include <stdlib.h>

#include "mod_log_config.h"
#include "http_config.h"
#include "http_log.h"
#include "util_md5.h"
#include "apr_strings.h"

#define SALT_SIZE 128
#define HASHED_BUF 64

module AP_MODULE_DECLARE_DATA log_iphash_module;

static const char log_iphash_filter_name[] = "LOG_IP_HASH";

typedef struct iphash_config_t {
	char salt[SALT_SIZE + 1];
} iphash_config_t;

/* seed_rand() copied from support/htpasswd.c */

static apr_status_t 
seed_rand(void)
{
	int		seed = 0;
	apr_status_t	rv;

	rv = apr_generate_random_bytes((unsigned char *)&seed, sizeof(seed));

	if (rv) {
		return rv;
	}

	srand(seed);

	return rv;
}

/* generate_salt() copied from support/htpasswd.c */

static void 
generate_salt(char *s, size_t size)
{
	static unsigned char tbl[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	size_t		     i;

	for (i = 0; i < size; ++i) {
		int idx = (int)(64.0 * rand() / (RAND_MAX + 1.0));
		s[i] = tbl[idx];
	}
}

static void *
iphash_create_server_config(apr_pool_t *p, server_rec *s)
{
	apr_status_t	rv;

	iphash_config_t *cf = apr_pcalloc(p, sizeof(iphash_config_t));
	memset(cf->salt, 0, sizeof(cf->salt));

	if ((rv = seed_rand())) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "Unable to generate random bytes: %pm", &rv);
	}

	generate_salt(cf->salt, SALT_SIZE);

	return cf;
}

/*
 * Format items...
 */

static const char *
log_ip_hash(request_rec * r, char *a)
{
	char           *hashed_ip;
	char           *salted_ip;
	char           *hashed_ipv6;
	char           *dest;
	apr_size_t	i = 0;
	apr_size_t	n = HASHED_BUF - 1;

	hashed_ipv6 = apr_pcalloc(r->pool, HASHED_BUF);

	iphash_config_t *cf = ap_get_module_config(r->server->module_config, &log_iphash_module);
	salted_ip = apr_pstrcat(r->pool, cf->salt, r->connection->remote_ip, NULL);

	hashed_ip = ap_md5(r->pool, (unsigned char *)salted_ip);

	dest = hashed_ipv6;

	do {
		if ((*dest++ = *hashed_ip++) == 0) {
			break;
		}

		if ((++i % 4 == 0) && *hashed_ip) {
			*dest++ = ':';

			if (--n == 0) {
				break;
			}
		}
	} while (--n != 0);

	return hashed_ipv6;
}

/*
 * The hooks...
 */

static int 
log_iphash_pre_config(apr_pool_t * p, apr_pool_t * plog, apr_pool_t * ptemp)
{
	static		APR_OPTIONAL_FN_TYPE(ap_register_log_handler) * log_pfn_register;

	log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

	if (log_pfn_register) {
		log_pfn_register(p, "Z", log_ip_hash, 0);
	}

	return OK;
}

static void 
register_hooks(apr_pool_t * p)
{
	ap_hook_pre_config(log_iphash_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

module AP_MODULE_DECLARE_DATA log_iphash_module =
{
	STANDARD20_MODULE_STUFF,
	NULL,			/* create per-dir config */
	NULL,			/* merge per-dir config */
	iphash_create_server_config,	/* server config */
	NULL,			/* merge server config */
	NULL,			/* command apr_table_t */
	register_hooks		/* register hooks */
};
