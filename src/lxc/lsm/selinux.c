/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "config.h"
#include "log.h"
#include "lsm.h"

#define DEFAULT_LABEL "unconfined_t"

lxc_log_define(selinux, lsm);

/*
 * selinux_process_label_get: Get SELinux context of a process
 *
 * @pid     : the pid to get, or 0 for self
 *
 * Returns the context of the given pid. The caller must free()
 * the returned string.
 *
 * Note that this relies on /proc being available.
 */
static char *selinux_process_label_get(pid_t pid)
{
	security_context_t ctx;
	char *label;

	if (getpidcon_raw(pid, &ctx) < 0) {
		SYSERROR("failed to get SELinux context for pid %d", pid);
		return NULL;
	}
	label = strdup((char *)ctx);
	freecon(ctx);
	return label;
}

/*
 * selinux_process_label_set: Set SELinux context of a process
 *
 * @label   : label string
 * @conf    : the container configuration to use if @label is NULL
 * @default : use the default context if @label is NULL
 * @on_exec : the new context will take effect on exec(2) not immediately
 *
 * Returns 0 on success, < 0 on failure
 *
 * Notes: This relies on /proc being available.
 */
static int selinux_process_label_set(const char *inlabel, struct lxc_conf *conf,
				     bool on_exec)
{
	int ret;
	const char *label;

	label = inlabel ? inlabel : conf->lsm_se_context;
	if (!label) {

		label = DEFAULT_LABEL;
	}

	if (strcmp(label, "unconfined_t") == 0)
		return 0;

	if (on_exec)
		ret = setexeccon_raw((char *)label);
	else
		ret = setcon_raw((char *)label);
	if (ret < 0) {
		SYSERROR("Failed to set SELinux%s context to \"%s\"",
			 on_exec ? " exec" : "", label);
		return -1;
	}

	INFO("Changed SELinux%s context to \"%s\"", on_exec ? " exec" : "", label);
	return 0;
}

/*
 * selinux_mount_label_set: Set SELinux context of a file
 *
 * @path    : a file
 * @label   : label string
 *
 * Returns 0 on success, < 0 on failure
 */
static int selinux_mount_label_set(const char *path, const char *label)
{
	if (path == NULL || label == NULL || strcmp(label, "unconfined_t") == 0) {
		return 0;
	}

	if (!is_selinux_enabled()) {
		return 0;
	}

	if (lsetfilecon(path, label) != 0) {
		SYSERROR("Failed to setSELinux context to \"%s\": %s", label, path);
		return -1;
	}

	INFO("Changed SELinux context to \"%s\": %s", label, path);
	return 0;
}

/*
 * is_exclude_relabel_path: Determine whether it is a excluded path to label
 *
 * @path    : a file or directory
 *
 * Returns 0 on success, < 0 on failure
 */
static bool is_exclude_relabel_path(const char *path)
{
	const char *exclude_path[] = { "/", "/usr", "/etc", "/tmp", "/home", "/run", "/var", "/root" };
	size_t i;

	for (i = 0; i < sizeof(exclude_path) / sizeof(char *); i++) {
		if (strcmp(path, exclude_path[i]) == 0) {
			return true;
		}
	}

	return false;
}

/*
 * bad_prefix: Prevent users from relabing system files
 *
 * @path    : a file or directory
 *
 * Returns 0 on success, < 0 on failure
 */
static int bad_prefix(const char *fpath)
{
	const char *bad_prefixes = "/usr";

	if (fpath == NULL) {
		ERROR("Empty file path");
		return -1;
	}

	if (strncmp(fpath, bad_prefixes, strlen(bad_prefixes)) == 0) {
		ERROR("relabeling content in %s is not allowed", bad_prefixes);
		return -1;
	}

	return 0;
}

/*
 * recurse_set_mount_label: Recursively label files or folders
 *
 * @path    : a file or directory
 * @label   : label string
 *
 * Returns 0 on success, < 0 on failure
 */
static int recurse_set_mount_label(const char *basePath, const char *label)
{
	int ret = 0;
	__do_closedir DIR *dir = NULL;
	struct dirent *ptr = NULL;
	char base[PATH_MAX] = { 0 };

	if ((dir = opendir(basePath)) == NULL) {
		ERROR("Failed to Open dir: %s", basePath);
		return -1;
	}

	ret = lsetfilecon(basePath, label);
	if (ret != 0) {
		ERROR("Failed to set file label");
		return ret;
	}

	while ((ptr = readdir(dir)) != NULL) {
		if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
			continue;
		} else {
			int nret = snprintf(base, sizeof(base), "%s/%s", basePath, ptr->d_name);
			if (nret < 0 || nret >= sizeof(base)) {
				ERROR("Failed to get path");
				return -1;
			}
			if (ptr->d_type == DT_DIR) {
				ret = recurse_set_mount_label(base, label);
				if (ret != 0) {
					ERROR("Failed to set dir label");
					return ret;
				}
			} else {
				ret = lsetfilecon(base, label);
				if (ret != 0) {
					ERROR("Failed to set file label");
					return ret;
				}
			}
		}
	}

	return 0;
}

/*
 * selinux_chcon: Chcon changes the `fpath` file object to the SELinux label `label`.
 * If `fpath` is a directory and `recurse`` is true, Chcon will walk the
 * directory tree setting the label.
 *
 * @fpath   : a file or directory
 * @label   : label string
 * @recurse : whether to recurse
 *
 * Returns 0 on success, < 0 on failure
 */
static int selinux_chcon(const char *fpath, const char *label, bool recurse)
{
	struct stat s_buf;

	if (fpath == NULL || label == NULL) {
		return 0;
	}

	if (bad_prefix(fpath) != 0) {
		return -1;
	}
	if (stat(fpath, &s_buf) != 0) {
		return -1;
	}
	if (recurse && S_ISDIR(s_buf.st_mode)) {
		return recurse_set_mount_label(fpath, label);
	}

	if (lsetfilecon(fpath, label) != 0) {
		ERROR("Failed to set file label");
		return -1;
	}

	return 0;
}

/*
 * selinux_relabel: Relabel changes the label of path to the filelabel string.
 * It changes the MCS label to s0 if shared is true.
 * This will allow all containers to share the content.
 *
 * @path    : a file or directory
 * @label   : label string
 * @shared  : whether to use share mode
 *
 * Returns 0 on success, < 0 on failure
 */
static int selinux_relabel(const char *path, const char *label, bool shared)
{
	__do_free char *tmp_file_label = NULL;

	if (path == NULL || label == NULL) {
		return 0;
	}

	if (!is_selinux_enabled()) {
		return 0;
	}

	tmp_file_label = strdup(label);
	if (is_exclude_relabel_path(path)) {
		ERROR("SELinux relabeling of %s is not allowed", path);
		return -1;
	}

	if (shared) {
		context_t c = context_new(label);
		context_range_set(c, "s0");
		free(tmp_file_label);
		tmp_file_label = strdup(context_str(c));
		context_free(c);
	}

	if (selinux_chcon(path, tmp_file_label, true) != 0) {
		ERROR("Failed to modify %s's selinux context: %s", path, tmp_file_label);
		return -1;
	}

	return 0;
}

/*
 * selinux_keyring_label_set: Set SELinux context that will be assigned to the keyring
 *
 * @label   : label string
 *
 * Returns 0 on success, < 0 on failure
 */
static int selinux_keyring_label_set(char *label)
{
	return setkeycreatecon_raw(label);
};

static struct lsm_drv selinux_drv = {
	.name = "SELinux",
	.enabled           = is_selinux_enabled,
	.process_label_get = selinux_process_label_get,
	.process_label_set = selinux_process_label_set,
	.mount_label_set    = selinux_mount_label_set,
	.relabel           = selinux_relabel,
	.keyring_label_set = selinux_keyring_label_set,
};

struct lsm_drv *lsm_selinux_drv_init(void)
{
	if (!is_selinux_enabled())
		return NULL;
	return &selinux_drv;
}
