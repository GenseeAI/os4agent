#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include "common/compiler.h"
#include "xmalloc.h"
#include "criu-log.h"
#include "util.h"
#include "mount.h"
#include "filesystems.h"

#undef LOG_PREFIX
#define LOG_PREFIX "overlayfs: "

static char *xlate_one_path(const char *path)
{
	struct mount_info *m, *best = NULL;
	int best_len = 0;
	const char *suffix;

	if (!path || path[0] != '/')
		return xstrdup(path ? path : "");

	for (m = mntinfo; m; m = m->next) {
		const char *mp = m->ns_mountpoint;
		int len;

		if (!mp || !mp[0])
			continue;
		if (mp[0] == '.')
			mp++;
		if (mp[0] != '/')
			continue;

		len = strlen(mp);
		while (len > 1 && mp[len - 1] == '/')
			len--;

		if (strncmp(path, mp, len) != 0)
			continue;
		if (path[len] != '\0' && path[len] != '/')
			continue;
		if (len > best_len) {
			best = m;
			best_len = len;
		}
	}

	if (!best) {
		pr_debug("no mount matches '%s'; passing through unchanged\n", path);
		return xstrdup(path);
	}

	suffix = path + best_len;
	return xsprintf("%s%s", service_mountpoint(best), suffix);
}

static char *xlate_colon_paths(const char *value)
{
	char *vbuf = xstrdup(value);
	char *result = NULL;
	char *path, *saveptr;

	if (!vbuf)
		return NULL;

	for (path = strtok_r(vbuf, ":", &saveptr); path; path = strtok_r(NULL, ":", &saveptr)) {
		char *new_path = xlate_one_path(path);

		if (!new_path)
			goto err;
		if (!result) {
			result = new_path;
		} else {
			char *t = xsprintf("%s:%s", result, new_path);

			xfree(result);
			xfree(new_path);
			if (!t)
				goto err;
			result = t;
		}
	}

	xfree(vbuf);
	return result ? result : xstrdup("");
err:
	xfree(vbuf);
	xfree(result);
	return NULL;
}


static char *xlate_one_option(const char *piece, size_t plen, int *err)
{
	static const char *path_keys[] = { "lowerdir", "upperdir", "workdir" };
	const char *eq;
	size_t klen;
	size_t i;
	char *vbuf;
	char *new_value;
	char *result;

	*err = 0;
	eq = memchr(piece, '=', plen);
	if (!eq)
		return NULL;
	klen = (size_t)(eq - piece);

	for (i = 0; i < ARRAY_SIZE(path_keys); i++) {
		if (klen != strlen(path_keys[i]))
			continue;
		if (strncmp(piece, path_keys[i], klen) != 0)
			continue;

		vbuf = strndup(eq + 1, plen - klen - 1);
		if (!vbuf) {
			*err = -1;
			return NULL;
		}
		new_value = xlate_colon_paths(vbuf);
		free(vbuf);
		if (!new_value) {
			*err = -1;
			return NULL;
		}
		result = xsprintf("%s=%s", path_keys[i], new_value);
		xfree(new_value);
		if (!result)
			*err = -1;
		return result;
	}
	return NULL;
}

static char *xlate_options(const char *options)
{
	char *result = NULL;
	const char *p;

	if (!options || !options[0])
		return xstrdup("");

	for (p = options; *p;) {
		const char *comma = strchr(p, ',');
		size_t plen = comma ? (size_t)(comma - p) : strlen(p);
		char *piece;
		char *t;
		int err = 0;

		piece = xlate_one_option(p, plen, &err);
		if (err)
			goto fail;
		if (!piece) {
			piece = strndup(p, plen);
			if (!piece)
				goto fail;
		}

		if (!result) {
			result = piece;
		} else {
			t = xsprintf("%s,%s", result, piece);
			xfree(result);
			xfree(piece);
			if (!t)
				goto fail;
			result = t;
		}

		p += plen;
		if (*p == ',')
			p++;
	}

	if (!result)
		result = xstrdup("");
	return result;
fail:
	xfree(result);
	return NULL;
}

int overlayfs_mount(struct mount_info *mi, const char *src, const char *fstype, unsigned long mountflags)
{
	char *new_opts;
	int ret;

	new_opts = xlate_options(mi->options);
	if (!new_opts) {
		pr_err("Failed to translate overlay mount options for id=%d\n", mi->mnt_id);
		return -1;
	}

	if (mi->options && strcmp(mi->options, new_opts) != 0)
		pr_info("translated mount-id %d opts:\n  src: %s\n  dst: %s\n", mi->mnt_id, mi->options, new_opts);

	ret = mount(src, service_mountpoint(mi), fstype, mountflags, new_opts);
	if (ret)
		pr_perror("Unable to mount overlay %s (id=%d) opts='%s'", service_mountpoint(mi), mi->mnt_id, new_opts);

	xfree(new_opts);
	return ret;
}
