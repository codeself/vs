#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libaudit.h"

#define AUDIT_MAX_KEY_LEN   16
#define UNUSE_RET           10

int list_requested = 0, interpret = 0;
char key[AUDIT_MAX_KEY_LEN+1];
const char key_sep[2] = { AUDIT_KEY_SEPARATOR, 0 };
static unsigned int keylen;
static int fd = -1;
static int add = AUDIT_FILTER_UNSET, del = AUDIT_FILTER_UNSET, action = -1;
static int ignore = 0, continue_error = 0;
static int exclude = 0;
static int multiple = 0;
static struct audit_rule_data *rule_new = NULL;

static struct option long_opts[] =
{
#if HAVE_DECL_AUDIT_FEATURE_VERSION == 1
  {"loginuid-immutable", 0, NULL, 1},
#endif
#if HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME == 1 || \
    HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME == 1
  {"backlog_wait_time", 1, NULL, 2},
#endif
#if HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL == 1
  {"reset_backlog_wait_time_actual", 0, NULL, 4},
#endif
  {"signal", 1, NULL, 5},
  {NULL, 0, NULL, 0}
};

static int reset_vars(void)
{
	list_requested = 0;
	_audit_syscalladded = 0;
	_audit_permadded = 0;
	_audit_archadded = 0;
	_audit_exeadded = 0;
	_audit_filterfsadded = 0;
	_audit_elf = 0;
	add = AUDIT_FILTER_UNSET;
	del = AUDIT_FILTER_UNSET;
	action = -1;
	exclude = 0;
	multiple = 0;

    if (rule_new)
	    audit_rule_free_data(rule_new);

    rule_new = NULL;
	rule_new = audit_rule_create_data();
	if (fd < 0) {
		if ((fd = audit_open()) < 0)
			return 1;
	}
	return 0;
}

static int lookup_filter(const char *str, int *filter)
{
	*filter = audit_name_to_flag(str);
	if (*filter == AUDIT_FILTER_EXCLUDE)
		exclude = 1;
	if (*filter == -1)
		return 2;
	return 0;
}

static int lookup_action(const char *str, int *act)
{
	if (strcmp(str, "always") == 0)
		*act = AUDIT_ALWAYS;
	else if (strcmp(str, "never") == 0)
		*act = AUDIT_NEVER;
	else if (strcmp(str, "possible") == 0)
		return 1;
	else
		return 2;
	return 0;
}

/*
 * Returns 0 ok, 1 deprecated action, 2 rule error,
 * 3 multiple rule insert/delete
 */
static int audit_rule_setup(char *opt, int *filter, int *act)
{
	int rc;
	char *p;

	if (++multiple != 1)
		return 3;

	p = strchr(opt, ',');
	if (p == NULL || strchr(p+1, ','))
		return 2;
	*p = 0;

	/* Try opt both ways */
	if (lookup_action(opt, act) == 2) {
		rc = lookup_filter(opt, filter);
		if (rc != 0) {
			*p = ',';
			return rc;
		}
	}

	/* Repair the string */
	*p = ',';
	opt = p+1;

	/* If flags are empty, p+1 must be the filter */
	if (*filter == AUDIT_FILTER_UNSET)
		lookup_filter(opt, filter);
	else {
		rc = lookup_action(opt, act);
		if (rc != 0)
			return rc;
	}

	/* Make sure we set both */
	if (*filter == AUDIT_FILTER_UNSET || *act == -1)
		return 2;

	return 0;
}

static int parse_syscall(const char *optarg)
{
	int retval = 0;
	char *saved;

	if (strchr(optarg, ',')) {
		char *ptr, *tmp = strdup(optarg);
		if (tmp == NULL)
			return -1;
		ptr = strtok_r(tmp, ",", &saved);
		while (ptr) {
			retval = audit_rule_syscallbyname_data(rule_new, ptr);
			if (retval != 0) {
				if (retval == -1) {
					retval = -3; // error reported
				}
				break;
			}
			ptr = strtok_r(NULL, ",", &saved);
		}
		free(tmp);
		return retval;
	}

	return audit_rule_syscallbyname_data(rule_new, optarg);
}

static int check_rule_mismatch(int lineno, const char *option)
{
	struct audit_rule_data tmprule;
	unsigned int old_audit_elf = _audit_elf;
	int rc = 0;

	switch (_audit_elf)
	{
		case AUDIT_ARCH_X86_64:
			_audit_elf = AUDIT_ARCH_I386;
			break;
		case AUDIT_ARCH_PPC64:
			_audit_elf = AUDIT_ARCH_PPC;
			break;
		case AUDIT_ARCH_S390X:
			_audit_elf = AUDIT_ARCH_S390;
			break;
	}

	char *ptr, *saved, *tmp = strdup(option);
	if (tmp == NULL)
		return -1;
	ptr = strtok_r(tmp, ",", &saved);
	memset(&tmprule, 0, sizeof(struct audit_rule_data));
	while (ptr) {
		audit_rule_syscallbyname_data(&tmprule, ptr);
		ptr = strtok_r(NULL, ",", &saved);
	}
	if (memcmp(tmprule.mask, rule_new->mask, AUDIT_BITMASK_SIZE))
		rc = 1;
	free(tmp);

	_audit_elf = old_audit_elf;
	if (rc) {
		if (lineno)
		else
	}
	return 0;
}

/*
 * This function will check the path before accepting it. It returns
 * 1 on error and 0 on success.
 */
static int check_path(const char *path)
{
	char *ptr, *base;
	size_t nlen;
	size_t plen = strlen(path);
	if (plen >= PATH_MAX) {
		return 1;
	}
	if (path[0] != '/') {
		return 1;
	}
	ptr = strdup(path);
	base = basename(ptr);
	nlen = strlen(base);
	free(ptr);
	if (nlen > NAME_MAX) {
		return 1;
	}

	return 0;
}

/*
 * Setup a watch.  The "name" of the watch in userspace will be the <path> to
 * the watch.  When this potential watch reaches the kernel, it will resolve
 * down to <name> (of terminating file or directory). 
 * Returns a 1 on success & -1 on failure.
 */
static int audit_setup_watch_name(struct audit_rule_data **rulep, char *path)
{
	int type = AUDIT_WATCH;
	size_t len;
	struct stat buf;

	if (check_path(path))
		return -1;

	// Trim trailing '/' should they exist
	len = strlen(path);
	if (len > 2 && path[len-1] == '/') {
		while (path[len-1] == '/' && len > 1) {
			path[len-1] = 0;
			len--;
		}
	}
	if (stat(path, &buf) == 0) {
		if (S_ISDIR(buf.st_mode))
			type = AUDIT_DIR;
	}
	/* FIXME: might want to check to see that rule is empty */
	if (audit_add_watch_dir(type, rulep, path)) 
		return -1;

	return 1;
}

static int equiv_parse(char *optarg, char **mp, char **sub)
{
	char *ptr = strchr(optarg, ',');
	if (ptr == NULL)
		return -1;	// no comma
	*ptr = 0;
	ptr++;
	if (*ptr == 0)
		return -1;	// ends with comma
	*mp = optarg;
	*sub = ptr;
	if (strchr(*sub, ','))
		return -1;	// too many commas
	return 0;
}

static int setopt(int count, int lineno, char *vars[])
{
	uint32_t rate;
	uint32_t limit;
    int c, lidx = 0;
    int retval = 0, rc;
	int flags = AUDIT_FILTER_UNSET;

    optind = 0;
    opterr = 0;
    key[0] = 0;
    keylen = AUDIT_MAX_KEY_LEN;

    while ((retval >= 0) && (c = getopt_long(count, vars,
			"icDtC:e:f:r:b:a:A:d:S:F:w:W:k:p:q:",
			long_opts, &lidx)) != EOF) {
	    flags = AUDIT_FILTER_UNSET;

	    rc = UNUSE_RET;
        switch (c) {
    	case 'i':
		    ignore = 1;
		    retval = -2;
		    break;
	    case 'c':
		    ignore = 1;
		    continue_error = 1;
		    retval = -2;
		    break;
        case 'e':
		    if (optarg && ((strcmp(optarg, "0") == 0) ||
		    		(strcmp(optarg, "1") == 0) ||
		    		(strcmp(optarg, "2") == 0))) {
		    	if (audit_set_enabled(fd, strtoul(optarg,NULL,0)) > 0)
		    		audit_request_status(fd);
		    	else
		    		retval = -1;
		    } else {
		    	retval = -1;
		    }
		    break;
        case 'f':
		    if (optarg && ((strcmp(optarg, "0") == 0) ||
		    		(strcmp(optarg, "1") == 0) ||
		    		(strcmp(optarg, "2") == 0))) {
		    	if (audit_set_failure(fd, strtoul(optarg,NULL,0)) <= 0)
		    	    return -1;
		    } else {
		    	retval = -1;
		    }
		    break;
        case 'r':
		    if (optarg && isdigit(optarg[0])) { 
		    	errno = 0;
		    	rate = strtoul(optarg,NULL,0);
		    	if (errno)
		    		return -1;
		    	
                if (audit_set_rate_limit(fd, rate) <= 0)
		    		return -1;
		    } else {
		    	retval = -1;
		    }
		    break;
        case 'b':
		    if (optarg && isdigit(optarg[0])) {
		    	errno = 0;
		    	limit = strtoul(optarg,NULL,0);
		    	if (errno)
		    		return -1;

		    	if (audit_set_backlog_limit(fd, limit) <= 0)
		    		return -1;
		    } else {
		    	retval = -1;
		    }
		    break;
        case 'a':
		    if (strstr(optarg, "task") && _audit_syscalladded) {
		    	retval = -1;
		    } else {
		    	rc = audit_rule_setup(optarg, &add, &action);
		    	if (rc == 3) {
		    		retval = -1;
		    	} else if (rc == 2) {
		    	    retval = -1;
		    	} else if (rc == 1) {
		    		return -3; /* deprecated - eat it */
		    	} else
		    		retval = 1; /* success - please send */
		    }
		    break;
        case 'A': 
		    if (strstr(optarg, "task") && _audit_syscalladded) {
		    	retval = -1;
		    } else {
		    	rc = audit_rule_setup(optarg, &add, &action);
		    	if (rc == 3) {
		    		retval = -1;
		    	} else if (rc == 2) {
		    		retval = -1;
		    	} else if (rc == 1) {
		    		return -3; /* deprecated - eat it */
		    	} else {
		    		add |= AUDIT_FILTER_PREPEND;
		    		retval = 1; /* success - please send */
		    	}
		    }
		    break;
        case 'd': 
		    rc = audit_rule_setup(optarg, &del, &action);
		    if (rc == 3) {
		    	retval = -1;
		    } else if (rc == 2) {
		    	retval = -1;
		    } else if (rc == 1) {
		    	return -3; /* deprecated - eat it */
		    } else
		    	retval = 1; /* success - please send */
		    break;
        case 'S': {
		    int unknown_arch = !_audit_elf;
#ifdef WITH_IO_URING
		    if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
		    		AUDIT_FILTER_URING_EXIT || (del &
		    		(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
		    		AUDIT_FILTER_URING_EXIT)) {
		    	// Do io_uring op
		    	rc = parse_io_uring(optarg);
		    	switch (rc)
		    	{
		    		case 0:
		    			_audit_syscalladded = 1;
		    			retval = 1; /* success - please send */
		    			break;
		    		case -1:
		    		retval = -1;
		    		break;
		    	}
		    	break;
		    }
#endif
		    /* Do some checking to make sure that we are not adding a
		     * syscall rule to a list that does not make sense. */
		    if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
		    		AUDIT_FILTER_TASK || (del & 
		    		(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) == 
		    		AUDIT_FILTER_TASK)) {
		    	return -1;
		    } else if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
		    		AUDIT_FILTER_USER || (del &
		    		(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
		    		AUDIT_FILTER_USER)) {
		    	return -1;
		    } else if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
		    		AUDIT_FILTER_FS || (del &
		    		(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
		    		AUDIT_FILTER_FS)) {
		    	return -1;
		    } else if (exclude) {
		    	return -1;
		    } else {
		    	if (unknown_arch) {
		    		int machine;
		    		unsigned int elf;
		    		machine = audit_detect_machine();
		    		if (machine < 0) {
		    			return -1;
		    		}
		    		elf = audit_machine_to_elf(machine);
                                    if (elf == 0) {
		    			return -1;
		    		}
		    		_audit_elf = elf;
		    	}
		    }
		    rc = parse_syscall(optarg);
		    switch (rc)
		    {
		    	case 0:
		    		_audit_syscalladded = 1;
		    		if (unknown_arch && add != AUDIT_FILTER_UNSET)
		    			if (check_rule_mismatch(lineno, optarg) == -1)
		    				retval = -1;
		    		break;
		    	case -1:
		    		retval = -1;
		    		break;
		    	case -2:
		    		retval = -1;
		    		break;
		    	case -3: // Error reported - do nothing here
		    		retval = -1;
		    		break;
		    }}
		    break;
        case 'F':
		    if (add != AUDIT_FILTER_UNSET)
		    	flags = add & AUDIT_FILTER_MASK;
		    else if (del != AUDIT_FILTER_UNSET)
		    	flags = del & AUDIT_FILTER_MASK;
		    // if the field is arch & there is a -t option...we 
		    // can allow it
		    else if ((optind >= count) || (strstr(optarg, "arch=") == NULL)
		    		 || (strcmp(vars[optind], "-t") != 0)) {
		    	retval = -1;
		    	break;
		    }

		    // Keys need to get handled differently
		    if (strncmp(optarg, "key=", 4) == 0) {
		    	optarg += 4;
		    	goto process_keys;
		    }
		    rc = audit_rule_fieldpair_data(&rule_new,optarg,flags);
		    if (rc != 0) {
		    	audit_number_to_errmsg(rc, optarg);
		    	retval = -1;
		    } else {
		    	if (rule_new->fields[rule_new->field_count-1] ==
		    				AUDIT_PERM)
		    		_audit_permadded = 1;
		    	if (rule_new->fields[rule_new->field_count-1] ==
		    				AUDIT_EXE) 
		    		_audit_exeadded = 1;
		    }

		    break;
	    case 'C':
	    	if (add != AUDIT_FILTER_UNSET)
	    		flags = add & AUDIT_FILTER_MASK;
	    	else if (del != AUDIT_FILTER_UNSET)
	    		flags = del & AUDIT_FILTER_MASK;

	    	rc = audit_rule_interfield_comp_data(&rule_new, optarg, flags);
	    	if (rc != 0) {
	    		audit_number_to_errmsg(rc, optarg);
	    		retval = -1;
	    	} else {
	    		if (rule_new->fields[rule_new->field_count - 1] ==
	    		    AUDIT_PERM)
	    			_audit_permadded = 1;
	    	}
	    	break;
	    case 'D':
	    	if (count > 4 || count == 3) {
	    		retval = -1;
	    		break;
	    	}
	    	if (count == 4) {
	    		if (strcmp(vars[optind], "-k") == 0) {
	    			strncat(key, vars[3], keylen);
	    			count -= 2;
	    		} else {
	    			retval = -1;
	    			break;
	    		}
	    	}
	    	retval = delete_all_rules(fd);
	    	if (retval == 0) {
	    		key[0] = 0;
	    		retval = -2;
	    	}
	    	break;
	    case 'w':
	    	if (add != AUDIT_FILTER_UNSET ||
	    		del != AUDIT_FILTER_UNSET) {
	    		retval = -1;
	    	} else if (optarg) {
	    		add = AUDIT_FILTER_EXIT;
	    		action = AUDIT_ALWAYS;
	    		_audit_syscalladded = 1;
	    		retval = audit_setup_watch_name(&rule_new, optarg);
	    	} else {
	    		retval = -1;
	    	}
	    	break;
	    case 'W':
	    	if (optarg) { 
	    		del = AUDIT_FILTER_EXIT;
	    		action = AUDIT_ALWAYS;
	    		_audit_syscalladded = 1;
	    		retval = audit_setup_watch_name(&rule_new, optarg);
	    	} else {
	    		retval = -1;
	    	}
	    	break;
	    case 'k':
	    	if (!(_audit_syscalladded || _audit_permadded ||
	    	      _audit_exeadded ||
	    	      _audit_filterfsadded) ||
	    	    (add==AUDIT_FILTER_UNSET && del==AUDIT_FILTER_UNSET)) {
	    		retval = -1;
	    		break;
	    	} else if (!optarg) {
	    		retval = -1;
	    		break;
	    	}
process_keys:
		    if ((strlen(optarg)+strlen(key)+(!!key[0])) >
		    					AUDIT_MAX_KEY_LEN) {
		    	retval = -1;
		    } else {
		    	if (strchr(optarg, AUDIT_KEY_SEPARATOR))
		    	if (key[0]) { // Add the separator if we need to
		    		strcat(key, key_sep);
		    		keylen--;
		    	}
		    	strncat(key, optarg, keylen);
		    	keylen = AUDIT_MAX_KEY_LEN - strlen(key);
		    }
		    break;
	    case 'p':
	    	if (add == AUDIT_FILTER_UNSET && del == AUDIT_FILTER_UNSET) {
	    		retval = -1;
	    	} else if (!optarg) {
	    		retval = -1;
	    	} else 
	    		retval = audit_setup_perms(rule_new, optarg);
	    	break;
        case 'q':
	    	if (_audit_syscalladded) {
	    		retval = -1;
	    	} else {
	    		char *mp, *sub;
	    		retval = equiv_parse(optarg, &mp, &sub);
	    		if (retval < 0) {
	    			retval = -1;
	    		} else {
	    			retval = audit_make_equivalent(fd, mp, sub);
	    			if (retval <= 0) {
	    				retval = -1;
	    			} else
	    				return -2; // success - no reply needed
	    		}
	    	}
	    	break;
        case 't':
	    	retval = audit_trim_subtrees(fd);
	    	if (retval <= 0)
	    		retval = -1;
	    	else
	    		return -2;  // success - no reply for this
	    	break;
	    
        // Now the long options
	    case 1:
	    	retval = audit_set_loginuid_immutable(fd);
	    	if (retval <= 0)
	    		retval = -1;
	    	else
	    		return -2;  // success - no reply for this
	    	break;
	    case 2:
#if HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME == 1 || \
    HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME == 1
		    if (optarg && isdigit(optarg[0])) {
		    	uint32_t bwt;
		    	errno = 0;
		    	bwt = strtoul(optarg,NULL,0);
		    	if (errno) {
		    		return -1;
		    	}
		    	if (audit_set_backlog_wait_time(fd, bwt) <= 0)
		    		return -1;
		    } else {
		    	retval = -1;
		    }
#else
		    retval = -1;
#endif
		    break;
	    case 4:
#if HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL == 1
		    if ((rc = audit_reset_backlog_wait_time_actual(fd)) >= 0) {
		    	return -2;
		    } else {
		    	retval = -1;
		    }
#else
		retval = -1;
#endif
		break;
        default: {
		    char *bad_opt;
		    if (optind >= 2)
		    	bad_opt = vars[optind -1];
		    else
		    	bad_opt = " ";
		    if (lineno)
		    else
		        retval = -1;
		    }
		    break;
        }
    }
    
    /* catch extra args or errors where the user types "- s" */
    if (optind == 1)
	    retval = -1;
    else if ((optind < count) && (retval != -1)) {
	    retval = -1;
    }

    /* See if we were adding a key */
    if (key[0] && list_requested == 0) {
	    int flags = 0;
	    char *cmd=NULL;

	    /* Get the flag */
	    if (add != AUDIT_FILTER_UNSET)
	    	flags = add & AUDIT_FILTER_MASK;
	    else if (del != AUDIT_FILTER_UNSET)
	    	flags = del & AUDIT_FILTER_MASK;

	    /* Build the command */
	    if (asprintf(&cmd, "key=%s", key) < 0) {
	    	cmd = NULL;
	    	retval = -1;
	    } else {
	    	/* Add this to the rule */
	    	int ret = audit_rule_fieldpair_data(&rule_new, cmd, flags);
	    	if (ret != 0) {
	    		retval = -1;
	    	}
	    	free(cmd);
	    }
    }
    
    return retval;
}

int vs_audit_rule_process(int argc, char *argv[])
{
    if (reset_vars())
        return VS_ERR;

    setopt(argc, 0, argv);
}		
