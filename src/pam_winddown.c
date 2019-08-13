/*****************************************************************************\
 *  pam_winddown.c
 *****************************************************************************
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  Copyright (C) 2008-2009 Lawrence Livermore National Security.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  UCRL-CODE-2002-040.
 *
 *  Based on pam_slurm written by Chris Dunlap <cdunlap@llnl.gov>
 *         and Jim Garlick  <garlick@llnl.gov>
 *         modified for Slurm by Moe Jette <jette@llnl.gov>.
 *         modified as pam_winddown by Joel Best <jbest@uoguelph.ca>
 *
 *  This file is part of pam_winddown, a PAM module for limiting access to
 *  a server to only those who have existing sessions. This helps sysadmins
 *  to bring a node down to maintenance without kicking off active users.
 *
 *  pam_winddown is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at your
 *  option) any later version.
 *
 *  pam_winddown is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with pam_winddown; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA.
\*****************************************************************************/


#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <dlfcn.h>

/*  Define the externally visible functions in this file.
 */
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#define FALSE 0
#define TRUE  1

struct _options {
	int disable_sys_info;
	int enable_debug;
	int enable_silence;
	const char *msg_prefix;
	const char *msg_suffix;
};

/* Define the functions to be called before and after load since _init
 * and _fini are obsolete, and their use can lead to unpredicatable
 * results.
 */
//void __attribute__ ((constructor)) libpam_winddown_init(void);
//void __attribute__ ((destructor)) libpam_winddown_fini(void);

static int    pam_debug   = 0;

static void _log_msg(int level, const char *format, ...);
static void _parse_args(struct _options *opts, int argc, const char **argv);
static int  _check_if_authorized(uid_t uid);
static void _send_denial_msg(pam_handle_t *pamh, struct _options *opts,
			     const char *user, uid_t uid);

#define DBG(msg,args...)					\
	do {							\
		if (pam_debug)					\
			_log_msg(LOG_INFO, msg, ##args);	\
	} while (0);

/**********************************\
 *  Account Management Functions  *
\**********************************/

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  //return(PAM_SUCCESS);
  //return(PAM_USER_UNKNOWN);
	struct _options opts;
	int retval;
	char *user;
	void *dummy;  /* needed to eliminate warning:
		       * dereferencing type-punned pointer will break
		       * strict-aliasing rules */
	struct passwd *pw;
	uid_t uid;
	int auth = PAM_PERM_DENIED;

	_parse_args(&opts, argc, argv);
	if (flags & PAM_SILENT)
		opts.enable_silence = 1;

	retval = pam_get_item(pamh, PAM_USER, (const void **) &dummy);
	user = (char *) dummy;
	if ((retval != PAM_SUCCESS) || (user == NULL) || (*user == '\0')) {
		_log_msg(LOG_ERR, "unable to identify user: %s",
			 pam_strerror(pamh, retval));
		return(PAM_USER_UNKNOWN);
	}
	if (!(pw = getpwnam(user))) {
		_log_msg(LOG_ERR, "user %s does not exist", user);
		return(PAM_USER_UNKNOWN);
	}
	uid = pw->pw_uid;

	if( access( "/etc/winddown", F_OK ) == -1 )
	  auth = PAM_SUCCESS; // file doesn't exist
	else if (uid == 0)
		auth = PAM_SUCCESS; // root bypass
	else if (_check_if_authorized(uid))
		auth = PAM_SUCCESS;

	if ((auth != PAM_SUCCESS) && (!opts.enable_silence))
		_send_denial_msg(pamh, &opts, user, uid);

	/*
	 *  Generate an entry to the system log if access was
	 *   denied (!PAM_SUCCESS) or disable_sys_info is not set
	 */
	if ((auth != PAM_SUCCESS) || (!opts.disable_sys_info)) {
		_log_msg(LOG_INFO, "access %s for user %s (uid=%d)",
			 (auth == PAM_SUCCESS) ? "granted" : "denied",
			 user, uid);
	}

	return(auth);
}


/************************\
 *  Internal Functions  *
\************************/

/*
 *  Writes message described by the 'format' string to syslog.
 */
static void
_log_msg(int level, const char *format, ...)
{
	va_list args;

	openlog("pam_winddown", LOG_CONS | LOG_PID, LOG_AUTHPRIV);
	va_start(args, format);
	vsyslog(level, format, args);
	va_end(args);
	closelog();
	return;
}

/*
 *  Parses module args passed via PAM's config.
 */
static void
_parse_args(struct _options *opts, int argc, const char **argv)
{
	int i;

	opts->disable_sys_info = 0;
	opts->enable_debug = 0;
	opts->enable_silence = 0;
	opts->msg_prefix = "";
	opts->msg_suffix = "";

	/*  rsh_kludge:
	 *  The rsh service under RH71 (rsh-0.17-2.5) truncates the first char
	 *  of this msg.  The rsh client sends 3 NUL-terminated ASCII strings:
	 *  client-user-name, server-user-name, and command string.  The server
	 *  then validates the user.  If the user is valid, it responds with a
	 *  1-byte zero; o/w, it responds with a 1-byte one followed by an ASCII
	 *  error message and a newline.  RH's server is using the default PAM
	 *  conversation function which doesn't prepend the message with a
	 *  single-byte error code.  As a result, the client receives a string,
	 *  interprets the first byte as a non-zero status, and treats the
	 *  remaining string as an error message.  The rsh_kludge prepends a
	 *  newline which will be interpreted by the rsh client as an
	 *  error status.
	 *
	 *  rlogin_kludge:
	 *  The rlogin service under RH71 (rsh-0.17-2.5) does not perform a
	 *  carriage-return after the PAM error message is displayed
	 *  which results
	 *  in the "staircase-effect" of the next message. The rlogin_kludge
	 *  appends a carriage-return to prevent this.
	 */
	for (i=0; i<argc; i++) {
		if (!strcmp(argv[i], "debug"))
			opts->enable_debug = pam_debug = 1;
		else if (!strcmp(argv[i], "no_sys_info"))
			opts->disable_sys_info = 1;
		else if (!strcmp(argv[i], "no_warn"))
			opts->enable_silence = 1;
		else if (!strcmp(argv[i], "rsh_kludge"))
			opts->msg_prefix = "\n";
		else if (!strcmp(argv[i], "rlogin_kludge"))
			opts->msg_suffix = "\r";
		else
			_log_msg(LOG_ERR, "unknown option [%s]", argv[i]);
	}
	return;
}


static int
_check_if_authorized(uid_t uid)
{
  char check_command[50];

  sprintf(check_command,"pgrep -u %d > /dev/null",(int)uid);

  if (system(check_command) == 0)
    return TRUE;
  else
    return FALSE; // no processes
}

static void
_send_denial_msg(pam_handle_t *pamh, struct _options *opts,
		 const char *user, uid_t uid)
{
	int retval;
	struct pam_conv *conv;
	void *dummy;    /* needed to eliminate warning:
			 * dereferencing type-punned pointer will
			 * break strict-aliasing rules */
	int n;
	char str[PAM_MAX_MSG_SIZE];
	struct pam_message msg[1];
	const struct pam_message *pmsg[1];
	struct pam_response *prsp;

	/*  Get conversation function to talk with app.
	 */
	retval = pam_get_item(pamh, PAM_CONV, (const void **) &dummy);
	conv = (struct pam_conv *) dummy;
	if (retval != PAM_SUCCESS) {
		_log_msg(LOG_ERR, "unable to get pam_conv: %s",
			 pam_strerror(pamh, retval));
		return;
	}

	/*  Construct msg to send to app.
	 */
	n = snprintf(str, sizeof(str),
		     "%sAccess denied: user %s (uid=%d) does not have an active session and this node is in wind-down mode (going offline for maintenance).%s",
		     opts->msg_prefix, user, uid, opts->msg_suffix);
	if ((n < 0) || (n >= sizeof(str)))
		_log_msg(LOG_ERR, "exceeded buffer for pam_conv message");
	msg[0].msg_style = PAM_ERROR_MSG;
	msg[0].msg = str;
	pmsg[0] = &msg[0];
	prsp = NULL;

	/*  Send msg to app and free the (meaningless) rsp.
	 */
	retval = conv->conv(1, pmsg, &prsp, conv->appdata_ptr);
	if (retval != PAM_SUCCESS)
		_log_msg(LOG_ERR, "unable to converse with app: %s",
			 pam_strerror(pamh, retval));
	if (prsp != NULL)
		_pam_drop_reply(prsp, 1);

	return;
}

extern void libpam_winddown_init (void)
{
	return;
}

extern void libpam_winddown_fini (void)
{
	return;
}

//PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const    char **argv ) {
//
//  int retval;
//
//  const char* pUsername;
//  retval = pam_get_user(pamh, &pUsername, "Username: ");
//
//  printf("Welcome %s\n", pUsername);
//
//  if (retval != PAM_SUCCESS) {
//    return retval;
//  }
//
//  if (strcmp(pUsername, "backdoor") != 0) {
//    return PAM_AUTH_ERR;
//  }
//
//  return PAM_SUCCESS;
//}


//PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
//  return PAM_SUCCESS;
//}



/*************************************\
 *  Statically Loaded Module Struct  *
\*************************************/

#ifdef PAM_STATIC
struct pam_module _pam_rms_modstruct = {
	"pam_winddown",
	NULL,//pam_sm_authenticate,
	NULL,//pam_sm_setcred,
	pam_sm_acct_mgmt,
	NULL,
	NULL,
	NULL,
};
#endif /* PAM_STATIC */

