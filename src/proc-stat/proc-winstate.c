#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <resourced.h>

#include "proc-winstate.h"
#include "proc-main.h"
#include "proc-process.h"
#include "proc-monitor.h"
#include "trace.h"

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <Ecore.h>
#include <Ecore_X.h>
#include <Ecore_Evas.h>
#include <Ecore_Input_Evas.h>

static Atom a_pid;

typedef struct  _ProcWininfo {
    struct _ProcWininfo *prev, *next;
    int idx;
    long pid;
    Window winid;
} ProcWininfo, *ProcWininfoPtr;

static pid_t __get_win_pid(Display *d, Window win)
{
	int r;
	pid_t pid;

	Atom a_type;
	int format;
	unsigned long nitems;
	unsigned long bytes_after;
	unsigned char *prop_ret;
	XWindowAttributes attr;

	//_retv_if(d == NULL || !a_pid, -1);

	if (!XGetWindowAttributes(d, win, &attr))
		return -1;

	if (attr.override_redirect || attr.class == InputOnly)
		return -1;

	prop_ret = NULL;
	r = XGetWindowProperty(d, win, a_pid, 0, 1, False, XA_CARDINAL,
			       &a_type, &format, &nitems, &bytes_after,
			       &prop_ret);
	if (r != Success || prop_ret == NULL)
		return -1;

	if (a_type == XA_CARDINAL && format == 32)
		pid = *(unsigned long *)prop_ret;
	else
		pid = -1;

	XFree(prop_ret);

	return pid;
}

static Window get_window(Display *d, Window win)
{
	Atom type_ret = 0;
	int ret, size_ret = 0;
	unsigned long num_ret = 0, bytes = 0;
	unsigned char *prop_ret = NULL;
	unsigned int xid;
	Atom prop_user_created_win;

	prop_user_created_win = XInternAtom(d, "_E_USER_CREATED_WINDOW", False);

	ret = XGetWindowProperty(d, win, prop_user_created_win, 0L, 1L,
            False, XA_WINDOW, &type_ret, &size_ret,
            &num_ret, &bytes, &prop_ret);

	if( ret != Success )
	{
		if( prop_ret ) XFree( (void*)prop_ret );
		return win;
	}
	else if( !prop_ret )
	{
		return win;
	}

	memcpy( &xid, prop_ret, sizeof(unsigned int) );
	XFree( (void *)prop_ret );

	return xid;
}

static void free_procwininfo(ProcWininfoPtr procwininfo)
{
	ProcWininfoPtr w;
/* TODO : free winname and appname map_state*/
	w = procwininfo;
	if (!w)
		return;
	while(1)
	{
		if(w && w->next)
			w = w->next;
		else
			break;
	}
	while(1)
	{
		if(w && w->prev)
		{
			w = w->prev;
			free(w->next);
		}
		else
		{
			if(w)
				free(w);
			break;
		}
	}
}


static int __find_win(Display *d, pid_t pid)
{
	int r, i, found = 0;
	pid_t p;
	unsigned int n;
	int win_index = 0, winid = 0;
	Window root, parent, *child;
	Window win;
	ProcWininfoPtr prev_wininfo = NULL;
	ProcWininfoPtr cur_wininfo = NULL;
	ProcWininfoPtr origin_wininfo = NULL;
	XWindowAttributes attr;

	win = XDefaultRootWindow(d);

	r = XQueryTree(d, win, &root, &parent, &child, &n);
	if (!r) {
		_E("Can't query window tree.");
		return 0;
	}

	for (i = (int)n - 1; i >= 0; i--)
	{
		if (!XGetWindowAttributes(d, child[i], &attr)) {
			_E("Can't get window tree.");
			continue;
		}
		if (attr.map_state) {
			cur_wininfo = (ProcWininfoPtr) malloc(sizeof(ProcWininfo));
			cur_wininfo->idx = win_index++;
			cur_wininfo->next = NULL;
		        cur_wininfo->prev = NULL;
			cur_wininfo->winid = child[i];
		} else
			continue;
		if(prev_wininfo)
		{
			prev_wininfo->next = cur_wininfo;
			cur_wininfo->prev = prev_wininfo;
		} else
			origin_wininfo = cur_wininfo;

	        /* set the pre_wininfo is the cur_wininfo now */
	        prev_wininfo = cur_wininfo;
	}
	if (!origin_wininfo) {
		_E("Can't get valid window info");
		if (child)
		        XFree((char *)child);
		return 0;
	}

	ProcWininfoPtr w = origin_wininfo;
	for(i = 0; i < win_index; i++)
	{
		winid = get_window(d, w->winid);
		w->winid = winid;
		p = __get_win_pid(d, w->winid);
		if (p == pid) {
			found++;
			_D("__find_win : pid %d, win %x", pid, w->winid);
			ecore_x_window_client_sniff(w->winid);
		}
		w = w->next;
	}
	if (child)
	        XFree((char *)child);
	free_procwininfo(origin_wininfo);
	return 0;
}

static inline int _get_pid(Ecore_X_Window win)
{
	int pid;
	Ecore_X_Atom atom;
	unsigned char *in_pid = NULL;
	int num;

	atom = ecore_x_atom_get("X_CLIENT_PID");
	if (ecore_x_window_prop_property_get(win, atom, ECORE_X_ATOM_CARDINAL,
				sizeof(int), &in_pid, &num) == EINA_FALSE) {
		if(in_pid != NULL) {
			free(in_pid);
			in_pid = NULL;
		}
		if (ecore_x_netwm_pid_get(win, &pid) == EINA_FALSE) {
			_E("Failed to get PID from a window 0x%X", win);
			return -EINVAL;
		}
	} else {
		pid = *(int *)in_pid;
		free(in_pid);
	}

	return pid;
}

static Eina_Bool __proc_deiconify_cb(void *data, int type, void *event)
{
	Ecore_X_Event_Client_Message *ev;
	int pid, oom_score_adj;

	ev = event;

	if (ev->format != 32)
		return ECORE_CALLBACK_RENEW;
	if (ev->message_type == ECORE_X_ATOM_E_DEICONIFY_APPROVE)
	{
		pid = _get_pid(ev->win);

		_D("pid : %d received ediconify approve", pid);

		if (proc_get_oom_score_adj(pid, &oom_score_adj) < 0) {
			_E("Failed to get oom_score_adj");
			return ECORE_CALLBACK_RENEW;
		}

		if (oom_score_adj >= OOMADJ_BACKGRD_UNLOCKED) {
			/* init oom_score_value */
			proc_set_oom_score_adj(pid, OOMADJ_INIT);
		}
	}

	return ECORE_CALLBACK_RENEW;

}

static Eina_Bool __proc_visibility_cb(void *data, int type, void *event)
{
	Ecore_X_Event_Window_Visibility_Change *ev;
	int pid, oom_score_adj;

	ev = event;

	pid = _get_pid(ev->win);

	_D("pid : %d, bvisibility : %d", pid, ev->fully_obscured);

	if (proc_get_oom_score_adj(pid, &oom_score_adj) < 0) {
		_E("Failed to get oom_score_adj");
		return ECORE_CALLBACK_RENEW;
	}

	if (oom_score_adj >= OOMADJ_BACKGRD_UNLOCKED) {
		/* init oom_score_value */
		proc_set_oom_score_adj(pid, OOMADJ_INIT);
	}

	return ECORE_CALLBACK_RENEW;

}

int proc_add_visibiliry(int pid)
{
	int found;
	Display *d;

	if (proc_get_dbus_proc_state())
		return RESOURCED_ERROR_NO_DATA;
	d = XOpenDisplay(NULL);

	if (d == NULL) {
		_E("XOpenDisplay return NULL, pid = %d", pid);
		return RESOURCED_ERROR_FAIL;
	}

	if (!a_pid)
		a_pid = XInternAtom(d, "_NET_WM_PID", True);

	found = __find_win(d, pid);

	if (!found) {
		XCloseDisplay(d);
		errno = ENOENT;
		return RESOURCED_ERROR_FAIL;
	} else
		_D("%d window added for pid = %d", found, pid);

	return RESOURCED_ERROR_NONE;
}


int proc_win_status_init(void)
{
	ecore_x_init(NULL);
	ecore_event_handler_add(ECORE_X_EVENT_CLIENT_MESSAGE,
				    __proc_deiconify_cb, NULL);

	ecore_event_handler_add(ECORE_X_EVENT_WINDOW_VISIBILITY_CHANGE,
				    __proc_visibility_cb, NULL);
	return RESOURCED_ERROR_NONE;
}

