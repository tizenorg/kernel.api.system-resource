#ifndef _PERF_CONTROL_MACRO_H
#define _PERF_CONTROL_MACRO_H

#define execute_once \
	static int __func__##guardian;                                   \
	for (; \
	__func__##guardian == 0; \
	__func__##guardian = 1)

#include <assert.h>
#include <stdio.h>
#include <config.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define DECLARE_WRAPPER(fn_name, inner_fn) \
static void fn_name(void *data, void __attribute__((__unused__)) *not_used) \
{\
	return inner_fn(data);                        \
}

#define UNUSED __attribute__((__unused__))

#define MAX_SIZE2(a, b) sizeof(a) + sizeof(b) - 1
#define MAX_SIZE3(a, b, c) MAX_SIZE2(a, b) + sizeof(c) - 1

/*
 * One byte digit has 3 position in decimal representation
 * 2 - 5
 * 4 - 10
 * 8 - 20
 * >8 - compile time error
 * plus 1 null termination byte
 * plus 1 for negative prefix
 */
#define MAX_DEC_SIZE(type) \
	(2 + (sizeof(type) <= 1 ? 3 : \
	sizeof(type) <= 2 ? 5 : \
	sizeof(type) <= 4 ? 10 : \
	sizeof(type) <= 8 ? 20 : \
	sizeof(int[-2*(sizeof(type) > 8)])))

#define ret_value_if(expr, val) do { \
        if (expr) { \
                _E("(%s) -> %s():%d return", #expr, __FUNCTION__, __LINE__); \
                return (val); \
        } \
} while (0)

#define ret_value_msg_if(expr, val, fmt, arg...) do {	\
	if (expr) {				\
		_E(fmt, ##arg);			\
		return val;			\
	}					\
} while (0)

#define ret_value_secure_msg_if(expr, val, fmt, arg...) do {	\
		if (expr) { 			\
			_SE(fmt, ##arg); 		\
			return val; 		\
		}					\
	} while (0)

#define ret_value_errno_msg_if(expr, val, fmt, arg...) do {	\
	if (expr) {					\
		ETRACE_ERRNO_MSG(fmt, ##arg);		\
		return val;				\
	}						\
} while (0)

/*
 * @brief Copy from source to destination
 * destination should not be on heap.
 * Destination will be null terminated
 */
#define STRING_SAVE_COPY(destination, source) \
	do { \
		size_t null_pos = strlen(source); \
		strncpy(destination, source, sizeof(destination)); \
		null_pos = sizeof(destination) - 1 < null_pos ? \
			sizeof(destination) - 1 : null_pos; \
		destination[null_pos] = '\0'; \
	} while(0)

/* FIXME: Do we really need pointers? */
#define array_foreach(key, type, array)                                 \
	guint _array_foreach_index;                                             \
	type *key;                                                            \
	for (_array_foreach_index = 0;                                         \
		array && _array_foreach_index < array->len && \
		(key = &g_array_index(array, type, _array_foreach_index)); \
		++_array_foreach_index)

#define slist_foreach(key, type, list)                       \
	type *key;                                                 \
	GSList *_slist_foreach_copy_list = list;                               \
	for (;                                                                \
	_slist_foreach_copy_list && \
	((key = _slist_foreach_copy_list->data) || 1); \
	_slist_foreach_copy_list = _slist_foreach_copy_list->next)

#define gslist_for_each_item(item, list)                       \
	for(item = list; item != NULL; item = g_slist_next(item))

#define DB_ACTION(command) do {				\
	if ((command) != SQLITE_OK) {			\
		error_code = RESOURCED_ERROR_DB_FAILED;	\
		goto handle_error;			\
	}						\
} while (0)

#define MODULE_REGISTER(module)						\
	static void __attribute__ ((constructor)) module_init(void)	\
	{								\
		add_module(module);					\
	}								\
	static void __attribute__ ((destructor)) module_exit(void)	\
	{								\
		remove_module(module);					\
	}

#endif	/* _PERF_CONTROL_MACRO_H */
