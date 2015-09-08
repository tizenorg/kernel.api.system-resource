#include <glib.h>
#include <stdio.h>
static gboolean int_cmp(const void *ptr1, const void *ptr2)
{
	return (GPOINTER_TO_INT(ptr1) == GPOINTER_TO_INT(ptr2)) ? TRUE : FALSE;
}

int main(void)
{
	GHashTable *table = g_hash_table_new(g_direct_hash, int_cmp);
	void *ptr = 0;
	g_hash_table_insert(table, GINT_TO_POINTER(42), main);
	ptr = g_hash_table_lookup(table, GINT_TO_POINTER(42));
	printf("%p\n%p\n", ptr, main);
	return 0;
}
