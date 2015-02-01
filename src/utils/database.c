#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include "app-stat.h"
#include "macro.h"
#include "storage.h"

int main(int argc, char **argv)
{
	struct application_stat requests[] = {
		{"emacs", 24, 42},
		{"vim", 43, 49},
		{"emacs", 52, 56}
	};/*It's not standards compliant, but more robust */

	int index;
	struct application_stat_tree *app_tree = create_app_stat_tree();

	init_database("./base.db");

	for (index = 0; index != ARRAY_SIZE(requests); ++index)
		g_tree_insert((GTree *) app_tree->tree,
			(gpointer)index, (gpointer)(requests + index));

	store_result(app_tree, 0); /*0 time period means alway perform storing*/
	close_database();
	free_app_stat_tree(app_tree);
	return 0;
}
