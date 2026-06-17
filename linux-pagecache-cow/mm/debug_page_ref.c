// SPDX-License-Identifier: GPL-2.0
#include <linux/mm_types.h>
#include <linux/tracepoint.h>
#include <linux/filecow.h>

#define CREATE_TRACE_POINTS
#include <trace/events/page_ref.h>

void __page_ref_set(struct page *page, int v)
{
	trace_page_ref_set(page, v);
	filecow_ref_trace(page, "set", v, 0);
}
EXPORT_SYMBOL(__page_ref_set);
EXPORT_TRACEPOINT_SYMBOL(page_ref_set);

void __page_ref_mod(struct page *page, int v)
{
	trace_page_ref_mod(page, v);
	filecow_ref_trace(page, "mod", v, 0);
}
EXPORT_SYMBOL(__page_ref_mod);
EXPORT_TRACEPOINT_SYMBOL(page_ref_mod);

void __page_ref_mod_and_test(struct page *page, int v, int ret)
{
	trace_page_ref_mod_and_test(page, v, ret);
	filecow_ref_trace(page, "mod_test", v, ret);
}
EXPORT_SYMBOL(__page_ref_mod_and_test);
EXPORT_TRACEPOINT_SYMBOL(page_ref_mod_and_test);

void __page_ref_mod_and_return(struct page *page, int v, int ret)
{
	trace_page_ref_mod_and_return(page, v, ret);
	filecow_ref_trace(page, "mod_ret", v, ret);
}
EXPORT_SYMBOL(__page_ref_mod_and_return);
EXPORT_TRACEPOINT_SYMBOL(page_ref_mod_and_return);

void __page_ref_mod_unless(struct page *page, int v, int u)
{
	trace_page_ref_mod_unless(page, v, u);
	filecow_ref_trace(page, "mod_unless", v, u);
}
EXPORT_SYMBOL(__page_ref_mod_unless);
EXPORT_TRACEPOINT_SYMBOL(page_ref_mod_unless);

void __page_ref_freeze(struct page *page, int v, int ret)
{
	trace_page_ref_freeze(page, v, ret);
	filecow_ref_trace(page, "freeze", v, ret);
}
EXPORT_SYMBOL(__page_ref_freeze);
EXPORT_TRACEPOINT_SYMBOL(page_ref_freeze);

void __page_ref_unfreeze(struct page *page, int v)
{
	trace_page_ref_unfreeze(page, v);
	filecow_ref_trace(page, "unfreeze", v, 0);
}
EXPORT_SYMBOL(__page_ref_unfreeze);
EXPORT_TRACEPOINT_SYMBOL(page_ref_unfreeze);
