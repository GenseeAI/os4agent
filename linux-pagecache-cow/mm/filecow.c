#include <linux/filecow.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/proc_fs.h>
#include <linux/refcount.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/ktime.h>
#include <linux/sysctl.h>
#include <linux/swap.h>
#include <linux/pagevec.h>
#include <linux/xarray.h>

#include "internal.h"

static atomic_long_t filecow_stat_forks = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_fork_skipped_dirty = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_fork_admitted = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_large_seen = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_large_skipped = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_extent_unshareable = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_aggressive_evict_ok = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_aggressive_evict_busy = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_bulk_hook_used = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_perfolio_hook_used = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_ra_chain_hit = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_ra_chain_miss = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_ra_unbounded_calls = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_ra_unbounded_layer_calls = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_ra_order_calls = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_ra_order_layer_fallback = ATOMIC_LONG_INIT(0);
EXPORT_SYMBOL_GPL(filecow_stat_ra_chain_hit);
EXPORT_SYMBOL_GPL(filecow_stat_ra_chain_miss);
EXPORT_SYMBOL_GPL(filecow_stat_ra_unbounded_calls);
EXPORT_SYMBOL_GPL(filecow_stat_ra_unbounded_layer_calls);
EXPORT_SYMBOL_GPL(filecow_stat_ra_order_calls);
EXPORT_SYMBOL_GPL(filecow_stat_ra_order_layer_fallback);
static atomic_long_t filecow_stat_lookup_install = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_lookup_miss = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_folios_unaccounted = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_layers_allocated = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_layers_freed = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_layers_active = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_fork_no_layer = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_stat_fork_reused_layer = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_diag_evict_ok = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_diag_evict_refuse = ATOMIC_LONG_INIT(0);
static atomic_long_t filecow_diag_evict_skipped = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_iget_chain_hops = ATOMIC_LONG_INIT(0);
atomic_long_t filecow_stat_iget_chain_admits = ATOMIC_LONG_INIT(0);
EXPORT_SYMBOL_GPL(filecow_stat_iget_chain_hops);
EXPORT_SYMBOL_GPL(filecow_stat_iget_chain_admits);

static int filecow_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "forks %ld\n",
		   atomic_long_read(&filecow_stat_forks));
	seq_printf(m, "fork_skipped_dirty %ld\n",
		   atomic_long_read(&filecow_stat_fork_skipped_dirty));
	seq_printf(m, "fork_admitted_folios %ld\n",
		   atomic_long_read(&filecow_stat_fork_admitted));
	seq_printf(m, "large_folios_seen %ld\n",
		   atomic_long_read(&filecow_stat_large_seen));
	seq_printf(m, "large_folios_skipped %ld\n",
		   atomic_long_read(&filecow_stat_large_skipped));
	seq_printf(m, "extent_unshareable_folios %ld\n",
		   atomic_long_read(&filecow_stat_extent_unshareable));
	seq_printf(m, "aggressive_evict_ok %ld\n",
		   atomic_long_read(&filecow_stat_aggressive_evict_ok));
	seq_printf(m, "aggressive_evict_busy %ld\n",
		   atomic_long_read(&filecow_stat_aggressive_evict_busy));
	seq_printf(m, "bulk_hook_used %ld\n",
		   atomic_long_read(&filecow_stat_bulk_hook_used));
	seq_printf(m, "perfolio_hook_used %ld\n",
		   atomic_long_read(&filecow_stat_perfolio_hook_used));
	seq_printf(m, "ra_chain_hit %ld\n",
		   atomic_long_read(&filecow_stat_ra_chain_hit));
	seq_printf(m, "ra_chain_miss %ld\n",
		   atomic_long_read(&filecow_stat_ra_chain_miss));
	seq_printf(m, "lookup_install %ld\n",
		   atomic_long_read(&filecow_stat_lookup_install));
	seq_printf(m, "lookup_miss %ld\n",
		   atomic_long_read(&filecow_stat_lookup_miss));
	seq_printf(m, "ra_unbounded_calls %ld\n",
		   atomic_long_read(&filecow_stat_ra_unbounded_calls));
	seq_printf(m, "ra_unbounded_layer_calls %ld\n",
		   atomic_long_read(&filecow_stat_ra_unbounded_layer_calls));
	seq_printf(m, "ra_order_calls %ld\n",
		   atomic_long_read(&filecow_stat_ra_order_calls));
	seq_printf(m, "ra_order_layer_fallback %ld\n",
		   atomic_long_read(&filecow_stat_ra_order_layer_fallback));
	seq_printf(m, "folios_unaccounted %ld\n",
		   atomic_long_read(&filecow_stat_folios_unaccounted));
	seq_printf(m, "layers_allocated %ld\n",
		   atomic_long_read(&filecow_stat_layers_allocated));
	seq_printf(m, "layers_freed %ld\n",
		   atomic_long_read(&filecow_stat_layers_freed));
	seq_printf(m, "layers_active %ld\n",
		   atomic_long_read(&filecow_stat_layers_active));
	seq_printf(m, "fork_no_layer %ld\n",
		   atomic_long_read(&filecow_stat_fork_no_layer));
	seq_printf(m, "fork_reused_layer %ld\n",
		   atomic_long_read(&filecow_stat_fork_reused_layer));
	seq_printf(m, "diag_evict_ok %ld\n",
		   atomic_long_read(&filecow_diag_evict_ok));
	seq_printf(m, "diag_evict_refuse %ld\n",
		   atomic_long_read(&filecow_diag_evict_refuse));
	seq_printf(m, "diag_evict_skipped %ld\n",
		   atomic_long_read(&filecow_diag_evict_skipped));
	seq_printf(m, "iget_chain_hops %ld\n",
		   atomic_long_read(&filecow_stat_iget_chain_hops));
	seq_printf(m, "iget_chain_admits %ld\n",
		   atomic_long_read(&filecow_stat_iget_chain_admits));
	return 0;
}


int sysctl_filecow_enabled __read_mostly = 1;
EXPORT_SYMBOL_GPL(sysctl_filecow_enabled);

int sysctl_filecow_test_large_folios __read_mostly = 0;
EXPORT_SYMBOL_GPL(sysctl_filecow_test_large_folios);

int sysctl_filecow_aggressive_reclaim_priority __read_mostly = DEF_PRIORITY / 2;
EXPORT_SYMBOL_GPL(sysctl_filecow_aggressive_reclaim_priority);
static const int filecow_aggressive_reclaim_priority_max = DEF_PRIORITY;

int sysctl_filecow_unhook_strategy __read_mostly = 1;
static const int filecow_unhook_strategy_max = 3;

static int __init filecow_boot_param(char *str)
{
	if (!str)
		return 0;
	if (!strcmp(str, "0") || !strcmp(str, "off") || !strcmp(str, "n"))
		sysctl_filecow_enabled = 0;
	else if (!strcmp(str, "1") || !strcmp(str, "on") || !strcmp(str, "y"))
		sysctl_filecow_enabled = 1;
	return 1;
}
__setup("filecow=", filecow_boot_param);

static void filecow_unhook_evict_mapping(struct address_space *mapping)
{
	struct folio_batch fbatch;
	struct folio_batch free_batch;
	pgoff_t start = 0;
	unsigned int i;
	unsigned long n_ok = 0, n_refuse = 0, n_skipped = 0;

	folio_batch_init(&fbatch);
	for (;;) {
		struct folio *folio;
		bool reached_end = true;
		XA_STATE(xas, &mapping->i_pages, start);

		folio_batch_reinit(&fbatch);
		rcu_read_lock();
		xas_for_each(&xas, folio, ULONG_MAX) {
			if (xas_retry(&xas, folio))
				continue;
			if (xa_is_value(folio))
				continue;
			if (!folio_test_filecow(folio))
				continue;
			if (!folio_try_get(folio))
				continue;
			if (folio != xas_reload(&xas)) {
				folio_put(folio);
				continue;
			}
			if (folio_batch_add(&fbatch, folio) == 0) {
				start = folio->index + folio_nr_pages(folio);
				reached_end = false;
				break;
			}
		}
		rcu_read_unlock();

		if (!folio_batch_count(&fbatch))
			break;

		folio_batch_init(&free_batch);
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			folio = fbatch.folios[i];

			folio_lock(folio);
			if (xa_load(&mapping->i_pages, folio->index) != folio ||
			    !folio_test_filecow(folio)) {
				folio_unlock(folio);
				folio_put(folio);
				n_skipped++;
				continue;
			}

			if (!folio_isolate_lru(folio)) {
				folio_unlock(folio);
				folio_put(folio);
				n_skipped++;
				continue;
			}

			folio_put(folio);
			if (filecow_aggressive_evict(folio)) {
				folio_unlock(folio);
				if (folio_batch_add(&free_batch, folio) == 0) {
					mem_cgroup_uncharge_folios(&free_batch);
					free_unref_folios(&free_batch);
					folio_batch_reinit(&free_batch);
				}
				n_ok++;
			} else {
				folio_unlock(folio);
				folio_putback_lru(folio);
				n_refuse++;
			}
		}

		if (folio_batch_count(&free_batch)) {
			mem_cgroup_uncharge_folios(&free_batch);
			free_unref_folios(&free_batch);
		}

		if (reached_end)
			break;
		cond_resched();
	}

	atomic_long_add(n_ok, &filecow_diag_evict_ok);
	atomic_long_add(n_refuse, &filecow_diag_evict_refuse);
	atomic_long_add(n_skipped, &filecow_diag_evict_skipped);
	pr_debug("filecow_unhook_evict: mapping=%px ok=%lu refuse=%lu skip=%lu\n",
		 mapping, n_ok, n_refuse, n_skipped);
}

static void filecow_unhook_sb(struct super_block *sb, void *unused)
{
	struct inode *inode, *toput_inode = NULL;
	int strategy = READ_ONCE(sysctl_filecow_unhook_strategy);

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode_state_read(inode) &
		     (I_FREEING | I_WILL_FREE | I_NEW)) ||
		    !mapping_filecow_layer(inode->i_mapping)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		switch (strategy) {
		case 0:
			truncate_inode_pages(inode->i_mapping, 0);
			filecow_drop_sharer(inode->i_mapping);
			break;
		case 1:
			filecow_unhook_evict_mapping(inode->i_mapping);
			filecow_drop_sharer(inode->i_mapping);
			break;
		case 2:
			filecow_unhook_evict_mapping(inode->i_mapping);
			break;
		case 3:
			filecow_drop_sharer(inode->i_mapping);
			break;
		}
		iput(toput_inode);
		toput_inode = inode;
		cond_resched();
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);
}

static void filecow_drop_all_pagecache(void)
{
	lru_add_drain_all();
	iterate_supers(filecow_unhook_sb, NULL);
	lru_add_drain_all();
}

static int filecow_enabled_sysctl_handler(const struct ctl_table *table,
					  int write, void *buffer,
					  size_t *length, loff_t *ppos)
{
	int old = READ_ONCE(sysctl_filecow_enabled);
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret || !write)
		return ret;

	if (old && !sysctl_filecow_enabled) {
		pr_info("filecow: toggled off — dropping all filecow page cache\n");
		filecow_drop_all_pagecache();
	}
	return 0;
}

static const struct ctl_table filecow_sysctl_table[] = {
	{
		.procname	= "filecow_enabled",
		.data		= &sysctl_filecow_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= filecow_enabled_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "filecow_test_large_folios",
		.data		= &sysctl_filecow_test_large_folios,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "filecow_aggressive_reclaim_priority",
		.data		= &sysctl_filecow_aggressive_reclaim_priority,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= (void *)&filecow_aggressive_reclaim_priority_max,
	},
	{
		.procname	= "filecow_unhook_strategy",
		.data		= &sysctl_filecow_unhook_strategy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= (void *)&filecow_unhook_strategy_max,
	},
};

#define FILECOW_TOMB_MARK	0x1UL
void *xa_make_tombstone(void)
{
	return xa_mk_value(FILECOW_TOMB_MARK);
}

bool xa_is_tombstone(void *entry)
{
	return xa_is_value(entry) &&
	       (xa_to_value(entry) & FILECOW_TOMB_MARK);
}

static struct kmem_cache *filecow_layer_cache __read_mostly;
static u64 filecow_global_generation;
static DEFINE_SPINLOCK(filecow_global_gen_lock);

static u64 filecow_next_generation(void)
{
	u64 g;
	spin_lock(&filecow_global_gen_lock);
	g = ++filecow_global_generation;
	spin_unlock(&filecow_global_gen_lock);
	return g;
}

struct filecow_layer *filecow_layer_alloc(struct address_space *primary)
{
	struct filecow_layer *layer;

	layer = kmem_cache_alloc(filecow_layer_cache, GFP_KERNEL);
	if (!layer)
		return NULL;

	xa_init_flags(&layer->pages, XA_FLAGS_LOCK_IRQ | XA_FLAGS_ACCOUNT);
	refcount_set(&layer->refs, 0);
	layer->below = NULL;
	layer->generation = filecow_next_generation();
	layer->primary_inode = primary->host;
	spin_lock_init(&layer->sharers_lock);
	INIT_LIST_HEAD(&layer->sharers);
	INIT_LIST_HEAD(&layer->children);
	INIT_LIST_HEAD(&layer->sibling_link);
	layer->wb_err = 0;
	atomic_long_inc(&filecow_stat_layers_allocated);
	atomic_long_inc(&filecow_stat_layers_active);
	return layer;
}

static void __filecow_layer_free_rcu(struct rcu_head *head)
{
	struct filecow_layer *layer = container_of(head, struct filecow_layer, rcu);
	WARN_ON_ONCE(!list_empty(&layer->sharers));
	WARN_ON_ONCE(!list_empty(&layer->children));
	atomic_long_inc(&filecow_stat_layers_freed);
	atomic_long_dec(&filecow_stat_layers_active);
	kmem_cache_free(filecow_layer_cache, layer);
}

static void __filecow_layer_free(struct filecow_layer *layer)
{
	struct filecow_layer *below = layer->below;

	if (below) {
		spin_lock(&below->sharers_lock);
		list_del_rcu(&layer->sibling_link);
		spin_unlock(&below->sharers_lock);
		WRITE_ONCE(layer->below, NULL);
		filecow_layer_drop(below);
	}

	call_rcu(&layer->rcu, __filecow_layer_free_rcu);
}

static void __filecow_layer_logical_drain(struct filecow_layer *layer)
{
	struct filecow_layer *below = layer->below;
	struct folio *folio;
	XA_STATE(xas, &layer->pages, 0);

	WARN_ON_ONCE(!list_empty(&layer->sharers));

	rcu_read_lock();
	xas_for_each(&xas, folio, ULONG_MAX) {
		unsigned long m;

		if (xa_is_value(folio))
			continue;
		if (xas_retry(&xas, folio))
			continue;

		m = (unsigned long)READ_ONCE(folio->mapping);
		if (WARN_ON_ONCE(!(m & FOLIO_MAPPING_FILECOW) ||
				 (m & ~FOLIO_MAPPING_FILECOW) !=
					 (unsigned long)layer)) {
			pr_warn("filecow drain: stale slot at idx=%lu "
				"folio=%px ->mapping=%px expected_layer=%px (skipping folio_put)\n",
				xas.xa_index, folio, (void *)m, layer);
			continue;
		}
		folio_put(folio);
	}
	rcu_read_unlock();

	xa_destroy(&layer->pages);
	if (below) {
		spin_lock(&below->sharers_lock);
		list_del_rcu(&layer->sibling_link);
		spin_unlock(&below->sharers_lock);
	}

	WRITE_ONCE(layer->below, NULL);
	if (below)
		filecow_layer_drop(below);
}

void filecow_layer_drop(struct filecow_layer *layer)
{
	if (!layer)
		return;
	if (refcount_dec_and_test(&layer->refs))
		__filecow_layer_free(layer);
}
EXPORT_SYMBOL_GPL(filecow_layer_drop);

static void filecow_unaccount_folio(struct folio *folio)
{
	long nr = folio_nr_pages(folio);
	lruvec_stat_mod_folio(folio, NR_FILE_PAGES, -nr);
	atomic_long_add(nr, &filecow_stat_folios_unaccounted);
}

void __filecow_folio_drop_on_free(struct folio *folio)
{
	struct filecow_layer *layer = folio_to_filecow_layer(folio);
	WARN_ON_ONCE(folio_mapcount(folio));
	filecow_unaccount_folio(folio);
	xa_cmpxchg(&layer->pages, folio->index, folio, NULL, GFP_ATOMIC);
	WRITE_ONCE(folio->mapping, NULL);
	filecow_layer_drop(layer);
}
EXPORT_SYMBOL_GPL(__filecow_folio_drop_on_free);

void filecow_drop_sharer(struct address_space *mapping)
{
	struct filecow_layer *layer = mapping->ro;
	bool was_last_sharer;
	bool was_primary = false;

	if (!layer)
		return;

	refcount_inc(&layer->refs);
	spin_lock(&layer->sharers_lock);
	list_del_init(&mapping->filecow_link);
	was_last_sharer = list_empty(&layer->sharers);
	if (layer->primary_inode == mapping->host) {
		struct address_space *next_as;
		struct inode *new_primary = NULL;

		was_primary = true;
		list_for_each_entry(next_as, &layer->sharers, filecow_link) {
			struct inode *cand = next_as->host;

			if (cand && !(inode_state_read_once(cand) &
				     (I_FREEING | I_WILL_FREE | I_CLEAR))) {
				new_primary = cand;
				break;
			}
		}
		WRITE_ONCE(layer->primary_inode, new_primary);
	}
	spin_unlock(&layer->sharers_lock);

	mapping->ro = NULL;
	if (!was_last_sharer && was_primary) {

		struct folio **batch = NULL;
		unsigned int n_batch = 0, capacity;
		struct folio *folio;
		unsigned int i;
		XA_STATE(xas, &layer->pages, 0);

		capacity = 4096;
		batch = kvmalloc_array(capacity, sizeof(*batch),
				       GFP_KERNEL | __GFP_NOWARN);
		if (!batch)
			goto skip_reparent;

		for (;;) {
			n_batch = 0;
			xas_lock_irq(&xas);
			xas_for_each(&xas, folio, ULONG_MAX) {
				if (xas_retry(&xas, folio))
					continue;
				if (xa_is_value(folio))
					continue;
				if (!folio_memcg_charged(folio))
					continue;
				folio_get(folio);
				batch[n_batch++] = folio;
				if (n_batch == capacity)
					break;
			}
			xas_unlock_irq(&xas);

			if (n_batch == 0)
				break;

			for (i = 0; i < n_batch; i++) {
				mem_cgroup_uncharge(batch[i]);
				folio_put(batch[i]);
			}

			if (n_batch < capacity)
				break;

			xas_set(&xas, 0);
		}

		kvfree(batch);
	}
skip_reparent:

	if (was_last_sharer)
		__filecow_layer_logical_drain(layer);

	filecow_layer_drop(layer);
	filecow_layer_drop(layer);
}
EXPORT_SYMBOL_GPL(filecow_drop_sharer);

bool filecow_has_sharer(struct filecow_layer *layer,
			struct address_space *mapping)
{
	struct address_space *m;
	bool found = false;

	if (!layer || !mapping)
		return false;

	spin_lock(&layer->sharers_lock);
	list_for_each_entry(m, &layer->sharers, filecow_link) {
		if (m == mapping) {
			found = true;
			break;
		}
	}
	spin_unlock(&layer->sharers_lock);

	return found;
}
EXPORT_SYMBOL_GPL(filecow_has_sharer);

bool folio_belongs_to(struct folio *folio, struct address_space *mapping)
{
	if (folio_test_filecow(folio)) {
		void *entry;
		rcu_read_lock();
		entry = xa_load(&mapping->i_pages, folio->index);
		rcu_read_unlock();
		return entry == (void *)folio;
	}
	return folio->mapping == mapping;
}
EXPORT_SYMBOL_GPL(folio_belongs_to);

struct folio *filecow_lookup(struct address_space *mapping, pgoff_t index,
			     gfp_t gfp)
{
	struct filecow_layer *layer;
	struct folio *folio = NULL;
	void *cmpxchg_ret;

	rcu_read_lock();
	for (layer = READ_ONCE(mapping->ro); layer;
	     layer = READ_ONCE(layer->below)) {
		void *entry;

		if (xa_empty(&layer->pages))
			continue;

		entry = xa_load(&layer->pages, index);
		if (!entry)
			continue;
		if (xa_is_tombstone(entry))
			goto out;
		if (xa_is_value(entry))
			continue;
		if (!folio_try_get((struct folio *)entry))
			continue;
		folio = (struct folio *)entry;
		break;
	}
out:
	rcu_read_unlock();

	if (!folio) {
		atomic_long_inc(&filecow_stat_lookup_miss);
		return NULL;
	}

	folio_get(folio);
	xa_lock_irq(&mapping->i_pages);
	cmpxchg_ret = __xa_cmpxchg(&mapping->i_pages, index, NULL, folio, gfp);
	if (cmpxchg_ret == NULL)
		mapping->nrpages += folio_nr_pages(folio);
	xa_unlock_irq(&mapping->i_pages);
	if (cmpxchg_ret != NULL)
		folio_put(folio);

	atomic_long_inc(&filecow_stat_lookup_install);
	return folio;
}
EXPORT_SYMBOL_GPL(filecow_lookup);

struct folio *filecow_cow_folio(struct address_space *mapping,
				struct folio *src, pgoff_t index,
				gfp_t gfp)
{
	struct folio *new_folio;
	void *prev;
	long nr;

	VM_BUG_ON_FOLIO(folio_test_large(src), src);
	VM_BUG_ON_FOLIO(!folio_test_locked(src), src);
	VM_BUG_ON_FOLIO(!folio_test_filecow(src), src);

	nr = folio_nr_pages(src);
	new_folio = filemap_alloc_folio(gfp, folio_order(src), NULL);
	if (!new_folio)
		return ERR_PTR(-ENOMEM);

	__folio_set_locked(new_folio);
	folio_copy(new_folio, src);
	if (folio_test_uptodate(src))
		folio_mark_uptodate(new_folio);
	__folio_set_filecow_origin(new_folio);

	new_folio->index = index;
	new_folio->mapping = mapping;
	folio_ref_add(new_folio, nr);
	if (mem_cgroup_charge(new_folio, current->mm, gfp)) {
		new_folio->mapping = NULL;
		folio_ref_sub(new_folio, nr);
		__folio_clear_locked(new_folio);
		folio_put(new_folio);
		return ERR_PTR(-ENOMEM);
	}

	prev = xa_cmpxchg(&mapping->i_pages, index, src, new_folio, gfp);
	if (xa_is_err(prev) || prev != src) {
		mem_cgroup_uncharge(new_folio);
		new_folio->mapping = NULL;
		folio_ref_sub(new_folio, nr);
		__folio_clear_locked(new_folio);
		folio_put(new_folio);
		if (xa_is_err(prev))
			return ERR_PTR(xa_err(prev));
		return ERR_PTR(-EAGAIN);
	}
	folio_put_refs(src, nr);
	lruvec_stat_mod_folio(new_folio, NR_FILE_PAGES, nr);
	folio_add_lru(new_folio);
	return new_folio;
}
EXPORT_SYMBOL_GPL(filecow_cow_folio);

static bool can_share_folio(struct folio *folio,
			    struct address_space *src,
			    struct address_space *snap)
{
	if (!src->a_ops || !src->a_ops->folio_extent_shared)
		return false;
	return src->a_ops->folio_extent_shared(folio, src, snap);
}

long __filecow_drop_local_slot_locked(struct address_space *mapping,
				      struct folio *folio,
				      bool install_tombstone)
{
	long nr = folio_nr_pages(folio);
	void *prev;
	void *new_entry = install_tombstone ? xa_make_tombstone() : NULL;

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_filecow(folio), folio);

	prev = __xa_cmpxchg(&mapping->i_pages, folio->index, folio, new_entry,
			    GFP_ATOMIC);
	if (prev != folio)
		return 0;

	mapping->nrpages -= nr;
	return nr;
}


void filecow_drop_local_slot(struct address_space *mapping, struct folio *folio)
{
	long nr;

	spin_lock(&mapping->host->i_lock);
	xa_lock_irq(&mapping->i_pages);
	nr = __filecow_drop_local_slot_locked(mapping, folio, false);
	xa_unlock_irq(&mapping->i_pages);
	if (mapping_shrinkable(mapping))
		inode_lru_list_add(mapping->host);
	spin_unlock(&mapping->host->i_lock);

	if (nr)
		folio_put_refs(folio, nr);
}
EXPORT_SYMBOL_GPL(filecow_drop_local_slot);


void filecow_drop_local_slot_no_folio_lock(struct address_space *mapping,
					   struct folio *folio)
{
	long nr = folio_nr_pages(folio);
	void *prev;

	VM_BUG_ON_FOLIO(!folio_test_filecow(folio), folio);

	spin_lock(&mapping->host->i_lock);
	xa_lock_irq(&mapping->i_pages);
	prev = __xa_cmpxchg(&mapping->i_pages, folio->index, folio, NULL,
			    GFP_ATOMIC);
	if (prev == folio)
		mapping->nrpages -= nr;
	else
		nr = 0;
	xa_unlock_irq(&mapping->i_pages);
	if (mapping_shrinkable(mapping))
		inode_lru_list_add(mapping->host);
	spin_unlock(&mapping->host->i_lock);

	if (nr)
		folio_put_refs(folio, nr);
}
EXPORT_SYMBOL_GPL(filecow_drop_local_slot_no_folio_lock);

#define MAX_FREEZE_RETRIES	8

bool filecow_aggressive_evict(struct folio *folio)
{
	struct filecow_layer *layer;
	struct filecow_layer **worklist = NULL;
	struct address_space *m;
	pgoff_t index;
	int sharer_refs;
	int expected_refs;
	unsigned int n_visited = 0, capacity = 16;
	unsigned int i;
	unsigned int retries;
	bool ret = false;

	if (!folio_test_filecow(folio))
		return false;

	if (folio_test_private(folio) && folio_needs_release(folio)) {
		struct address_space *fm = folio_mapping(folio);
		if (!fm || !fm->a_ops || !fm->a_ops->release_folio)
			return false;
		if (!filemap_release_folio(folio, GFP_KERNEL))
			return false;
	}
	layer = folio_to_filecow_layer(folio);
	index = folio->index;

retry_grow:
	worklist = kvmalloc_array(capacity, sizeof(*worklist),
				  GFP_KERNEL | __GFP_NOWARN);
	if (!worklist) {
		atomic_long_inc(&filecow_stat_aggressive_evict_busy);
		return false;
	}

	refcount_inc(&layer->refs);
	worklist[n_visited++] = layer;

	for (i = 0; i < n_visited; i++) {
		struct filecow_layer *L = worklist[i];
		struct filecow_layer *child;

		rcu_read_lock();
		list_for_each_entry_rcu(child, &L->children, sibling_link) {
			if (!refcount_inc_not_zero(&child->refs))
				continue;
			if (n_visited == capacity) {

				refcount_dec(&child->refs);
				rcu_read_unlock();
				goto grow_worklist;
			}
			worklist[n_visited++] = child;
		}
		rcu_read_unlock();
	}

	for (retries = 0; retries < MAX_FREEZE_RETRIES; retries++) {
		sharer_refs = 0;
		for (i = 0; i < n_visited; i++) {
			struct filecow_layer *L = worklist[i];

			spin_lock(&L->sharers_lock);
			list_for_each_entry(m, &L->sharers, filecow_link) {
				if (xa_load(&m->i_pages, index) == folio)
					sharer_refs++;
			}
			spin_unlock(&L->sharers_lock);
		}

		expected_refs = 1 + 1 + sharer_refs;

		if (folio_ref_freeze(folio, expected_refs))
			goto frozen;

	}
	atomic_long_inc(&filecow_stat_aggressive_evict_busy);
	goto out;

frozen:
	for (i = 0; i < n_visited; i++) {
		struct filecow_layer *L = worklist[i];

		spin_lock(&L->sharers_lock);
		list_for_each_entry(m, &L->sharers, filecow_link) {
			xa_lock_irq(&m->i_pages);
			if (xa_load(&m->i_pages, index) == folio) {
				__xa_store(&m->i_pages, index, NULL, GFP_ATOMIC);
				m->nrpages -= 1;
			}
			xa_unlock_irq(&m->i_pages);
		}
		spin_unlock(&L->sharers_lock);
	}
	xa_store(&layer->pages, index, NULL, GFP_ATOMIC);
	ret = true;
out:

	for (i = 0; i < n_visited; i++)
		filecow_layer_drop(worklist[i]);
	kvfree(worklist);

	if (!ret)
		return false;
	goto post_detach;

grow_worklist:
	for (i = 0; i < n_visited; i++)
		filecow_layer_drop(worklist[i]);
	kvfree(worklist);
	worklist = NULL;
	n_visited = 0;
	capacity *= 2;
	if (capacity > 4096) {

		atomic_long_inc(&filecow_stat_aggressive_evict_busy);
		return false;
	}
	goto retry_grow;

post_detach:
	filecow_unaccount_folio(folio);
	folio->mapping = NULL;
	filecow_layer_drop(layer);
	atomic_long_inc(&filecow_stat_aggressive_evict_ok);
	return true;
}
EXPORT_SYMBOL_GPL(filecow_aggressive_evict);

/*
 * Return true when @mapping contains state which is newer than mapping->ro
 * and therefore must be captured in a new layer.  Filecow folios in i_pages
 * are only local lookup aliases for an existing layer and ordinary XArray
 * values are reclaim metadata.  A tombstone or a normal folio, however,
 * changes what a descendant must observe.
 *
 * The caller holds the mapping invalidate lock for write.  The XArray lock
 * closes the remaining race with reclaim while the frozen source is inspected.
 */
static bool filecow_mapping_has_private_state(struct address_space *mapping,
					      bool *has_tombstone)
{
	struct folio *folio;
	bool has_private = false;
	XA_STATE(xas, &mapping->i_pages, 0);

	*has_tombstone = false;
	xas_lock_irq(&xas);
	xas_for_each(&xas, folio, ULONG_MAX) {
		if (xas_retry(&xas, folio))
			continue;
		if (xa_is_tombstone(folio)) {
			*has_tombstone = true;
			has_private = true;
			continue;
		}
		if (!xa_is_value(folio) && !folio_test_filecow(folio))
			has_private = true;
	}
	xas_unlock_irq(&xas);

	return has_private;
}

int address_space_fork(struct address_space *new, struct address_space *source)
{
	struct filecow_layer *L;
	struct folio **batch = NULL, *folio;
	pgoff_t *indices = NULL;
	unsigned long *share_bitmap = NULL;
	int n = 0, capacity, i, moved = 0;
	int ret = 0;
	bool any_shareable = false;
	bool has_private_state;
	bool has_tombstone;
	XA_STATE(xas, &source->i_pages, 0);

	if (!READ_ONCE(sysctl_filecow_enabled))
		return -EOPNOTSUPP;

	atomic_long_inc(&filecow_stat_forks);
	if (WARN_ON_ONCE(!new || !source))
		return -EINVAL;
	if (WARN_ON_ONCE(new == source))
		return -EINVAL;

	struct rw_semaphore *first  = (source < new)
		? &source->invalidate_lock
		: &new->invalidate_lock;
	struct rw_semaphore *second = (source < new)
		? &new->invalidate_lock
		: &source->invalidate_lock;

	down_write(first);
	down_write_nested(second, SINGLE_DEPTH_NESTING);
	if (new->ro != NULL) {
		pr_warn_ratelimited(
			"filecow: address_space_fork race-loser "
			"new=%px new->host=%px new->ro=%px "
			"source=%px source->host=%px\n",
			new, new->host, new->ro,
			source, source->host);
		ret = -EBUSY;
		goto out_unlock;
	}
	if (WARN_ON_ONCE(new->nrpages != 0)) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (mapping_tagged(source, PAGECACHE_TAG_DIRTY) ||
	    mapping_tagged(source, PAGECACHE_TAG_WRITEBACK)) {
		atomic_long_inc(&filecow_stat_fork_skipped_dirty);
		ret = -EBUSY;
		goto out_unlock;
	}
	has_private_state = filecow_mapping_has_private_state(source,
							      &has_tombstone);

	/*
	 * A clean mapping without a filecow layer has no in-memory state to
	 * preserve.  The filesystem snapshot already supplies the child's data,
	 * so creating an empty layer here only retains one unnecessary layer per
	 * inode in a long-lived source's generation chain.
	 */
	if (!source->ro && !has_private_state) {
		atomic_long_inc(&filecow_stat_fork_no_layer);
		goto out_unlock;
	}

	/*
	 * When all local entries are aliases of the current immutable layer,
	 * attach the child to that layer directly.  Repeated forks of an
	 * unchanged source then consume one sharer reference per live child,
	 * rather than permanently extending the layer chain.
	 */
	if (source->ro && !has_private_state) {
		L = source->ro;
		spin_lock(&L->sharers_lock);
		refcount_inc(&L->refs);
		new->ro = L;
		list_add(&new->filecow_link, &L->sharers);
		spin_unlock(&L->sharers_lock);
		atomic_long_inc(&filecow_stat_fork_reused_layer);
		goto out_unlock;
	}

	capacity = source->nrpages;
	if (capacity != 0) {
		batch = kvmalloc_array(capacity, sizeof(*batch),
				       GFP_KERNEL | __GFP_NOWARN);
		indices = kvmalloc_array(capacity, sizeof(*indices),
					 GFP_KERNEL | __GFP_NOWARN);
		if (!batch || !indices) {
			ret = -ENOMEM;
			goto out_free_arrays;
		}

		xas_lock_irq(&xas);
		xas_for_each(&xas, folio, ULONG_MAX) {
			if (n >= capacity)
				break;
			if (xas_retry(&xas, folio))
				continue;
			if (xa_is_value(folio))
				continue;
			if (folio_test_large(folio)) {
				atomic_long_inc(&filecow_stat_large_seen);
				atomic_long_add(folio_nr_pages(folio),
						&filecow_stat_large_skipped);
				continue;
			}

			if (folio_test_filecow(folio))
				continue;
			batch[n] = folio;
			indices[n] = xas.xa_index;
			n++;
		}
		xas_unlock_irq(&xas);

		share_bitmap = kvmalloc_array(BITS_TO_LONGS(n), sizeof(long),
					      GFP_KERNEL | __GFP_ZERO);
		if (share_bitmap && source->a_ops &&
		    source->a_ops->folio_extents_shared_bulk) {
			source->a_ops->folio_extents_shared_bulk(source, new,
								 indices, n,
								 share_bitmap);
			atomic_long_inc(&filecow_stat_bulk_hook_used);
			any_shareable = !bitmap_empty(share_bitmap, n);
		} else {
			atomic_long_inc(&filecow_stat_perfolio_hook_used);
			for (i = 0; i < n; i++) {
				if (!can_share_folio(batch[i], source, new))
					continue;
				any_shareable = true;
				if (share_bitmap)
					__set_bit(i, share_bitmap);
			}
		}
	}

	/*
	 * Ordinary cached folios whose extents are not shared with the snapshot
	 * must remain private to the source.  The snapshot already has their
	 * correct on-disk contents, so an empty filecow generation would retain
	 * memory without preserving any state.
	 */
	if (!has_tombstone && !any_shareable) {
		kvfree(share_bitmap);
		kvfree(batch);
		kvfree(indices);
		if (!source->ro) {
			atomic_long_inc(&filecow_stat_fork_no_layer);
			goto out_unlock;
		}

		L = source->ro;
		spin_lock(&L->sharers_lock);
		refcount_inc(&L->refs);
		new->ro = L;
		list_add(&new->filecow_link, &L->sharers);
		spin_unlock(&L->sharers_lock);
		atomic_long_inc(&filecow_stat_fork_reused_layer);
		goto out_unlock;
	}

	L = filecow_layer_alloc(source);
	if (!L) {
		ret = -ENOMEM;
		goto out_free_arrays;
	}
	L->below = source->ro;
	if (source->ro) {
		struct filecow_layer *L_old = source->ro;

		spin_lock(&L_old->sharers_lock);
		list_del_init(&source->filecow_link);

		if (L_old->primary_inode == source->host) {
			struct address_space *next_as;
			struct inode *new_primary = NULL;

			list_for_each_entry(next_as, &L_old->sharers,
					    filecow_link) {
				struct inode *cand = next_as->host;

				if (cand && !(inode_state_read_once(cand) &
					     (I_FREEING | I_WILL_FREE | I_CLEAR))) {
					new_primary = cand;
					break;
				}
			}
			WRITE_ONCE(L_old->primary_inode, new_primary);
		}
		spin_unlock(&L_old->sharers_lock);
	}

	for (i = 0; i < n; i++) {
		void *prev;
		void *xa_ret;
		bool shareable;

		if (share_bitmap)
			shareable = test_bit(i, share_bitmap);
		else
			shareable = can_share_folio(batch[i], source, new);
		if (!shareable) {
			atomic_long_inc(&filecow_stat_extent_unshareable);
			continue;
		}

		prev = xa_cmpxchg(&source->i_pages, indices[i], batch[i],
				NULL, GFP_KERNEL);
		if (prev != batch[i])
			continue;

		xa_ret = xa_store(&L->pages, indices[i], batch[i],
				GFP_KERNEL);
		if (xa_err(xa_ret)) {
			xa_store(&source->i_pages, indices[i], batch[i],
				GFP_KERNEL);
			continue;
		}

		batch[i]->mapping = (struct address_space *)((unsigned long)L | FOLIO_MAPPING_FILECOW);
		moved++;
		atomic_long_inc(&filecow_stat_fork_admitted);
	}

	kvfree(share_bitmap);
	source->nrpages -= moved;
	kvfree(batch);
	kvfree(indices);

	spin_lock(&L->sharers_lock);
	refcount_set(&L->refs, 2 + moved);
	source->ro = L;
	list_add(&source->filecow_link, &L->sharers);
	new->ro = L;
	list_add(&new->filecow_link, &L->sharers);
	spin_unlock(&L->sharers_lock);

	if (L->below) {
		spin_lock(&L->below->sharers_lock);
		list_add_rcu(&L->sibling_link, &L->below->children);
		spin_unlock(&L->below->sharers_lock);
	}

	if (source < new) {
		up_write(&new->invalidate_lock);
		up_write(&source->invalidate_lock);
	} else {
		up_write(&source->invalidate_lock);
		up_write(&new->invalidate_lock);
	}
	return 0;

out_free_arrays:
	kvfree(share_bitmap);
	kvfree(batch);
	kvfree(indices);
out_unlock:
	if (source < new) {
		up_write(&new->invalidate_lock);
		up_write(&source->invalidate_lock);
	} else {
		up_write(&source->invalidate_lock);
		up_write(&new->invalidate_lock);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(address_space_fork);

int address_space_fork_or_share(struct address_space **new_mapping,
				struct inode *new_inode,
				struct address_space *src_mapping,
				bool inode_is_ro)
{
	if (!READ_ONCE(sysctl_filecow_enabled)) {
		*new_mapping = &new_inode->i_data;
		return 0;
	}
	if (inode_is_ro) {
		*new_mapping = src_mapping;
		return 0;
	}
	*new_mapping = &new_inode->i_data;
	return address_space_fork(*new_mapping, src_mapping);
}
EXPORT_SYMBOL_GPL(address_space_fork_or_share);

#define FILECOW_RT_RING_BITS	18
#define FILECOW_RT_RING_SIZE	(1U << FILECOW_RT_RING_BITS)
#define FILECOW_RT_RING_MASK	(FILECOW_RT_RING_SIZE - 1)
#define FILECOW_RT_STACK_DEPTH	8

struct filecow_ref_event {
	u64 timestamp_ns;
	unsigned long pfn;
	const char *op;
	int v;
	int ret;
	unsigned long mapping_word;
	unsigned int stack_nr;
	unsigned long stack[FILECOW_RT_STACK_DEPTH];
};

struct filecow_ref_ring {
	atomic_t head;
	struct filecow_ref_event events[FILECOW_RT_RING_SIZE];
};

static DEFINE_PER_CPU(struct filecow_ref_ring, filecow_ref_ring);
static atomic_t filecow_ref_trace_enabled = ATOMIC_INIT(0);

static void __filecow_ref_trace_emit(struct page *page, const char *op,
				     int v, int ret)
{
	struct filecow_ref_ring *ring;
	struct filecow_ref_event *ev;
	unsigned int idx;

	ring = this_cpu_ptr(&filecow_ref_ring);
	idx = atomic_inc_return(&ring->head) & FILECOW_RT_RING_MASK;
	ev = &ring->events[idx];
	ev->timestamp_ns = ktime_get_boottime_ns();
	ev->pfn = page_to_pfn(page);
	ev->op = op;
	ev->v = v;
	ev->ret = ret;
	ev->mapping_word = (unsigned long)READ_ONCE(page->mapping);
	ev->stack_nr = stack_trace_save(ev->stack,
					FILECOW_RT_STACK_DEPTH, 2);
}

void filecow_ref_trace_auto_stop(void)
{
	if (atomic_xchg(&filecow_ref_trace_enabled, 0) != 0)
		pr_alert("filecow_ref_trace: auto-stopped due to bad_page\n");
}
EXPORT_SYMBOL_GPL(filecow_ref_trace_auto_stop);

void filecow_ref_trace(struct page *page, const char *op, int v, int ret)
{
	unsigned long m;

	if (!atomic_read(&filecow_ref_trace_enabled))
		return;
	m = (unsigned long)READ_ONCE(page->mapping);
	if (!(m & FOLIO_MAPPING_FILECOW))
		return;
	__filecow_ref_trace_emit(page, op, v, ret);
}
EXPORT_SYMBOL_GPL(filecow_ref_trace);

static int sysctl_filecow_ref_trace_enabled_proxy;
static int filecow_ref_trace_enabled_handler(const struct ctl_table *table,
					     int write, void *buffer,
					     size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (!ret && write)
		atomic_set(&filecow_ref_trace_enabled,
			   sysctl_filecow_ref_trace_enabled_proxy);
	return ret;
}

static const struct ctl_table filecow_ref_trace_sysctl[] = {
	{
		.procname	= "filecow_ref_trace_enabled",
		.data		= &sysctl_filecow_ref_trace_enabled_proxy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= filecow_ref_trace_enabled_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
};

static void *filecow_ref_trace_start(struct seq_file *m, loff_t *pos)
{
	if (*pos >= num_possible_cpus() * (loff_t)FILECOW_RT_RING_SIZE)
		return NULL;
	return pos;
}

static void *filecow_ref_trace_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= num_possible_cpus() * (loff_t)FILECOW_RT_RING_SIZE)
		return NULL;
	return pos;
}

static void filecow_ref_trace_stop(struct seq_file *m, void *v)
{
}

static int filecow_ref_trace_show(struct seq_file *m, void *v)
{
	loff_t idx = *(loff_t *)v;
	int cpu = idx / FILECOW_RT_RING_SIZE;
	unsigned int slot = idx % FILECOW_RT_RING_SIZE;
	struct filecow_ref_ring *ring = per_cpu_ptr(&filecow_ref_ring, cpu);
	struct filecow_ref_event *ev = &ring->events[slot];
	unsigned int i;

	if (ev->timestamp_ns == 0)
		return 0;

	seq_printf(m, "%llu cpu=%d pfn=%05lx op=%s v=%d ret=%d mapping=%lx",
		   ev->timestamp_ns, cpu, ev->pfn, ev->op ? ev->op : "?",
		   ev->v, ev->ret, ev->mapping_word);
	for (i = 0; i < ev->stack_nr; i++)
		seq_printf(m, " %pS", (void *)ev->stack[i]);
	seq_putc(m, '\n');
	return 0;
}

static const struct seq_operations filecow_ref_trace_ops = {
	.start	= filecow_ref_trace_start,
	.next	= filecow_ref_trace_next,
	.stop	= filecow_ref_trace_stop,
	.show	= filecow_ref_trace_show,
};

static int filecow_ref_trace_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &filecow_ref_trace_ops);
}

static const struct proc_ops filecow_ref_trace_proc_ops = {
	.proc_open	= filecow_ref_trace_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};

struct filecow_iput_entry {
	struct llist_node llist;
	struct inode *inode;
};

static LLIST_HEAD(filecow_deferred_iputs);
static struct work_struct filecow_iput_work;

static void filecow_iput_work_fn(struct work_struct *w)
{
	struct llist_node *node = llist_del_all(&filecow_deferred_iputs);
	struct llist_node *next;

	while (node) {
		struct filecow_iput_entry *e =
			container_of(node, struct filecow_iput_entry, llist);
		next = node->next;
		iput(e->inode);
		kfree(e);
		node = next;
	}
}

void filecow_defer_iput(struct inode *inode)
{
	struct filecow_iput_entry *e;

	e = kmalloc(sizeof(*e), GFP_NOFS);
	if (!e) {

		WARN_ON_ONCE(1);
		iput(inode);
		return;
	}
	e->inode = inode;
	llist_add(&e->llist, &filecow_deferred_iputs);
	schedule_work(&filecow_iput_work);
}
EXPORT_SYMBOL_GPL(filecow_defer_iput);

static int __init filecow_init(void)
{
	filecow_layer_cache = KMEM_CACHE(filecow_layer, SLAB_PANIC);
	register_sysctl_init("vm", filecow_sysctl_table);
	register_sysctl_init("vm", filecow_ref_trace_sysctl);
	proc_create_single("filecow_stats", 0444, NULL, filecow_stats_show);
	proc_create("filecow_ref_trace", 0444, NULL,
		    &filecow_ref_trace_proc_ops);
	INIT_WORK(&filecow_iput_work, filecow_iput_work_fn);
	return 0;
}
subsys_initcall(filecow_init);
