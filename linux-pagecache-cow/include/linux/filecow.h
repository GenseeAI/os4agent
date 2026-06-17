#ifndef _LINUX_FILECOW_H
#define _LINUX_FILECOW_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/gfp_types.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>

struct address_space;
struct inode;
struct folio;
struct filecow_layer;

#ifdef CONFIG_FILECOW

extern int sysctl_filecow_enabled;
extern int sysctl_filecow_test_large_folios;
extern int sysctl_filecow_aggressive_reclaim_priority;

extern atomic_long_t filecow_stat_ra_chain_hit;
extern atomic_long_t filecow_stat_ra_chain_miss;
extern atomic_long_t filecow_stat_ra_unbounded_calls;
extern atomic_long_t filecow_stat_ra_unbounded_layer_calls;
extern atomic_long_t filecow_stat_ra_order_calls;
extern atomic_long_t filecow_stat_ra_order_layer_fallback;
extern atomic_long_t filecow_stat_iget_chain_hops;
extern atomic_long_t filecow_stat_iget_chain_admits;

void filecow_defer_iput(struct inode *inode);
int address_space_fork(struct address_space *new, struct address_space *source);
int address_space_fork_or_share(struct address_space **new_mapping,
				struct inode *new_inode,
				struct address_space *src_mapping,
				bool inode_is_ro);
bool folio_belongs_to(struct folio *folio, struct address_space *mapping);
bool filecow_has_sharer(struct filecow_layer *layer, struct address_space *mapping);
void filecow_layer_drop(struct filecow_layer *layer);
void filecow_drop_sharer(struct address_space *mapping);
void filecow_drop_local_slot(struct address_space *mapping, struct folio *folio);
void filecow_drop_local_slot_no_folio_lock(struct address_space *mapping,
					   struct folio *folio);
struct folio *filecow_cow_folio(struct address_space *mapping,
				struct folio *src, pgoff_t index, gfp_t gfp);
long __filecow_drop_local_slot_locked(struct address_space *mapping,
				      struct folio *folio,
				      bool install_tombstone);
bool filecow_aggressive_evict(struct folio *folio);
void filecow_ref_trace(struct page *page, const char *op, int v, int ret);
void filecow_ref_trace_auto_stop(void);

static inline bool filecow_blocks_send_receive(void)
{
	return READ_ONCE(sysctl_filecow_enabled) != 0;
}

void __filecow_folio_drop_on_free(struct folio *folio);

static __always_inline void filecow_folio_drop_on_free(struct folio *folio)
{
	if (folio_test_filecow(folio))
		__filecow_folio_drop_on_free(folio);
}

#else /* CONFIG_FILECOW */

static inline int address_space_fork(struct address_space *new,
				     struct address_space *source)
{
	return -EOPNOTSUPP;
}

static inline int address_space_fork_or_share(struct address_space **new_mapping,
					      struct inode *new_inode,
					      struct address_space *src_mapping,
					      bool inode_is_ro)
{
	return 0;
}

static inline bool folio_belongs_to(struct folio *folio,
				    struct address_space *mapping)
{
	return folio->mapping == mapping;
}

static inline bool filecow_has_sharer(struct filecow_layer *layer,
				      struct address_space *mapping)
{
	return false;
}

static inline void filecow_layer_drop(struct filecow_layer *layer) {}
static inline void filecow_drop_sharer(struct address_space *mapping) {}
static inline void filecow_drop_local_slot(struct address_space *mapping,
					   struct folio *folio) {}
static inline void filecow_drop_local_slot_no_folio_lock(struct address_space *mapping,
							 struct folio *folio) {}
static inline struct folio *filecow_cow_folio(struct address_space *mapping,
					      struct folio *src,
					      pgoff_t index, gfp_t gfp)
{
	return ERR_PTR(-ENOTSUPP);
}

static inline long __filecow_drop_local_slot_locked(struct address_space *mapping,
						    struct folio *folio,
						    bool install_tombstone)
{
	return 0;
}

static inline bool filecow_aggressive_evict(struct folio *folio)
{
	return false;
}

static inline void filecow_folio_drop_on_free(struct folio *folio) { }
static inline void filecow_ref_trace(struct page *page, const char *op,
				     int v, int ret) { }
static inline void filecow_ref_trace_auto_stop(void) { }
static inline bool filecow_blocks_send_receive(void) { return false; }

#endif /* CONFIG_FILECOW */

#endif /* _LINUX_FILECOW_H */
