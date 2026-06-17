#ifndef BTRFS_FILECOW_H
#define BTRFS_FILECOW_H

struct folio;
struct address_space;

bool btrfs_folio_extent_shared(struct folio *folio,
			       struct address_space *src,
			       struct address_space *snap);

void btrfs_folios_extent_shared_bulk(struct address_space *src,
				     struct address_space *snap,
				     pgoff_t *indices,
				     unsigned long count,
				     unsigned long *bitmap_out);

#endif /* BTRFS_FILECOW_H */
