#include <linux/fs.h>
#include <linux/pagemap.h>

#include "accessors.h"
#include "btrfs_inode.h"
#include "ctree.h"
#include "disk-io.h"
#include "file-item.h"
#include "filecow.h"

static int lookup_extent_at_offset(struct btrfs_root *root,
				   struct btrfs_path *path,
				   u64 ino, u64 offset,
				   struct btrfs_key *key,
				   struct btrfs_file_extent_item **fi_out,
				   struct extent_buffer **leaf_out)
{
	struct extent_buffer *leaf;
	struct btrfs_file_extent_item *fi;
	int ret;

	ret = btrfs_lookup_file_extent(NULL, root, path, ino, offset, 0);
	if (ret < 0)
		return ret;
	if (ret > 0) {
		if (path->slots[0] == 0)
			return 1;
		path->slots[0]--;
	}

	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, key, path->slots[0]);
	if (key->objectid != ino || key->type != BTRFS_EXTENT_DATA_KEY)
		return 1;
	if (key->offset > offset)
		return 1;
	if (btrfs_file_extent_end(path) <= offset)
		return 1;

	fi = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	*fi_out = fi;
	*leaf_out = leaf;
	return 0;
}

static bool extent_records_equal(struct extent_buffer *leaf_a,
				 struct btrfs_file_extent_item *fi_a,
				 struct btrfs_key *key_a,
				 struct extent_buffer *leaf_b,
				 struct btrfs_file_extent_item *fi_b,
				 struct btrfs_key *key_b)
{
	if (key_a->offset != key_b->offset)
		return false;
	if (btrfs_file_extent_type(leaf_a, fi_a) !=
	    btrfs_file_extent_type(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_disk_bytenr(leaf_a, fi_a) !=
	    btrfs_file_extent_disk_bytenr(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_disk_num_bytes(leaf_a, fi_a) !=
	    btrfs_file_extent_disk_num_bytes(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_offset(leaf_a, fi_a) !=
	    btrfs_file_extent_offset(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_num_bytes(leaf_a, fi_a) !=
	    btrfs_file_extent_num_bytes(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_ram_bytes(leaf_a, fi_a) !=
	    btrfs_file_extent_ram_bytes(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_compression(leaf_a, fi_a) !=
	    btrfs_file_extent_compression(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_encryption(leaf_a, fi_a) !=
	    btrfs_file_extent_encryption(leaf_b, fi_b))
		return false;
	if (btrfs_file_extent_other_encoding(leaf_a, fi_a) !=
	    btrfs_file_extent_other_encoding(leaf_b, fi_b))
		return false;
	return true;
}

static bool extent_at_path_covers(struct btrfs_path *path,
				  u64 ino, u64 offset)
{
	struct extent_buffer *leaf = path->nodes[0];
	struct btrfs_key key;

	if (!leaf)
		return false;
	if (path->slots[0] >= btrfs_header_nritems(leaf))
		return false;
	btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
	if (key.objectid != ino || key.type != BTRFS_EXTENT_DATA_KEY)
		return false;
	if (key.offset > offset)
		return false;
	if (btrfs_file_extent_end(path) <= offset)
		return false;
	return true;
}

void btrfs_folios_extent_shared_bulk(struct address_space *src,
				     struct address_space *snap,
				     pgoff_t *indices,
				     unsigned long count,
				     unsigned long *bitmap_out)
{
	struct btrfs_inode *src_inode;
	struct btrfs_inode *snap_inode;
	struct btrfs_root *src_root;
	struct btrfs_root *snap_root;
	struct btrfs_path *src_path = NULL;
	struct btrfs_path *snap_path = NULL;
	struct btrfs_key src_key, snap_key;
	struct btrfs_file_extent_item *src_fi, *snap_fi;
	struct extent_buffer *src_leaf, *snap_leaf;
	u64 src_ino, snap_ino;
	unsigned long i;
	int ret;

	if (!src || !snap || !src->host || !snap->host)
		return;
	if (src == snap)
		return;

	src_inode = BTRFS_I(src->host);
	snap_inode = BTRFS_I(snap->host);
	src_root = src_inode->root;
	snap_root = snap_inode->root;
	if (!src_root || !snap_root || src_root == snap_root)
		return;

	src_ino = btrfs_ino(src_inode);
	snap_ino = btrfs_ino(snap_inode);
	if (src_ino != snap_ino)
		return;

	src_path = btrfs_alloc_path();
	snap_path = btrfs_alloc_path();
	if (!src_path || !snap_path)
		goto out;

	for (i = 0; i < count; i++) {
		u64 offset = (u64)indices[i] << PAGE_SHIFT;
		u8 type;
		if (!extent_at_path_covers(src_path, src_ino, offset)) {
			btrfs_release_path(src_path);
			ret = lookup_extent_at_offset(src_root, src_path,
						      src_ino, offset,
						      &src_key, &src_fi,
						      &src_leaf);
			if (ret != 0)
				continue;
		} else {
			src_leaf = src_path->nodes[0];
			btrfs_item_key_to_cpu(src_leaf, &src_key,
					      src_path->slots[0]);
			src_fi = btrfs_item_ptr(src_leaf, src_path->slots[0],
						struct btrfs_file_extent_item);
		}

		if (!extent_at_path_covers(snap_path, snap_ino, offset)) {
			btrfs_release_path(snap_path);
			ret = lookup_extent_at_offset(snap_root, snap_path,
						      snap_ino, offset,
						      &snap_key, &snap_fi,
						      &snap_leaf);
			if (ret != 0)
				continue;
		} else {
			snap_leaf = snap_path->nodes[0];
			btrfs_item_key_to_cpu(snap_leaf, &snap_key,
					      snap_path->slots[0]);
			snap_fi = btrfs_item_ptr(snap_leaf, snap_path->slots[0],
						 struct btrfs_file_extent_item);
		}

		type = btrfs_file_extent_type(src_leaf, src_fi);
		if (type == BTRFS_FILE_EXTENT_INLINE ||
		    (type != BTRFS_FILE_EXTENT_REG &&
		     type != BTRFS_FILE_EXTENT_PREALLOC))
			continue;

		if (btrfs_file_extent_disk_bytenr(src_leaf, src_fi) == 0)
			continue;

		if (extent_records_equal(src_leaf, src_fi, &src_key,
					 snap_leaf, snap_fi, &snap_key))
			__set_bit(i, bitmap_out);
	}

out:
	btrfs_free_path(src_path);
	btrfs_free_path(snap_path);
}

bool btrfs_folio_extent_shared(struct folio *folio,
			       struct address_space *src,
			       struct address_space *snap)
{
	struct btrfs_inode *src_inode;
	struct btrfs_inode *snap_inode;
	struct btrfs_root *src_root;
	struct btrfs_root *snap_root;
	struct btrfs_path *src_path = NULL;
	struct btrfs_path *snap_path = NULL;
	struct btrfs_key src_key, snap_key;
	struct btrfs_file_extent_item *src_fi, *snap_fi;
	struct extent_buffer *src_leaf, *snap_leaf;
	u64 offset = (u64)folio->index << PAGE_SHIFT;
	u8 type;
	bool shared = false;
	int ret;

	if (!src || !snap || !src->host || !snap->host)
		return false;
	if (src == snap)
		return false;

	src_inode = BTRFS_I(src->host);
	snap_inode = BTRFS_I(snap->host);
	src_root = src_inode->root;
	snap_root = snap_inode->root;
	if (!src_root || !snap_root)
		return false;
	if (src_root == snap_root)
		return false;
	if (btrfs_ino(src_inode) != btrfs_ino(snap_inode))
		return false;

	src_path = btrfs_alloc_path();
	snap_path = btrfs_alloc_path();
	if (!src_path || !snap_path)
		goto out;

	ret = lookup_extent_at_offset(src_root, src_path,
				      btrfs_ino(src_inode), offset,
				      &src_key, &src_fi, &src_leaf);
	if (ret != 0)
		goto out;
	ret = lookup_extent_at_offset(snap_root, snap_path,
				      btrfs_ino(snap_inode), offset,
				      &snap_key, &snap_fi, &snap_leaf);
	if (ret != 0)
		goto out;

	type = btrfs_file_extent_type(src_leaf, src_fi);
	if (type == BTRFS_FILE_EXTENT_INLINE)
		goto out;
	if (type != BTRFS_FILE_EXTENT_REG &&
	    type != BTRFS_FILE_EXTENT_PREALLOC)
		goto out;

	if (btrfs_file_extent_disk_bytenr(src_leaf, src_fi) == 0)
		goto out;

	shared = extent_records_equal(src_leaf, src_fi, &src_key,
				      snap_leaf, snap_fi, &snap_key);
out:
	btrfs_free_path(src_path);
	btrfs_free_path(snap_path);
	return shared;
}
