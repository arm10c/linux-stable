/*
 * kobject.c - library routines for handling generic kernel objects
 *
 * Copyright (c) 2002-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2006-2007 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2007 Novell Inc.
 *
 * This file is released under the GPLv2.
 *
 *
 * Please see the file Documentation/kobject.txt for critical information
 * about using the kobject interface.
 */

#include <linux/kobject.h>
#include <linux/kobj_completion.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/stat.h>
#include <linux/slab.h>

/**
 * kobject_namespace - return @kobj's namespace tag
 * @kobj: kobject in question
 *
 * Returns namespace tag of @kobj if its parent has namespace ops enabled
 * and thus @kobj should have a namespace tag associated with it.  Returns
 * %NULL otherwise.
 */
// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject)
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject)
const void *kobject_namespace(struct kobject *kobj)
{
	// kobj: kmem_cache#30-oX (struct kobject), kobj_ns_ops(kmem_cache#30-oX (struct kobject)): NULL
	// kobj: kmem_cache#30-oX (struct kobject), kobj_ns_ops(kmem_cache#30-oX (struct kobject)): NULL
	const struct kobj_ns_type_operations *ns_ops = kobj_ns_ops(kobj);
	// ns_ops: NULL
	// ns_ops: NULL

	// ns_ops: NULL, KOBJ_NS_TYPE_NONE: 0
	// ns_ops: NULL, KOBJ_NS_TYPE_NONE: 0
	if (!ns_ops || ns_ops->type == KOBJ_NS_TYPE_NONE)
		return NULL;
		// return NULL
		// return NULL

	return kobj->ktype->namespace(kobj);
}

/*
 * populate_dir - populate directory with attributes.
 * @kobj: object we're working on.
 *
 * Most subsystems have a set of default attributes that are associated
 * with an object that registers with them.  This is a helper called during
 * object registration that loops through the default attributes of the
 * subsystem and creates attributes files for them in sysfs.
 */
// ARM10C 20160123
// kobj: kmem_cache#30-oX (struct kobject)
// ARM10C 20160813
// kobj: kmem_cache#30-oX (struct kobject)
static int populate_dir(struct kobject *kobj)
{
	// kobj: kmem_cache#30-oX (struct kobject)
	// get_ktype(kmem_cache#30-oX (struct kobject)): &dynamic_kobj_ktype
	struct kobj_type *t = get_ktype(kobj);
	// t: &dynamic_kobj_ktype

	struct attribute *attr;
	int error = 0;
	// error: 0

	int i;

	// t: &dynamic_kobj_ktype, t->default_attrs: (&dynamic_kobj_ktype)->default_attrs: NULL
	if (t && t->default_attrs) {
		for (i = 0; (attr = t->default_attrs[i]) != NULL; i++) {
			error = sysfs_create_file(kobj, attr);
			if (error)
				break;
		}
	}

	// error: 0
	return error;
	// return 0
}

// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject)
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject)
static int create_dir(struct kobject *kobj)
{
	int error;

	// kobj: kmem_cache#30-oX (struct kobject), kobject_namespace(kmem_cache#30-oX (struct kobject)): NULL
	// sysfs_create_dir_ns(kmem_cache#30-oX (struct kobject), NULL): 0
	// kobj: kmem_cache#30-oX (struct kobject), kobject_namespace(kmem_cache#30-oX (struct kobject)): NULL
	// sysfs_create_dir_ns(kmem_cache#30-oX (struct kobject), NULL): 0
	error = sysfs_create_dir_ns(kobj, kobject_namespace(kobj));
	// error: 0
	// error: 0

	// sysfs_create_dir_ns에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: NULL
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-o7 (struct idr_layer)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&sysfs_ino_ida)->free_bitmap: NULL
	//
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: NULL
	// (kmem_cache#21-o7 (struct idr_layer))->layer: 0
	// (kmem_cache#21-o7 (struct idr_layer))->ary[0]: kmem_cache#27-oX (struct ida_bitmap)
	// (kmem_cache#21-o7 (struct idr_layer))->count: 1
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 0 bit를 1로 set 수행
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	//
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/
	//
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)

	// sysfs_create_dir_ns에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	//
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// *(&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino): 3
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_name: "cgroup"
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_parent: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_right: NULL
	// &(kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino: 3 값을 이용하여
	// rb_node를 INODE(3) 주석을 달기로 함
	//
	// rb_insert_color에서 한일:
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(3)-b
	//              /            \
	*/
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)

	// error: 0
	// error: 0
	if (!error) {
		// kobj: kmem_cache#30-oX (struct kobject)
		// populate_dir(kmem_cache#30-oX (struct kobject)): 0
		// kobj: kmem_cache#30-oX (struct kobject)
		// populate_dir(kmem_cache#30-oX (struct kobject)): 0
		error = populate_dir(kobj);
		// error: 0
		// error: 0

		// error: 0
		// error: 0
		if (error)
			sysfs_remove_dir(kobj);
	}

	/*
	 * @kobj->sd may be deleted by an ancestor going away.  Hold an
	 * extra reference so that it stays until @kobj is gone.
	 */
	// kobj->sd: (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)
	// kobj->sd: (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	sysfs_get(kobj->sd);
	
	// sysfs_get에서 한일:
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_count: 2
	
	// sysfs_get에서 한일:
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count: 2

	// error: 0
	// error: 0
	return error;
	// return 0
	// return 0
}

static int get_kobj_path_length(struct kobject *kobj)
{
	int length = 1;
	struct kobject *parent = kobj;

	/* walk up the ancestors until we hit the one pointing to the
	 * root.
	 * Add 1 to strlen for leading '/' of each level.
	 */
	do {
		if (kobject_name(parent) == NULL)
			return 0;
		length += strlen(kobject_name(parent)) + 1;
		parent = parent->parent;
	} while (parent);
	return length;
}

static void fill_kobj_path(struct kobject *kobj, char *path, int length)
{
	struct kobject *parent;

	--length;
	for (parent = kobj; parent; parent = parent->parent) {
		int cur = strlen(kobject_name(parent));
		/* back up enough to print this name with '/' */
		length -= cur;
		strncpy(path + length, kobject_name(parent), cur);
		*(path + --length) = '/';
	}

	pr_debug("kobject: '%s' (%p): %s: path = '%s'\n", kobject_name(kobj),
		 kobj, __func__, path);
}

/**
 * kobject_get_path - generate and return the path associated with a given kobj and kset pair.
 *
 * @kobj:	kobject in question, with which to build the path
 * @gfp_mask:	the allocation type used to allocate the path
 *
 * The result must be freed by the caller with kfree().
 */
char *kobject_get_path(struct kobject *kobj, gfp_t gfp_mask)
{
	char *path;
	int len;

	len = get_kobj_path_length(kobj);
	if (len == 0)
		return NULL;
	path = kzalloc(len, gfp_mask);
	if (!path)
		return NULL;
	fill_kobj_path(kobj, path, len);

	return path;
}
EXPORT_SYMBOL_GPL(kobject_get_path);

/* add the kobject to its kset's list */
static void kobj_kset_join(struct kobject *kobj)
{
	if (!kobj->kset)
		return;

	kset_get(kobj->kset);
	spin_lock(&kobj->kset->list_lock);
	list_add_tail(&kobj->entry, &kobj->kset->list);
	spin_unlock(&kobj->kset->list_lock);
}

/* remove the kobject from its kset's list */
static void kobj_kset_leave(struct kobject *kobj)
{
	if (!kobj->kset)
		return;

	spin_lock(&kobj->kset->list_lock);
	list_del_init(&kobj->entry);
	spin_unlock(&kobj->kset->list_lock);
	kset_put(kobj->kset);
}

// ARM10C 20160109
// kobj: kmem_cache#30-oX (struct kobject)
static void kobject_init_internal(struct kobject *kobj)
{
	// kobj: kmem_cache#30-oX (struct kobject)
	if (!kobj)
		return;

	// &kobj->kref: &(kmem_cache#30-oX (struct kobject))->kref
	kref_init(&kobj->kref);

	// kref_init에서 한일:
	// (&(kmem_cache#30-oX (struct kobject))->kref)->refcount: 1

	// &kobj->entry: &(kmem_cache#30-oX (struct kobject))->entry
	INIT_LIST_HEAD(&kobj->entry);

	// INIT_LIST_HEAD에서 한일:
	// (&(kmem_cache#30-oX (struct kobject))->entry)->next: &(kmem_cache#30-oX (struct kobject))->entry
	// (&(kmem_cache#30-oX (struct kobject))->entry)->prev: &(kmem_cache#30-oX (struct kobject))->entry

	// kobj->state_in_sysfs: (kmem_cache#30-oX (struct kobject))->state_in_sysfs
	kobj->state_in_sysfs = 0;
	// kobj->state_in_sysfs: (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 0

	// kobj->state_add_uevent_sent: (kmem_cache#30-oX (struct kobject))->state_add_uevent_sent
	kobj->state_add_uevent_sent = 0;
	// kobj->state_add_uevent_sent: (kmem_cache#30-oX (struct kobject))->state_add_uevent_sent: 0

	// kobj->state_remove_uevent_sent: (kmem_cache#30-oX (struct kobject))->state_remove_uevent_sent
	kobj->state_remove_uevent_sent = 0;
	// kobj->state_remove_uevent_sent: (kmem_cache#30-oX (struct kobject))->state_remove_uevent_sent: 0

	// kobj->state_initialized: (kmem_cache#30-oX (struct kobject))->state_initialized
	kobj->state_initialized = 1;
	// kobj->state_initialized: (kmem_cache#30-oX (struct kobject))->state_initialized: 1
}


// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject)
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject)
static int kobject_add_internal(struct kobject *kobj)
{
	int error = 0;
	// error: 0
	// error: 0

	struct kobject *parent;

	// kobj: kmem_cache#30-oX (struct kobject)
	// kobj: kmem_cache#30-oX (struct kobject)
	if (!kobj)
		return -ENOENT;

	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: "fs"
	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: "cgroup"
	if (!kobj->name || !kobj->name[0]) {
		WARN(1, "kobject: (%p): attempted to be registered with empty "
			 "name!\n", kobj);
		return -EINVAL;
	}

	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: NULL
	// kobject_get(NULL): NULL
	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: kmem_cache#30-oX (struct kobject) (fs)
	// kobject_get(kmem_cache#30-oX (struct kobject) (fs)): kmem_cache#30-oX (struct kobject) (fs)
	parent = kobject_get(kobj->parent);
	// parent: NULL
	// parent: kmem_cache#30-oX (struct kobject) (fs)

	// kobject_get 에서 한일:
	// (&(kmem_cache#30-oX (struct kobject) (fs))->kref)->refcount: 1

	/* join kset if set, use it as parent if we do not already have one */
	// kobj->kset: (kmem_cache#30-oX (struct kobject))->kset: NULL
	// kobj->kset: (kmem_cache#30-oX (struct kobject))->kset: NULL
	if (kobj->kset) {
		if (!parent)
			parent = kobject_get(&kobj->kset->kobj);
		kobj_kset_join(kobj);
		kobj->parent = parent;
	}

	// kobj: kmem_cache#30-oX (struct kobject),
	// kobject_name(kmem_cache#30-oX (struct kobject)): "fs", parent: NULL,
	// kobj->kset: (kmem_cache#30-oX (struct kobject))->kset: NULL
	// kobj: kmem_cache#30-oX (struct kobject),
	// kobject_name(kmem_cache#30-oX (struct kobject)): "cgroup", parent: kmem_cache#30-oX (struct kobject) (fs),
	// kobj->kset: (kmem_cache#30-oX (struct kobject))->kset: NULL
	pr_debug("kobject: '%s' (%p): %s: parent: '%s', set: '%s'\n",
		 kobject_name(kobj), kobj, __func__,
		 parent ? kobject_name(parent) : "<NULL>",
		 kobj->kset ? kobject_name(&kobj->kset->kobj) : "<NULL>");
	// "kobject: 'fs' (kmem_cache#30-oX): kobject_add_internal: parent: '<NULL>', set: '<NULL>'\n"
	// "kobject: 'cgruop' (kmem_cache#30-oX): kobject_add_internal: parent: 'kmem_cache#30-oX (struct kobject) (fs)', set: '<NULL>'\n"

	// kobj: kmem_cache#30-oX (struct kobject), create_dir(kmem_cache#30-oX (struct kobject)): 0
	// kobj: kmem_cache#30-oX (struct kobject), create_dir(kmem_cache#30-oX (struct kobject)): 0
	error = create_dir(kobj);
	// error: 0
	// error: 0

	// create_dir에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&sysfs_ino_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	//
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/
	//
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_count: 2

	// create_dir에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	//
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// *(&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino): 3
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_name: "cgroup"
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_parent: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_right: NULL
	// &(kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino: 3 값을 이용하여
	// rb_node를 INODE(3) 주석을 달기로 함
	//
	// rb_insert_color에서 한일:
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(3)-b
	//              /            \
	*/
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count: 2

	// error: 0
	// error: 0
	if (error) {
		kobj_kset_leave(kobj);
		kobject_put(parent);
		kobj->parent = NULL;

		/* be noisy on error issues */
		if (error == -EEXIST)
			WARN(1, "%s failed for %s with "
			     "-EEXIST, don't try to register things with "
			     "the same name in the same directory.\n",
			     __func__, kobject_name(kobj));
		else
			WARN(1, "%s failed for %s (error: %d parent: %s)\n",
			     __func__, kobject_name(kobj), error,
			     parent ? kobject_name(parent) : "'none'");
	} else
		// kobj->state_in_sysfs: (kmem_cache#30-oX (struct kobject))->state_in_sysfs
		// kobj->state_in_sysfs: (kmem_cache#30-oX (struct kobject))->state_in_sysfs
		kobj->state_in_sysfs = 1;
		// kobj->state_in_sysfs: (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1
		// kobj->state_in_sysfs: (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1

	// error: 0
	// error: 0
	return error;
	// return 0
	// return 0
}

/**
 * kobject_set_name_vargs - Set the name of an kobject
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 * @vargs: vargs to format the string.
 */
// ARM10C 20160109
// kobj: kmem_cache#30-oX (struct kobject), fmt: "%s", vargs: "fs"
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject), fmt: "%s", vargs: "cgroup"
int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
				  va_list vargs)
{
	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: NULL
	const char *old_name = kobj->name;
	// old_name: (kmem_cache#30-oX (struct kobject))->name: NULL

	char *s;

	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: NULL, fmt: "%s"
	if (kobj->name && !fmt)
		return 0;

	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: NULL
	// GFP_KERNEL: 0xD0, fmt: "%s", vargs: "fs"
	// kvasprintf(GFP_KERNEL: 0xD0, "%s", "fs"): kmem_cache#30-oX: "fs"
	kobj->name = kvasprintf(GFP_KERNEL, fmt, vargs);
	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "fs"

	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "fs"
	if (!kobj->name)
		return -ENOMEM;

// 2016/01/09 종료
// 2016/01/16 시작

	/* ewww... some of these buggers have '/' in the name ... */
	// kobj->name: (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "fs"
	// strchr("fs", '/'): NULL
	while ((s = strchr(kobj->name, '/')))
		s[0] = '!';

	// old_name: (kmem_cache#30-oX (struct kobject))->name: NULL
	kfree(old_name);

	// kfree에서 한일:
	// (kmem_cache#30-oX (struct kobject))->name 에 이전에  할당된 메모리를 돌려줌

	return 0;
	// return 0
}

/**
 * kobject_set_name - Set the name of a kobject
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 *
 * This sets the name of the kobject.  If you have already added the
 * kobject to the system, you must call kobject_rename() in order to
 * change the name of the kobject.
 */
int kobject_set_name(struct kobject *kobj, const char *fmt, ...)
{
	va_list vargs;
	int retval;

	va_start(vargs, fmt);
	retval = kobject_set_name_vargs(kobj, fmt, vargs);
	va_end(vargs);

	return retval;
}
EXPORT_SYMBOL(kobject_set_name);

/**
 * kobject_init - initialize a kobject structure
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 *
 * This function will properly initialize a kobject such that it can then
 * be passed to the kobject_add() call.
 *
 * After this function is called, the kobject MUST be cleaned up by a call
 * to kobject_put(), not by a call to kfree directly to ensure that all of
 * the memory is cleaned up properly.
 */
// ARM10C 20160109
// kobj: kmem_cache#30-oX (struct kobject), &dynamic_kobj_ktype
void kobject_init(struct kobject *kobj, struct kobj_type *ktype)
{
	char *err_str;

	// kobj: kmem_cache#30-oX (struct kobject)
	if (!kobj) {
		err_str = "invalid kobject pointer!";
		goto error;
	}

	// ktype: &dynamic_kobj_ktype
	if (!ktype) {
		err_str = "must have a ktype to be initialized properly!\n";
		goto error;
	}

	// kobj->state_initialized: (kmem_cache#30-oX (struct kobject))->state_initialized: 0
	if (kobj->state_initialized) {
		/* do not error out as sometimes we can recover */
		printk(KERN_ERR "kobject (%p): tried to init an initialized "
		       "object, something is seriously wrong.\n", kobj);
		dump_stack();
	}

	// kobj: kmem_cache#30-oX (struct kobject)
	kobject_init_internal(kobj);

	// kobject_init_internal에서 한일:
	//
	// (&(kmem_cache#30-oX (struct kobject))->kref)->refcount: 1
	// (&(kmem_cache#30-oX (struct kobject))->entry)->next: &(kmem_cache#30-oX (struct kobject))->entry
	// (&(kmem_cache#30-oX (struct kobject))->entry)->prev: &(kmem_cache#30-oX (struct kobject))->entry
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 0
	// (kmem_cache#30-oX (struct kobject))->state_add_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_remove_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_initialized: 1

	// kobj->ktype: (kmem_cache#30-oX (struct kobject))->ktype, ktype: &dynamic_kobj_ktype
	kobj->ktype = ktype;
	// kobj->ktype: (kmem_cache#30-oX (struct kobject))->ktype: &dynamic_kobj_ktype

	return;
	// return

error:
	printk(KERN_ERR "kobject (%p): %s\n", kobj, err_str);
	dump_stack();
}
EXPORT_SYMBOL(kobject_init);

// ARM10C 20160109
// kobj: kmem_cache#30-oX (struct kobject), parent: NULL, fmt: "%s", args: "fs"
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject), parent: kmem_cache#30-oX (struct kobject), fmt: "%s", args: "cgroup"
static int kobject_add_varg(struct kobject *kobj, struct kobject *parent,
			    const char *fmt, va_list vargs)
{
	int retval;

	// kobj: kmem_cache#30-oX (struct kobject), fmt: "%s", vargs: "fs"
	// kobject_set_name_vargs(kmem_cache#30-oX (struct kobject), "%s", "fs"): 0
	// kobj: kmem_cache#30-oX (struct kobject), fmt: "%s", vargs: "cgroup"
	// kobject_set_name_vargs(kmem_cache#30-oX (struct kobject), "%s", "cgroup"): 0
	retval = kobject_set_name_vargs(kobj, fmt, vargs);
	// retval: 0
	// retval: 0

	// kobject_set_name_vargs에서 한일:
	// struct kobject의 멤버 name에 메모리를 할당하고 string 값을 만듬
	// (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "fs"

	// kobject_set_name_vargs에서 한일:
	// struct kobject의 멤버 name에 메모리를 할당하고 string 값을 만듬
	// (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "cgroup"

	// retval: 0
	// retval: 0
	if (retval) {
		printk(KERN_ERR "kobject: can not set name properly!\n");
		return retval;
	}

	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent, parent: NULL
	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent, parent: kmem_cache#30-oX (struct kobject) (fs)
	kobj->parent = parent;
	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: NULL
	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: kmem_cache#30-oX (struct kobject) (fs)

	// kobj: kmem_cache#30-oX (struct kobject)
	// kobject_add_internal(kmem_cache#30-oX (struct kobject)): 0
	// kobj: kmem_cache#30-oX (struct kobject)
	// kobject_add_internal(kmem_cache#30-oX (struct kobject)): 0
	return kobject_add_internal(kobj);
	// return 0
	// return 0

	// kobject_add_internal에서 한일:
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&sysfs_ino_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	//
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/
	//
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_count: 2
	//
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1

	// kobject_add_internal에서 한일:
	// (&(kmem_cache#30-oX (struct kobject) (fs))->kref)->refcount: 1
	//
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	//
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// *(&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino): 3
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_name: "cgroup"
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_parent: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_right: NULL
	// &(kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino: 3 값을 이용하여
	// rb_node를 INODE(3) 주석을 달기로 함
	//
	// rb_insert_color에서 한일:
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(3)-b
	//              /            \
	*/
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count: 2
}

/**
 * kobject_add - the main kobject add function
 * @kobj: the kobject to add
 * @parent: pointer to the parent of the kobject.
 * @fmt: format to name the kobject with.
 *
 * The kobject name is set and added to the kobject hierarchy in this
 * function.
 *
 * If @parent is set, then the parent of the @kobj will be set to it.
 * If @parent is NULL, then the parent of the @kobj will be set to the
 * kobject associted with the kset assigned to this kobject.  If no kset
 * is assigned to the kobject, then the kobject will be located in the
 * root of the sysfs tree.
 *
 * If this function returns an error, kobject_put() must be called to
 * properly clean up the memory associated with the object.
 * Under no instance should the kobject that is passed to this function
 * be directly freed with a call to kfree(), that can leak memory.
 *
 * Note, no "add" uevent will be created with this call, the caller should set
 * up all of the necessary sysfs files for the object and then call
 * kobject_uevent() with the UEVENT_ADD parameter to ensure that
 * userspace is properly notified of this kobject's creation.
 */
// ARM10C 20160109
// kobj: kmem_cache#30-oX (struct kobject), parent: NULL, "%s", name: "fs"
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject), parent: kmem_cache#30-oX (struct kobject), "%s", name: "cgroup"
int kobject_add(struct kobject *kobj, struct kobject *parent,
		const char *fmt, ...)
{
	va_list args;
	int retval;

	// kobj: kmem_cache#30-oX (struct kobject)
	// kobj: kmem_cache#30-oX (struct kobject)
	if (!kobj)
		return -EINVAL;

	// kobj->state_initialized: (kmem_cache#30-oX (struct kobject))->state_initialized: 1
	// kobj->state_initialized: (kmem_cache#30-oX (struct kobject))->state_initialized: 1
	if (!kobj->state_initialized) {
		printk(KERN_ERR "kobject '%s' (%p): tried to add an "
		       "uninitialized object, something is seriously wrong.\n",
		       kobject_name(kobj), kobj);
		dump_stack();
		return -EINVAL;
	}

	// fmt: "%s"
	// fmt: "%s"
	va_start(args, fmt);

	// va_start에서 한일:
	// (args): (((char *) &("%s")) + 4): "fs"
	// (args): (((char *) &("%s")) + 4): "fs"

	// kobj: kmem_cache#30-oX (struct kobject), parent: NULL, fmt: "%s", args: "fs"
	// kobject_add_varg(kmem_cache#30-oX (struct kobject), NULL, "%s", "fs"): 0
	// kobj: kmem_cache#30-oX (struct kobject), parent: kmem_cache#30-oX (struct kobject), fmt: "%s", args: "cgroup"
	// kobject_add_varg(kmem_cache#30-oX (struct kobject), kmem_cache#30-oX (struct kobject), "%s", "cgroup"): 0
	retval = kobject_add_varg(kobj, parent, fmt, args);
	// retval: 0
	// retval: 0

	// kobject_add_varg에서 한일:
	// struct kobject의 멤버 name에 메모리를 할당하고 string 값을 만듬
	//
	// (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "fs"
	// (kmem_cache#30-oX (struct kobject))->parent: NULL
	//
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&sysfs_ino_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	//
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/
	//
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_count: 2
	//
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1

	// kobject_add_varg에서 한일:
	// struct kobject의 멤버 name에 메모리를 할당하고 string 값을 만듬
	// (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "cgroup"
	// (kmem_cache#30-oX (struct kobject))->parent: kmem_cache#30-oX (struct kobject) (fs)
	//
	// (&(kmem_cache#30-oX (struct kobject) (fs))->kref)->refcount: 1
	//
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	//
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// *(&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino): 3
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_name: "cgroup"
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_parent: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_right: NULL
	// &(kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino: 3 값을 이용하여
	// rb_node를 INODE(3) 주석을 달기로 함
	//
	// rb_insert_color에서 한일:
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(3)-b
	//              /            \
	*/
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count: 2

	// (args): (((char *) &("%s")) + 4): "fs"
	// (args): (((char *) &("%s")) + 4): "cgroup"
	va_end(args);

	// va_end에서 한일:
	// (args): NULL

	// va_end에서 한일:
	// (args): NULL

	// retval: 0
	// retval: 0
	return retval;
	// return 0
	// return 0
}
EXPORT_SYMBOL(kobject_add);

/**
 * kobject_init_and_add - initialize a kobject structure and add it to the kobject hierarchy
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 * @parent: pointer to the parent of this kobject.
 * @fmt: the name of the kobject.
 *
 * This function combines the call to kobject_init() and
 * kobject_add().  The same type of error handling after a call to
 * kobject_add() and kobject lifetime rules are the same here.
 */
int kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
			 struct kobject *parent, const char *fmt, ...)
{
	va_list args;
	int retval;

	kobject_init(kobj, ktype);

	va_start(args, fmt);
	retval = kobject_add_varg(kobj, parent, fmt, args);
	va_end(args);

	return retval;
}
EXPORT_SYMBOL_GPL(kobject_init_and_add);

/**
 * kobject_rename - change the name of an object
 * @kobj: object in question.
 * @new_name: object's new name
 *
 * It is the responsibility of the caller to provide mutual
 * exclusion between two different calls of kobject_rename
 * on the same kobject and to ensure that new_name is valid and
 * won't conflict with other kobjects.
 */
int kobject_rename(struct kobject *kobj, const char *new_name)
{
	int error = 0;
	const char *devpath = NULL;
	const char *dup_name = NULL, *name;
	char *devpath_string = NULL;
	char *envp[2];

	kobj = kobject_get(kobj);
	if (!kobj)
		return -EINVAL;
	if (!kobj->parent)
		return -EINVAL;

	devpath = kobject_get_path(kobj, GFP_KERNEL);
	if (!devpath) {
		error = -ENOMEM;
		goto out;
	}
	devpath_string = kmalloc(strlen(devpath) + 15, GFP_KERNEL);
	if (!devpath_string) {
		error = -ENOMEM;
		goto out;
	}
	sprintf(devpath_string, "DEVPATH_OLD=%s", devpath);
	envp[0] = devpath_string;
	envp[1] = NULL;

	name = dup_name = kstrdup(new_name, GFP_KERNEL);
	if (!name) {
		error = -ENOMEM;
		goto out;
	}

	error = sysfs_rename_dir_ns(kobj, new_name, kobject_namespace(kobj));
	if (error)
		goto out;

	/* Install the new kobject name */
	dup_name = kobj->name;
	kobj->name = name;

	/* This function is mostly/only used for network interface.
	 * Some hotplug package track interfaces by their name and
	 * therefore want to know when the name is changed by the user. */
	kobject_uevent_env(kobj, KOBJ_MOVE, envp);

out:
	kfree(dup_name);
	kfree(devpath_string);
	kfree(devpath);
	kobject_put(kobj);

	return error;
}
EXPORT_SYMBOL_GPL(kobject_rename);

/**
 * kobject_move - move object to another parent
 * @kobj: object in question.
 * @new_parent: object's new parent (can be NULL)
 */
int kobject_move(struct kobject *kobj, struct kobject *new_parent)
{
	int error;
	struct kobject *old_parent;
	const char *devpath = NULL;
	char *devpath_string = NULL;
	char *envp[2];

	kobj = kobject_get(kobj);
	if (!kobj)
		return -EINVAL;
	new_parent = kobject_get(new_parent);
	if (!new_parent) {
		if (kobj->kset)
			new_parent = kobject_get(&kobj->kset->kobj);
	}

	/* old object path */
	devpath = kobject_get_path(kobj, GFP_KERNEL);
	if (!devpath) {
		error = -ENOMEM;
		goto out;
	}
	devpath_string = kmalloc(strlen(devpath) + 15, GFP_KERNEL);
	if (!devpath_string) {
		error = -ENOMEM;
		goto out;
	}
	sprintf(devpath_string, "DEVPATH_OLD=%s", devpath);
	envp[0] = devpath_string;
	envp[1] = NULL;
	error = sysfs_move_dir_ns(kobj, new_parent, kobject_namespace(kobj));
	if (error)
		goto out;
	old_parent = kobj->parent;
	kobj->parent = new_parent;
	new_parent = NULL;
	kobject_put(old_parent);
	kobject_uevent_env(kobj, KOBJ_MOVE, envp);
out:
	kobject_put(new_parent);
	kobject_put(kobj);
	kfree(devpath_string);
	kfree(devpath);
	return error;
}

/**
 * kobject_del - unlink kobject from hierarchy.
 * @kobj: object.
 */
void kobject_del(struct kobject *kobj)
{
	struct sysfs_dirent *sd;

	if (!kobj)
		return;

	sd = kobj->sd;
	sysfs_remove_dir(kobj);
	sysfs_put(sd);

	kobj->state_in_sysfs = 0;
	kobj_kset_leave(kobj);
	kobject_put(kobj->parent);
	kobj->parent = NULL;
}

/**
 * kobject_get - increment refcount for object.
 * @kobj: object.
 */
// ARM10C 20160116
// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: NULL
// ARM10C 20160730
// kmem_cache#30-oX (struct kobject) (fs)
struct kobject *kobject_get(struct kobject *kobj)
{
	// kobj: NULL
	// kobj: kmem_cache#30-oX (struct kobject) (fs)
	if (kobj)
		// &kobj->kref: &(kmem_cache#30-oX (struct kobject) (fs))->kref
		kref_get(&kobj->kref);

		// kref_get 에서 한일:
		// (&(kmem_cache#30-oX (struct kobject) (fs))->kref)->refcount: 1

	// kobj: NULL
	// kobj: kmem_cache#30-oX (struct kobject) (fs)
	return kobj;
	// return NULL
	// return kmem_cache#30-oX (struct kobject) (fs)
}

static struct kobject * __must_check kobject_get_unless_zero(struct kobject *kobj)
{
	if (!kref_get_unless_zero(&kobj->kref))
		kobj = NULL;
	return kobj;
}

/*
 * kobject_cleanup - free kobject resources.
 * @kobj: object to cleanup
 */
static void kobject_cleanup(struct kobject *kobj)
{
	struct kobj_type *t = get_ktype(kobj);
	const char *name = kobj->name;

	pr_debug("kobject: '%s' (%p): %s, parent %p\n",
		 kobject_name(kobj), kobj, __func__, kobj->parent);

	if (t && !t->release)
		pr_debug("kobject: '%s' (%p): does not have a release() "
			 "function, it is broken and must be fixed.\n",
			 kobject_name(kobj), kobj);

	/* send "remove" if the caller did not do it but sent "add" */
	if (kobj->state_add_uevent_sent && !kobj->state_remove_uevent_sent) {
		pr_debug("kobject: '%s' (%p): auto cleanup 'remove' event\n",
			 kobject_name(kobj), kobj);
		kobject_uevent(kobj, KOBJ_REMOVE);
	}

	/* remove from sysfs if the caller did not do it */
	if (kobj->state_in_sysfs) {
		pr_debug("kobject: '%s' (%p): auto cleanup kobject_del\n",
			 kobject_name(kobj), kobj);
		kobject_del(kobj);
	}

	if (t && t->release) {
		pr_debug("kobject: '%s' (%p): calling ktype release\n",
			 kobject_name(kobj), kobj);
		t->release(kobj);
	}

	/* free name if we allocated it */
	if (name) {
		pr_debug("kobject: '%s': free name\n", name);
		kfree(name);
	}
}

#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
static void kobject_delayed_cleanup(struct work_struct *work)
{
	kobject_cleanup(container_of(to_delayed_work(work),
				     struct kobject, release));
}
#endif

static void kobject_release(struct kref *kref)
{
	struct kobject *kobj = container_of(kref, struct kobject, kref);
#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	pr_info("kobject: '%s' (%p): %s, parent %p (delayed)\n",
		 kobject_name(kobj), kobj, __func__, kobj->parent);
	INIT_DELAYED_WORK(&kobj->release, kobject_delayed_cleanup);
	schedule_delayed_work(&kobj->release, HZ);
#else
	kobject_cleanup(kobj);
#endif
}

/**
 * kobject_put - decrement refcount for object.
 * @kobj: object.
 *
 * Decrement the refcount, and if 0, call kobject_cleanup().
 */
void kobject_put(struct kobject *kobj)
{
	if (kobj) {
		if (!kobj->state_initialized)
			WARN(1, KERN_WARNING "kobject: '%s' (%p): is not "
			       "initialized, yet kobject_put() is being "
			       "called.\n", kobject_name(kobj), kobj);
		kref_put(&kobj->kref, kobject_release);
	}
}

static void dynamic_kobj_release(struct kobject *kobj)
{
	pr_debug("kobject: (%p): %s\n", kobj, __func__);
	kfree(kobj);
}

// ARM10C 20160109
// ARM10C 20160116
// ARM10C 20160123
static struct kobj_type dynamic_kobj_ktype = {
	.release	= dynamic_kobj_release,
	.sysfs_ops	= &kobj_sysfs_ops,
};

/**
 * kobject_create - create a struct kobject dynamically
 *
 * This function creates a kobject structure dynamically and sets it up
 * to be a "dynamic" kobject with a default release function set up.
 *
 * If the kobject was not able to be created, NULL will be returned.
 * The kobject structure returned from here must be cleaned up with a
 * call to kobject_put() and not kfree(), as kobject_init() has
 * already been called on this structure.
 */
// ARM10C 20160109
// ARM10C 20160730
struct kobject *kobject_create(void)
{
	struct kobject *kobj;

	// sizeof(struct kobject): 36 bytes, GFP_KERNEL: 0xD0
	// kzalloc(36, GFP_KERNEL: 0xD0): kmem_cache#30-oX (struct kobject)
	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	// kobj: kmem_cache#30-oX (struct kobject)

	// kobj: kmem_cache#30-oX (struct kobject)
	if (!kobj)
		return NULL;

	// kobj: kmem_cache#30-oX (struct kobject)
	kobject_init(kobj, &dynamic_kobj_ktype);

	// kobject_init에서 한일:
	//
	// (&(kmem_cache#30-oX (struct kobject))->kref)->refcount: 1
	// (&(kmem_cache#30-oX (struct kobject))->entry)->next: &(kmem_cache#30-oX (struct kobject))->entry
	// (&(kmem_cache#30-oX (struct kobject))->entry)->prev: &(kmem_cache#30-oX (struct kobject))->entry
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 0
	// (kmem_cache#30-oX (struct kobject))->state_add_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_remove_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_initialized: 1
	// (kmem_cache#30-oX (struct kobject))->ktype: &dynamic_kobj_ktype

	// kobj: kmem_cache#30-oX (struct kobject)
	return kobj;
	// return kmem_cache#30-oX (struct kobject)
}

/**
 * kobject_create_and_add - create a struct kobject dynamically and register it with sysfs
 *
 * @name: the name for the kobject
 * @parent: the parent kobject of this kobject, if any.
 *
 * This function creates a kobject structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kobject_put() and the structure will be dynamically freed when
 * it is no longer being used.
 *
 * If the kobject was not able to be created, NULL will be returned.
 */
// ARM10C 20160109
// "fs", NULL
// ARM10C 20160730
// "cgroup", fs_kobj: kmem_cache#30-oX (struct kobject)
struct kobject *kobject_create_and_add(const char *name, struct kobject *parent)
{
	struct kobject *kobj;
	int retval;

	// kobject_create(): kmem_cache#30-oX (struct kobject)
	// kobject_create(): kmem_cache#30-oX (struct kobject)
	kobj = kobject_create();
	// kobj: kmem_cache#30-oX (struct kobject)
	// kobj: kmem_cache#30-oX (struct kobject)

	// kobject_create에서 한일:
	//
	// struct kobject의 메모리를 할당받음 kmem_cache#30-oX (struct kobject)
	// (&(kmem_cache#30-oX (struct kobject))->kref)->refcount: 1
	// (&(kmem_cache#30-oX (struct kobject))->entry)->next: &(kmem_cache#30-oX (struct kobject))->entry
	// (&(kmem_cache#30-oX (struct kobject))->entry)->prev: &(kmem_cache#30-oX (struct kobject))->entry
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 0
	// (kmem_cache#30-oX (struct kobject))->state_add_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_remove_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_initialized: 1
	// (kmem_cache#30-oX (struct kobject))->ktype: &dynamic_kobj_ktype

	// kobject_create에서 한일:
	//
	// struct kobject의 메모리를 할당받음 kmem_cache#30-oX (struct kobject)
	// (&(kmem_cache#30-oX (struct kobject))->kref)->refcount: 1
	// (&(kmem_cache#30-oX (struct kobject))->entry)->next: &(kmem_cache#30-oX (struct kobject))->entry
	// (&(kmem_cache#30-oX (struct kobject))->entry)->prev: &(kmem_cache#30-oX (struct kobject))->entry
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 0
	// (kmem_cache#30-oX (struct kobject))->state_add_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_remove_uevent_sent: 0
	// (kmem_cache#30-oX (struct kobject))->state_initialized: 1
	// (kmem_cache#30-oX (struct kobject))->ktype: &dynamic_kobj_ktype

	// kobj: kmem_cache#30-oX (struct kobject)
	// kobj: kmem_cache#30-oX (struct kobject)
	if (!kobj)
		return NULL;

	// kobj: kmem_cache#30-oX (struct kobject), parent: NULL, name: "fs"
	// kobject_add(kmem_cache#30-oX (struct kobject), NULL, "%s", "fs"): 0
	// kobj: kmem_cache#30-oX (struct kobject), parent: kmem_cache#30-oX (struct kobject), name: "cgroup"
	// kobject_add(kmem_cache#30-oX (struct kobject), kmem_cache#30-oX (struct kobject), "%s", "cgroup"): 0
	retval = kobject_add(kobj, parent, "%s", name);
	// retval: 0
	// retval: 0

	// kobject_add에서 한일:
	// struct kobject의 멤버 name에 메모리를 할당하고 string 값을 만듬
	//
	// (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "fs"
	// (kmem_cache#30-oX (struct kobject))->parent: NULL
	//
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent)
	//
	// idr_layer_cache를 사용하여 struct idr_layer 의 메모리 kmem_cache#21-o0...7를 8 개를 할당 받음
	//
	// (&(&sysfs_ino_ida)->idr)->id_free 이 idr object 8 번을 가르킴
	// |
	// |-> ---------------------------------------------------------------------------------------------------------------------------
	//     | idr object 8         | idr object 7         | idr object 6         | idr object 5         | .... | idr object 0         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//     | ary[0]: idr object 7 | ary[0]: idr object 6 | ary[0]: idr object 5 | ary[0]: idr object 4 | .... | ary[0]: NULL         |
	//     ---------------------------------------------------------------------------------------------------------------------------
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 8
	//
	// struct ida_bitmap 의 메모리 kmem_cache#27-oX 할당 받음
	// (&sysfs_ino_ida)->free_bitmap: kmem_cache#27-oX (struct ida_bitmap)
	//
	// (&(&sysfs_ino_ida)->idr)->id_free: kmem_cache#21-oX (idr object 6)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 6
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// ((&(&sysfs_ino_ida)->idr)->top): kmem_cache#21-oX (idr object 8)
	//
	// (kmem_cache#21-oX (idr object 8))->layer: 0
	// kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// ((kmem_cache#21-oX (struct idr_layer) (idr object 8))->ary[0]): (typeof(*kmem_cache#27-oX (struct ida_bitmap)) __force space *)(kmem_cache#27-oX (struct ida_bitmap))
	// (kmem_cache#21-oX (struct idr_layer) (idr object 8))->count: 1
	//
	// (&sysfs_ino_ida)->free_bitmap: NULL
	// kmem_cache#27-oX (struct ida_bitmap) 메모리을 0으로 초기화
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 2 bit를 1로 set 수행
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_name: "fs"
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_parent: &sysfs_root
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_flags: 0x1
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent))->s_rb)->rb_right: NULL
	//
	// (&sysfs_root)->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent))->s_rb
	// (&sysfs_root)->s_dir.subdirs: 1
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent))->s_ino: 2 값을 이용하여
	// rb_node를 INODE(2) 주석을 달기로 함
	//
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(2)-b
	//              /            \
	*/
	//
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent)
	//
	// (kmem_cache#1-oX (struct sysfs_dirent))->s_count: 2
	//
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1

	// kobject_add에서 한일:
	// struct kobject의 멤버 name에 메모리를 할당하고 string 값을 만듬
	// (kmem_cache#30-oX (struct kobject))->name: kmem_cache#30-oX: "cgroup"
	// (kmem_cache#30-oX (struct kobject))->parent: kmem_cache#30-oX (struct kobject) (fs)
	//
	// (&(kmem_cache#30-oX (struct kobject) (fs))->kref)->refcount: 1
	//
	// sysfs_dir_cachep: kmem_cache#1을 이용하여 struct sysfs_dirent 메모리를 할당받음
	// kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	//
	// (&(&sysfs_ino_ida)->idr)->top: kmem_cache#21-oX (struct idr_layer) (idr object 8)
	// (&(&sysfs_ino_ida)->idr)->layers: 1
	// (&(&sysfs_ino_ida)->idr)->id_free: (idr object new 0)
	// (&(&sysfs_ino_ida)->idr)->id_free_cnt: 7
	//
	// (kmem_cache#27-oX (struct ida_bitmap))->bitmap 의 3 bit를 1로 set 수행
	// (kmem_cache#27-oX (struct ida_bitmap))->nr_busy: 2
	//
	// kmem_cache인 kmem_cache#21 에서 할당한 object인 kmem_cache#21-oX (idr object 7) 의 memory 공간을 반환함
	//
	// *(&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino): 3
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count)->counter: 1
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_active)->counter: 0
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_name: "cgroup"
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_mode: 0x41ED
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x2001
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ns: NULL
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_dir.kobj: kmem_cache#30-oX (struct kobject)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_hash: 계산된 hash index 값
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_parent: kmem_cache#1-oX (struct sysfs_dirent) (fs)
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_flags: 0x1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.subdirs: 1
	//
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->__rb_parent_color: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_left: NULL
	// (&(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb)->rb_right: NULL
	// &(kmem_cache#1-oX (struct sysfs_dirent) (fs))->s_dir.children.rb_node: &(kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_rb
	//
	// inode의 값을 나타내는 (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_ino: 3 값을 이용하여
	// rb_node를 INODE(3) 주석을 달기로 함
	//
	// rb_insert_color에서 한일:
	// rbtree 조건에 맞게 tree 구성 및 안정화 작업 수행
	/*
	//                INODE(3)-b
	//              /            \
	*/
	// (kmem_cache#30-oX (struct kobject))->sd: kmem_cache#1-oX (struct sysfs_dirent) (cgroup)
	// (kmem_cache#30-oX (struct kobject))->state_in_sysfs: 1
	//
	// (kmem_cache#1-oX (struct sysfs_dirent) (cgroup))->s_count: 2

	// retval: 0
	// retval: 0
	if (retval) {
		printk(KERN_WARNING "%s: kobject_add error: %d\n",
		       __func__, retval);
		kobject_put(kobj);
		kobj = NULL;
	}

	// kobj: kmem_cache#30-oX (struct kobject)
	// kobj: kmem_cache#30-oX (struct kobject)
	return kobj;
	// return kmem_cache#30-oX (struct kobject)
	// return kmem_cache#30-oX (struct kobject)
}
EXPORT_SYMBOL_GPL(kobject_create_and_add);

/**
 * kset_init - initialize a kset for use
 * @k: kset
 */
void kset_init(struct kset *k)
{
	kobject_init_internal(&k->kobj);
	INIT_LIST_HEAD(&k->list);
	spin_lock_init(&k->list_lock);
}

/* default kobject attribute operations */
static ssize_t kobj_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
	return ret;
}

static ssize_t kobj_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
	return ret;
}

const struct sysfs_ops kobj_sysfs_ops = {
	.show	= kobj_attr_show,
	.store	= kobj_attr_store,
};

/**
 * kobj_completion_init - initialize a kobj_completion object.
 * @kc: kobj_completion
 * @ktype: type of kobject to initialize
 *
 * kobj_completion structures can be embedded within structures with different
 * lifetime rules.  During the release of the enclosing object, we can
 * wait on the release of the kobject so that we don't free it while it's
 * still busy.
 */
void kobj_completion_init(struct kobj_completion *kc, struct kobj_type *ktype)
{
	init_completion(&kc->kc_unregister);
	kobject_init(&kc->kc_kobj, ktype);
}
EXPORT_SYMBOL_GPL(kobj_completion_init);

/**
 * kobj_completion_release - release a kobj_completion object
 * @kobj: kobject embedded in kobj_completion
 *
 * Used with kobject_release to notify waiters that the kobject has been
 * released.
 */
void kobj_completion_release(struct kobject *kobj)
{
	struct kobj_completion *kc = kobj_to_kobj_completion(kobj);
	complete(&kc->kc_unregister);
}
EXPORT_SYMBOL_GPL(kobj_completion_release);

/**
 * kobj_completion_del_and_wait - release the kobject and wait for it
 * @kc: kobj_completion object to release
 *
 * Delete the kobject from sysfs and drop the reference count.  Then wait
 * until any other outstanding references are also dropped.  This routine
 * is only necessary once other references may have been taken on the
 * kobject.  Typically this happens when the kobject has been published
 * to sysfs via kobject_add.
 */
void kobj_completion_del_and_wait(struct kobj_completion *kc)
{
	kobject_del(&kc->kc_kobj);
	kobject_put(&kc->kc_kobj);
	wait_for_completion(&kc->kc_unregister);
}
EXPORT_SYMBOL_GPL(kobj_completion_del_and_wait);

/**
 * kset_register - initialize and add a kset.
 * @k: kset.
 */
int kset_register(struct kset *k)
{
	int err;

	if (!k)
		return -EINVAL;

	kset_init(k);
	err = kobject_add_internal(&k->kobj);
	if (err)
		return err;
	kobject_uevent(&k->kobj, KOBJ_ADD);
	return 0;
}

/**
 * kset_unregister - remove a kset.
 * @k: kset.
 */
void kset_unregister(struct kset *k)
{
	if (!k)
		return;
	kobject_put(&k->kobj);
}

/**
 * kset_find_obj - search for object in kset.
 * @kset: kset we're looking in.
 * @name: object's name.
 *
 * Lock kset via @kset->subsys, and iterate over @kset->list,
 * looking for a matching kobject. If matching object is found
 * take a reference and return the object.
 */
struct kobject *kset_find_obj(struct kset *kset, const char *name)
{
	struct kobject *k;
	struct kobject *ret = NULL;

	spin_lock(&kset->list_lock);

	list_for_each_entry(k, &kset->list, entry) {
		if (kobject_name(k) && !strcmp(kobject_name(k), name)) {
			ret = kobject_get_unless_zero(k);
			break;
		}
	}

	spin_unlock(&kset->list_lock);
	return ret;
}

static void kset_release(struct kobject *kobj)
{
	struct kset *kset = container_of(kobj, struct kset, kobj);
	pr_debug("kobject: '%s' (%p): %s\n",
		 kobject_name(kobj), kobj, __func__);
	kfree(kset);
}

static struct kobj_type kset_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
	.release = kset_release,
};

/**
 * kset_create - create a struct kset dynamically
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically.  This structure can
 * then be registered with the system and show up in sysfs with a call to
 * kset_register().  When you are finished with this structure, if
 * kset_register() has been called, call kset_unregister() and the
 * structure will be dynamically freed when it is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
static struct kset *kset_create(const char *name,
				const struct kset_uevent_ops *uevent_ops,
				struct kobject *parent_kobj)
{
	struct kset *kset;
	int retval;

	kset = kzalloc(sizeof(*kset), GFP_KERNEL);
	if (!kset)
		return NULL;
	retval = kobject_set_name(&kset->kobj, "%s", name);
	if (retval) {
		kfree(kset);
		return NULL;
	}
	kset->uevent_ops = uevent_ops;
	kset->kobj.parent = parent_kobj;

	/*
	 * The kobject of this kset will have a type of kset_ktype and belong to
	 * no kset itself.  That way we can properly free it when it is
	 * finished being used.
	 */
	kset->kobj.ktype = &kset_ktype;
	kset->kobj.kset = NULL;

	return kset;
}

/**
 * kset_create_and_add - create a struct kset dynamically and add it to sysfs
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kset_unregister() and the structure will be dynamically freed when it
 * is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
struct kset *kset_create_and_add(const char *name,
				 const struct kset_uevent_ops *uevent_ops,
				 struct kobject *parent_kobj)
{
	struct kset *kset;
	int error;

	kset = kset_create(name, uevent_ops, parent_kobj);
	if (!kset)
		return NULL;
	error = kset_register(kset);
	if (error) {
		kfree(kset);
		return NULL;
	}
	return kset;
}
EXPORT_SYMBOL_GPL(kset_create_and_add);


// ARM10C 20151114
// #define DEFINE_SPINLOCK(kobj_ns_type_lock):
// spinlock_t kobj_ns_type_lock =
// (spinlock_t )
// { { .rlock =
//     {
//       .raw_lock = { { 0 } },
//       .magic = 0xdead4ead,
//       .owner_cpu = -1,
//       .owner = 0xffffffff,
//     }
// } }
static DEFINE_SPINLOCK(kobj_ns_type_lock);
// ARM10C 20151114
// KOBJ_NS_TYPES: 2
static const struct kobj_ns_type_operations *kobj_ns_ops_tbl[KOBJ_NS_TYPES];

int kobj_ns_type_register(const struct kobj_ns_type_operations *ops)
{
	enum kobj_ns_type type = ops->type;
	int error;

	spin_lock(&kobj_ns_type_lock);

	error = -EINVAL;
	if (type >= KOBJ_NS_TYPES)
		goto out;

	error = -EINVAL;
	if (type <= KOBJ_NS_TYPE_NONE)
		goto out;

	error = -EBUSY;
	if (kobj_ns_ops_tbl[type])
		goto out;

	error = 0;
	kobj_ns_ops_tbl[type] = ops;

out:
	spin_unlock(&kobj_ns_type_lock);
	return error;
}

int kobj_ns_type_registered(enum kobj_ns_type type)
{
	int registered = 0;

	spin_lock(&kobj_ns_type_lock);
	if ((type > KOBJ_NS_TYPE_NONE) && (type < KOBJ_NS_TYPES))
		registered = kobj_ns_ops_tbl[type] != NULL;
	spin_unlock(&kobj_ns_type_lock);

	return registered;
}

// ARM10C 20160116
// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: NULL
// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject)
// ARM10C 20160730
// kmem_cache#30-oX (struct kobject) (fs)
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject) (cgroup)
const struct kobj_ns_type_operations *kobj_child_ns_ops(struct kobject *parent)
{
	const struct kobj_ns_type_operations *ops = NULL;
	// ops: NULL
	// ops: NULL
	// ops: NULL

	// parent: NULL
	// parent: kmem_cache#30-oX (struct kobject), parent->ktype: (kmem_cache#30-oX (struct kobject))->ktype: &dynamic_kobj_ktype,
	// parent->ktype->child_ns_type: (kmem_cache#30-oX (struct kobject))->ktype->child_ns_type: NULL
	// parent: kmem_cache#30-oX (struct kobject) (fs), parent->ktype: (kmem_cache#30-oX (struct kobject) (fs))->ktype: &dynamic_kobj_ktype,
	// parent->ktype->child_ns_type: (kmem_cache#30-oX (struct kobject) (fs))->ktype->child_ns_type: NULL
	if (parent && parent->ktype->child_ns_type)
		ops = parent->ktype->child_ns_type(parent);

	// ops: NULL
	// ops: NULL
	// ops: NULL
	return ops;
	// return NULL
	// return NULL
	// return NULL
}

// ARM10C 20160116
// kobj: kmem_cache#30-oX (struct kobject)
// ARM10C 20160730
// kobj: kmem_cache#30-oX (struct kobject)
const struct kobj_ns_type_operations *kobj_ns_ops(struct kobject *kobj)
{
	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: NULL
	// kobj_child_ns_ops(NULL): NULL
	// kobj->parent: (kmem_cache#30-oX (struct kobject))->parent: kmem_cache#30-oX (struct kobject) (fs)
	// kobj_child_ns_ops(kmem_cache#30-oX (struct kobject) (fs)): NULL
	return kobj_child_ns_ops(kobj->parent);
	// return NULL
	// return NULL
}

bool kobj_ns_current_may_mount(enum kobj_ns_type type)
{
	bool may_mount = true;

	spin_lock(&kobj_ns_type_lock);
	if ((type > KOBJ_NS_TYPE_NONE) && (type < KOBJ_NS_TYPES) &&
	    kobj_ns_ops_tbl[type])
		may_mount = kobj_ns_ops_tbl[type]->current_may_mount();
	spin_unlock(&kobj_ns_type_lock);

	return may_mount;
}

// ARM10C 20151114
// type: 0
void *kobj_ns_grab_current(enum kobj_ns_type type)
{
	void *ns = NULL;
	// ns: NULL

	spin_lock(&kobj_ns_type_lock);

	// spin_lock에서 한일:
	// &kobj_ns_type_lock 을 사용한 spin lock 수행

	// type: 0, KOBJ_NS_TYPE_NONE: 0, KOBJ_NS_TYPES: 2
	if ((type > KOBJ_NS_TYPE_NONE) && (type < KOBJ_NS_TYPES) &&
	    kobj_ns_ops_tbl[type])
		ns = kobj_ns_ops_tbl[type]->grab_current_ns();
	spin_unlock(&kobj_ns_type_lock);

	// spin_unlock에서 한일:
	// &kobj_ns_type_lock 을 사용한 spin unlock 수행

	// ns: NULL
	return ns;
	// return NULL
}

const void *kobj_ns_netlink(enum kobj_ns_type type, struct sock *sk)
{
	const void *ns = NULL;

	spin_lock(&kobj_ns_type_lock);
	if ((type > KOBJ_NS_TYPE_NONE) && (type < KOBJ_NS_TYPES) &&
	    kobj_ns_ops_tbl[type])
		ns = kobj_ns_ops_tbl[type]->netlink_ns(sk);
	spin_unlock(&kobj_ns_type_lock);

	return ns;
}

const void *kobj_ns_initial(enum kobj_ns_type type)
{
	const void *ns = NULL;

	spin_lock(&kobj_ns_type_lock);
	if ((type > KOBJ_NS_TYPE_NONE) && (type < KOBJ_NS_TYPES) &&
	    kobj_ns_ops_tbl[type])
		ns = kobj_ns_ops_tbl[type]->initial_ns();
	spin_unlock(&kobj_ns_type_lock);

	return ns;
}

void kobj_ns_drop(enum kobj_ns_type type, void *ns)
{
	spin_lock(&kobj_ns_type_lock);
	if ((type > KOBJ_NS_TYPE_NONE) && (type < KOBJ_NS_TYPES) &&
	    kobj_ns_ops_tbl[type] && kobj_ns_ops_tbl[type]->drop_ns)
		kobj_ns_ops_tbl[type]->drop_ns(ns);
	spin_unlock(&kobj_ns_type_lock);
}

EXPORT_SYMBOL(kobject_get);
EXPORT_SYMBOL(kobject_put);
EXPORT_SYMBOL(kobject_del);

EXPORT_SYMBOL(kset_register);
EXPORT_SYMBOL(kset_unregister);
