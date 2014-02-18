/*
 * Driver for /dev/ncr device (aka NCR)
 *
 * Copyright (c) 2014 Marc Rivière <marc.riviere AT gmail DOT com>
 *
 * This file is part of linux cryptodev.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "../ncr-int.h"
#include "../cryptodev_int.h"
#include "../version.h"
#include "setkey.h"

MODULE_AUTHOR("Marc Riviere <marc.riviere@gmail.com>");
MODULE_DESCRIPTION("NCR key provisioning example");
MODULE_LICENSE("GPL");

/* ====== Module parameters ====== */

static int mkey_len = 32;
module_param(mkey_len, int, 0);
MODULE_PARM_DESC(mkey_len, "Master key size in bytes: 16, 24, 32");
static int aes_key_len = 32;
module_param(aes_key_len, int, 0);
MODULE_PARM_DESC(mkey_len, "AES key size in bytes: 16, 24, 32");
static int rsakey_fmt = 0;
module_param(rsakey_fmt, int, 0);
MODULE_PARM_DESC(rsakey_fmt,
	"0: DER PKCS1 PSS, 1: PEM PKCS1 PSS, 2: DER PKCS8, 3: PEM PKCS8");

/* ====== SYSFS attrributes ======*/

static ssize_t rsakey_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count) {
	return count;
}

static struct kobj_attribute rsakey_attribute = __ATTR(rsakey, S_IWUSR, NULL,
		rsakey_store);

static struct attribute *setkey_attrs[] = {
	&rsakey_attribute.attr,
	NULL
};

static struct attribute_group setkey_attr_group = {
	        .attrs = setkey_attrs,
};

static struct kobject *setkey_kobj;

/* ====== Provisioning ====== */
static void __init display_buf(void *buf, int buf_len)
{
	int i;

	for (i = 0; i < buf_len; i++)
		printk("%x", ((unsigned char *)buf)[i]);
	printk(".\n");
}

static int __init fetch_key_dummy(void *buf, int buf_len)
{
	get_random_bytes(buf, buf_len);
	return 0;
}

static int __init import_rsa_key(const unsigned char *der_data,
		const unsigned int der_data_size, const ncr_key_type_t key_type,
		const unsigned int key_flags, char *key_id)
{
	void *ncr;
	struct key_item_st *item_import;
	ncr_key_t rsa_private_key;
	unsigned int key_id_len;
	int rc = 0;

#ifdef KEY_PERSISTENCE
	ncr = ncr_get_lists();
#else
	/* Simulate a open on /dev/ncr
	 * We need to close the session if an error occurs */
	ncr = ncr_init_lists();
	if (ncr == NULL) {
		err();
		return -ENOMEM;
	}
#endif

	/* Get a descriptor on a key item */
	rsa_private_key = ncr_key_init(ncr);
	if (rsa_private_key < 0) {
		err();
#ifndef KEY_PERSISTENCE
		ncr_deinit_lists(ncr);
#endif
		return rsa_private_key;
	}

	/* Allocate memory for a locale key item
	 * The NCR module will copy our structure and we have to kfree it
	 * before returning to the calling function  */
	item_import = kzalloc(sizeof(struct key_item_st), GFP_KERNEL);
        if (!item_import) {
		err();
		ncr_key_deinit(ncr, rsa_private_key);
#ifndef KEY_PERSISTENCE
		ncr_deinit_lists(ncr);
#endif
		return -ENOMEM;
	}

	/* Fill in the RSA key item */
	item_import->type = key_type;
	item_import->flags = key_flags;
	item_import->algorithm = _ncr_algo_to_properties(NCR_ALG_RSA);

	key_id_len = strlen(key_id);
	if (key_id_len >= MAX_KEY_ID_SIZE)
	{
		key_id_len = MAX_KEY_ID_SIZE;
		key_id[key_id_len - 1] = '\0';
	}
	memcpy(item_import->key_id, "rsa_priv", 9);
	item_import->key_id_size = 9;
	memcpy(item_import->key.secret.data, der_data, der_data_size);

	item_import->key.secret.size = der_data_size;
	item_import->desc = rsa_private_key;

	/* Import RSA private key in NCR */
	rc = ncr_key_import_from_kernel(ncr, item_import);
	if (rc < 0) {
		err();
		ncr_key_deinit(ncr, rsa_private_key);
	}

#ifndef KEY_PERSISTENCE
	/* TODO or not...
	 * Without key persistence, when the session is closed, the rsa
	 * key is lost unless this key has been wrapped with the master key and
	 * exported as a file to a filesystem */
	ncr_deinit_lists(ncr);
#endif
	kfree(item_import);
	return rc;
}

static int __init import_aes_key(const unsigned char *data,
		const unsigned int data_size, ncr_algorithm_t algo,
		const unsigned int key_flags, char *key_id)
{
	void *ncr;
	struct key_item_st *item_import;
	ncr_key_t aes_key;
	unsigned int key_id_len;
	int rc = 0;

#ifdef KEY_PERSISTENCE
	ncr = ncr_get_lists();
#else
	/* Simulate a open on /dev/ncr
	 * We need to close the session if an error occurs */
	ncr = ncr_init_lists();
	if (ncr == NULL) {
		err();
		return -ENOMEM;
	}
#endif

	/* Get a descriptor on a key item */
	aes_key = ncr_key_init(ncr);
	if (aes_key < 0) {
		err();
#ifndef KEY_PERSISTENCE
		ncr_deinit_lists(ncr);
#endif
		return aes_key;
	}

	/* Allocate memory for a locale key item
	 * The NCR module will copy our structure and we have to kfree it
	 * before returning to the calling function  */
	item_import = kzalloc(sizeof(struct key_item_st), GFP_KERNEL);
        if (!item_import) {
		err();
		ncr_key_deinit(ncr, aes_key);
#ifndef KEY_PERSISTENCE
		ncr_deinit_lists(ncr);
#endif
		return -ENOMEM;
	}

	/* Fill in the AES key item */
	item_import->type = NCR_KEY_TYPE_SECRET;
	item_import->flags = key_flags;
	item_import->algorithm = _ncr_algo_to_properties(algo);

	key_id_len = strlen(key_id);
	if (key_id_len >= MAX_KEY_ID_SIZE)
	{
		key_id_len = MAX_KEY_ID_SIZE;
		key_id[key_id_len - 1] = '\0';
	}
	memcpy(item_import->key_id, key_id, key_id_len);
	item_import->key_id_size = key_id_len;
	memcpy(item_import->key.secret.data, data, data_size);

	item_import->key.secret.size = data_size;
	item_import->desc = aes_key;

	/* Import AES key in NCR */
	rc = ncr_key_import_from_kernel(ncr, item_import);
	if (rc < 0) {
		err();
		ncr_key_deinit(ncr, aes_key);
	}

#ifndef KEY_PERSISTENCE
	/* TODO or not...
	 * Without key persistence, when the session is closed, the rsa
	 * key is lost unless this key has been wrapped with the master key and
	 * exported as a file to a filesystem */
	ncr_deinit_lists(ncr);
#endif
	kfree(item_import);
	return rc;
}

/* ====== Module init/exit ====== */

static int __init check_param(void)
{
	if (mkey_len != 16 && mkey_len != 24 && mkey_len != 32)
	{
		printk(KERN_ERR PFX "mkey_len should be 16, 24 or 32 bytes.\n");
		return -EINVAL;
	}
	else if (rsakey_fmt < 0 || rsakey_fmt > 3)
	{
		printk(KERN_ERR PFX "rsakey_fmt should be in range [0-3].\n");
		return -EINVAL;
	}
	return 0;
}

static int __init init_setkeymod(void)
{
	int rc;
	unsigned char *mkey = NULL;
	unsigned char *aes_key = NULL;

	/* Sanity checks on the module parameters */
	rc = check_param();
	if (unlikely(rc))
		return rc;

	/* Create a ncr_setkey directory kobject in /sys/kernel/ */
	setkey_kobj = kobject_create_and_add("ncr_setkey", kernel_kobj);
	if (!setkey_kobj)
		return -ENOMEM;

	/* Create the file kobjects  associated with the ncr-setkey kobject */
	rc = sysfs_create_group(setkey_kobj, &setkey_attr_group);
	if (rc)
		kobject_put(setkey_kobj);

	/* Master key provisioning */
	printk(KERN_INFO PFX "Master key len: %d.\n", mkey_len);

	mkey = kmalloc(mkey_len, GFP_KERNEL);
        if (!mkey) {
		err();
		return -ENOMEM;
	}

	rc = fetch_key_dummy(mkey, mkey_len);
	if (unlikely(rc))
		goto fail;

	printk(KERN_INFO PFX "Master key: \n");
	display_buf(mkey, mkey_len);

	rc = ncr_master_key_set_internal(mkey, mkey_len);
	if (unlikely(rc))
		goto fail;
	printk(KERN_INFO PFX "Master key loaded.\n");

	/* AES key provisioning */
	aes_key = kmalloc(aes_key_len, GFP_KERNEL);
        if (!aes_key) {
		err();
		goto fail;
	}

	rc = fetch_key_dummy(aes_key, aes_key_len);
	if (unlikely(rc))
		goto fail2;

	printk(KERN_INFO PFX "Master key: \n");
	display_buf(aes_key, aes_key_len);


	rc = import_aes_key(aes_key, aes_key_len, NCR_ALG_AES_CBC,
			NCR_KEY_FLAG_ENCRYPT | NCR_KEY_FLAG_DECRYPT
			| NCR_KEY_FLAG_WRAPPABLE
			| NCR_KEY_FLAG_ALLOW_TRANSPARENT_HASH,
			"aes key");
	if(unlikely(rc))
		goto fail2;
	printk(KERN_INFO PFX "AES key loaded.\n");

	/* RSA private key provisioning */
	rc = import_rsa_key(rsa_der_data,
		sizeof(rsa_der_data) / sizeof(unsigned char),
		NCR_KEY_TYPE_PRIVATE, NCR_KEY_FLAG_ENCRYPT
		| NCR_KEY_FLAG_DECRYPT | NCR_KEY_FLAG_WRAPPABLE
		| NCR_KEY_FLAG_ALLOW_TRANSPARENT_HASH,
		"rsa_priv");
	if (unlikely(rc))
		goto fail2;
	printk(KERN_INFO PFX "RSA key loaded.\n");

	return 0;
fail2:
	kfree(aes_key);
fail:
	kfree(mkey);
	return rc;
}

static void __exit exit_setkeymod(void)
{
	kobject_put(setkey_kobj);
	printk(KERN_INFO PFX "setkey driver unloaded.\n");
}

module_init(init_setkeymod);
module_exit(exit_setkeymod);
