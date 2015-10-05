/*
 * Memory Scrubber for ECC-enabled DRAM
 *
 * Copyright (C) 2015 by Alex Wilson <alex.david.wilson@gmail.com>
 *
 * Released under the GPL version 2 only.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/mmzone.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/irqflags.h>
#include <asm-generic/memory_model.h>
#include <asm/pgtable.h>
#include <linux/highmem.h>
#include <linux/mm.h>

static struct task_struct *pgscrap_th;

struct zone *(*module_next_zone)(struct zone *zone) = NULL;
struct pglist_data *(*module_first_online_pgdat)(void) = NULL;

static int
next_zone_callback(void *data, const char *name, struct module *mod, 
	unsigned long addr)
{
	if (mod != NULL) 
		return 0;

	if (strcmp(name, "next_zone") == 0) {
		if (module_next_zone != NULL) {
			pr_debug("Found two \"next_zone\" symbols in the kernel, unable to continue\n");
			return -EFAULT;
		}
		module_next_zone = (typeof(module_next_zone))addr;
	}
	return 0;
}

static int
first_online_pgdat_callback(void *data, const char *name, struct module *mod, 
	unsigned long addr)
{
	if (mod != NULL) 
		return 0;

	if (strcmp(name, "first_online_pgdat") == 0) {
		if (module_first_online_pgdat != NULL) {
			pr_debug("Found two \"first_online_pgdat\" symbols in the kernel, unable to continue\n");
			return -EFAULT;
		}
		module_first_online_pgdat = (typeof(module_first_online_pgdat))addr;
	}
	return 0;
}

static int find_symbols(void)
{
	int ret;

	ret = kallsyms_on_each_symbol(next_zone_callback, NULL);
	if (ret) {
		pr_debug("kallsyms_on_each_symbol failed");
		return ret;
	}

	if (module_next_zone == NULL) {
		pr_debug("unable to find \"next_zone\" function\n");
		return -EFAULT;
	}

	ret = kallsyms_on_each_symbol(first_online_pgdat_callback, NULL);
	if (ret) {
		pr_debug("kallsyms_on_each_symbol failed");
		return ret;
	}

	if (module_first_online_pgdat == NULL) {
		pr_debug("unable to find \"first_online_pgdat\" function\n");
		return -EFAULT;
	}

	return 0;
}


static int pgscrap_thread(void *data)
{
	int ret = 0;
	unsigned long flags, pfn, start_pfn, end_pfn;
	struct zone *zone;
	struct page *page;
	void *page_vma, *dummy_page_vma;
	unsigned long num_scans = 0;
	signed long timeout;

	set_user_nice(current, 10);

	// Hack to get first_online_pgdat() and next_zone()
	pr_debug("finding symbols\n");
	ret = find_symbols();
	if (ret) {
		pr_debug("failed to find symbols!\n");
		return ret;
	}

	dummy_page_vma = kmalloc(PAGE_SIZE, GFP_KERNEL);

	pr_debug("starting scan\n");
	while (!kthread_should_stop()) {
		for (zone = (module_first_online_pgdat())->node_zones;
			zone;
			zone = module_next_zone(zone)) {

			spin_lock_irqsave(&zone->lock, flags);

			if (zone_is_empty(zone)) {
				spin_unlock_irqrestore(&zone->lock, flags);
				continue;
			}

			start_pfn = zone->zone_start_pfn;
			end_pfn = zone_end_pfn(zone);
			spin_unlock_irqrestore(&zone->lock, flags);

			for (pfn = start_pfn; pfn < end_pfn; pfn += 1) {
				if ((pfn-start_pfn)%0x1000 == 0) {
					timeout = msecs_to_jiffies(10);
					while (timeout && !kthread_should_stop())
						timeout = schedule_timeout_interruptible(timeout);

					if (kthread_should_stop())
						goto exit_loop;
				}

				if (!pfn_valid(pfn))
					continue;

				page = pfn_to_page(pfn);

				if (!memmap_valid_within(pfn, page, zone))
					continue;
		
				if (!page_is_ram(pfn))
					continue;

				if (page_count(page) > 0) {
					page_vma = page_address(page);
					if (page_vma != NULL)
						memcpy(dummy_page_vma, page_vma, PAGE_SIZE);
				}
			}
		}
		num_scans++;
		pr_debug("scan #%lu done\n", num_scans);
	}

exit_loop:
	kfree(dummy_page_vma);

	pr_debug("task ending\n");

	return 0;
}

static int pgscrap_init(void)
{
	int err;

	pr_debug("pgscrap inserted\n");
	pgscrap_th = kthread_run(&pgscrap_thread, NULL, "pgscrap");
	if (IS_ERR(pgscrap_th)) {
		pr_debug("failed to make thread!\n");
		err = PTR_ERR(pgscrap_th);
		pgscrap_th = NULL;
		return err;
	}

	pr_debug("pgscrap thread started\n");

	return 0;
}

static void pgscrap_exit(void)
{
	if (pgscrap_th) {
		kthread_stop(pgscrap_th);
		pgscrap_th = NULL;
	}

	pr_debug("pgscrap removed\n");
}

module_init(pgscrap_init);
module_exit(pgscrap_exit);

MODULE_AUTHOR("Alex Wilson <alex.david.wilson@gmail.com>");
MODULE_DESCRIPTION("Memory Scrubber for ECC-enabled DRAM");
MODULE_LICENSE("GPL");

