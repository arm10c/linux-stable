#ifndef __ASM_MEMORY_MODEL_H
#define __ASM_MEMORY_MODEL_H

#ifndef __ASSEMBLY__

#if defined(CONFIG_FLATMEM)

#ifndef ARCH_PFN_OFFSET
#define ARCH_PFN_OFFSET		(0UL)
#endif

#elif defined(CONFIG_DISCONTIGMEM)

#ifndef arch_pfn_to_nid
#define arch_pfn_to_nid(pfn)	pfn_to_nid(pfn)
#endif

#ifndef arch_local_page_offset
#define arch_local_page_offset(pfn, nid)	\
	((pfn) - NODE_DATA(nid)->node_start_pfn)
#endif

#endif /* CONFIG_DISCONTIGMEM */

/*
 * supports 3 memory models.
 */
#if defined(CONFIG_FLATMEM)

#define __pfn_to_page(pfn)	(mem_map + ((pfn) - ARCH_PFN_OFFSET))
#define __page_to_pfn(page)	((unsigned long)((page) - mem_map) + \
				 ARCH_PFN_OFFSET)
#elif defined(CONFIG_DISCONTIGMEM)

#define __pfn_to_page(pfn)			\
({	unsigned long __pfn = (pfn);		\
	unsigned long __nid = arch_pfn_to_nid(__pfn);  \
	NODE_DATA(__nid)->node_mem_map + arch_local_page_offset(__pfn, __nid);\
})

#define __page_to_pfn(pg)						\
({	const struct page *__pg = (pg);					\
	struct pglist_data *__pgdat = NODE_DATA(page_to_nid(__pg));	\
	(unsigned long)(__pg - __pgdat->node_mem_map) +			\
	 __pgdat->node_start_pfn;					\
})

#elif defined(CONFIG_SPARSEMEM_VMEMMAP)

/* memmap is virtually contiguous.  */
#define __pfn_to_page(pfn)	(vmemmap + (pfn))
#define __page_to_pfn(page)	(unsigned long)((page) - vmemmap)

#elif defined(CONFIG_SPARSEMEM)
/*
 * Note: section's mem_map is encoded to reflect its start_pfn.
 * section[i].section_mem_map == mem_map's address - start_pfn;
 */
// ARM10C 20140118
// pg : &page
//#define __page_to_pfn(pg)
//({	const struct page *__pg = (pg);
//	int __sec = page_to_section(__pg);
//	__sec : &mem_section[0][2]
//	(unsigned long)(__pg - __section_mem_map_addr(__nr_to_section(__sec)));
//	pfn offset이 계산됨
//})
#define __page_to_pfn(pg)					\
({	const struct page *__pg = (pg);				\
	int __sec = page_to_section(__pg);			\
	(unsigned long)(__pg - __section_mem_map_addr(__nr_to_section(__sec)));	\
})

// ARM10C 20140118
// pfn : 0x20000
//#define __pfn_to_page(pfn)
//({	unsigned long __pfn = (pfn);
//	struct mem_section *__sec = __pfn_to_section(__pfn);
//	__sec : &mem_section[0][2]
//	__section_mem_map_addr(__sec) + __pfn;
//	시작주소 + offset
//})
//
// ARM10C 20140329
// pfn_to_page(0xA0000)
//#define __pfn_to_page(0xA0000)
//({	unsigned long __pfn = (0xA0000);
//	struct mem_section *__sec = __pfn_to_section(__pfn);
//	__sec : &mem_section[0][0xA]
//	__section_mem_map_addr(__sec) + __pfn;
//	시작주소 + offset
//})
#define __pfn_to_page(pfn)				\
({	unsigned long __pfn = (pfn);			\
	struct mem_section *__sec = __pfn_to_section(__pfn);	\
	__section_mem_map_addr(__sec) + __pfn;		\
})
#endif /* CONFIG_FLATMEM/DISCONTIGMEM/SPARSEMEM */

// ARM10C 20140118
#define page_to_pfn __page_to_pfn
// ARM10C 20140118
// ARM10C 20140329
// ARM10C 20140517
// pfn_to_page(0xA00000)
#define pfn_to_page __pfn_to_page

#endif /* __ASSEMBLY__ */

#endif
