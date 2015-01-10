
#include <linux/device.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/pci_regs.h>
#include <linux/string.h>

/* Max address size we deal with */
// ARM10C 20141018
// OF_MAX_ADDR_CELLS: 4
#define OF_MAX_ADDR_CELLS	4
// ARM10C 20141018
// ARM10C 20141101
// OF_MAX_ADDR_CELLS: 4
// na: 1
// OF_CHECK_ADDR_COUNT(1): 1
#define OF_CHECK_ADDR_COUNT(na)	((na) > 0 && (na) <= OF_MAX_ADDR_CELLS)
// ARM10C 20141018
// ARM10C 20141101
// na: 1, ns: 1
// OF_CHECK_COUNTS(1, 1): 1
#define OF_CHECK_COUNTS(na, ns)	(OF_CHECK_ADDR_COUNT(na) && (ns) > 0)

static struct of_bus *of_match_bus(struct device_node *np);
static int __of_address_to_resource(struct device_node *dev,
		const __be32 *addrp, u64 size, unsigned int flags,
		const char *name, struct resource *r);

/* Debug utility */
#ifdef DEBUG
static void of_dump_addr(const char *s, const __be32 *addr, int na)
{
	printk(KERN_DEBUG "%s", s);
	while (na--)
		printk(" %08x", be32_to_cpu(*(addr++)));
	printk("\n");
}
#else
// ARM10C 20141018
static void of_dump_addr(const char *s, const __be32 *addr, int na) { }
#endif

/* Callbacks for bus specific translators */
// ARM10C 20141018
struct of_bus {
	const char	*name;
	const char	*addresses;
	int		(*match)(struct device_node *parent);
	void		(*count_cells)(struct device_node *child,
				       int *addrc, int *sizec);
	u64		(*map)(__be32 *addr, const __be32 *range,
				int na, int ns, int pna);
	int		(*translate)(__be32 *addr, u64 offset, int na);
	unsigned int	(*get_flags)(const __be32 *addr);
};

/*
 * Default translator (generic bus)
 */

// ARM10C 20141018
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, &na, &ns
// ARM10C 20141101
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, &na, &ns
static void of_bus_default_count_cells(struct device_node *dev,
				       int *addrc, int *sizec)
{
	// addrc: &na
	// addrc: &na
	if (addrc)
		// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// of_n_addr_cells(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): 1
		// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// of_n_addr_cells(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): 1
		*addrc = of_n_addr_cells(dev);
		// *addrc: na: 1
		// *addrc: na: 1

	// sizec: &ns
	// sizec: &ns
	if (sizec)
		// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// of_n_size_cells(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): 1
		// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		// of_n_size_cells(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): 1
		*sizec = of_n_size_cells(dev);
		// *sizec: ns: 1
		// *sizec: ns: 1
}

static u64 of_bus_default_map(__be32 *addr, const __be32 *range,
		int na, int ns, int pna)
{
	u64 cp, s, da;

	cp = of_read_number(range, na);
	s  = of_read_number(range + na + pna, ns);
	da = of_read_number(addr, na);

	pr_debug("OF: default map, cp=%llx, s=%llx, da=%llx\n",
		 (unsigned long long)cp, (unsigned long long)s,
		 (unsigned long long)da);

	if (da < cp || da >= (cp + s))
		return OF_BAD_ADDR;
	return da - cp;
}

static int of_bus_default_translate(__be32 *addr, u64 offset, int na)
{
	u64 a = of_read_number(addr, na);
	memset(addr, 0, na * 4);
	a += offset;
	if (na > 1)
		addr[na - 2] = cpu_to_be32(a >> 32);
	addr[na - 1] = cpu_to_be32(a & 0xffffffffu);

	return 0;
}

// ARM10C 20141018
// gic node의 reg property의 값의 시작주소
// ARM10C 20141101
// gic node의 reg property의 값의 시작주소
static unsigned int of_bus_default_get_flags(const __be32 *addr)
{
	// IORESOURCE_MEM: 0x00000200
	return IORESOURCE_MEM;
	// return IORESOURCE_MEM: 0x00000200
}

#ifdef CONFIG_PCI
/*
 * PCI bus specific translator
 */

static int of_bus_pci_match(struct device_node *np)
{
	/*
 	 * "pciex" is PCI Express
	 * "vci" is for the /chaos bridge on 1st-gen PCI powermacs
	 * "ht" is hypertransport
	 */
	return !strcmp(np->type, "pci") || !strcmp(np->type, "pciex") ||
		!strcmp(np->type, "vci") || !strcmp(np->type, "ht");
}

static void of_bus_pci_count_cells(struct device_node *np,
				   int *addrc, int *sizec)
{
	if (addrc)
		*addrc = 3;
	if (sizec)
		*sizec = 2;
}

static unsigned int of_bus_pci_get_flags(const __be32 *addr)
{
	unsigned int flags = 0;
	u32 w = be32_to_cpup(addr);

	switch((w >> 24) & 0x03) {
	case 0x01:
		flags |= IORESOURCE_IO;
		break;
	case 0x02: /* 32 bits */
	case 0x03: /* 64 bits */
		flags |= IORESOURCE_MEM;
		break;
	}
	if (w & 0x40000000)
		flags |= IORESOURCE_PREFETCH;
	return flags;
}

static u64 of_bus_pci_map(__be32 *addr, const __be32 *range, int na, int ns,
		int pna)
{
	u64 cp, s, da;
	unsigned int af, rf;

	af = of_bus_pci_get_flags(addr);
	rf = of_bus_pci_get_flags(range);

	/* Check address type match */
	if ((af ^ rf) & (IORESOURCE_MEM | IORESOURCE_IO))
		return OF_BAD_ADDR;

	/* Read address values, skipping high cell */
	cp = of_read_number(range + 1, na - 1);
	s  = of_read_number(range + na + pna, ns);
	da = of_read_number(addr + 1, na - 1);

	pr_debug("OF: PCI map, cp=%llx, s=%llx, da=%llx\n",
		 (unsigned long long)cp, (unsigned long long)s,
		 (unsigned long long)da);

	if (da < cp || da >= (cp + s))
		return OF_BAD_ADDR;
	return da - cp;
}

static int of_bus_pci_translate(__be32 *addr, u64 offset, int na)
{
	return of_bus_default_translate(addr + 1, offset, na - 1);
}

const __be32 *of_get_pci_address(struct device_node *dev, int bar_no, u64 *size,
			unsigned int *flags)
{
	const __be32 *prop;
	unsigned int psize;
	struct device_node *parent;
	struct of_bus *bus;
	int onesize, i, na, ns;

	/* Get parent & match bus type */
	parent = of_get_parent(dev);
	if (parent == NULL)
		return NULL;
	bus = of_match_bus(parent);
	if (strcmp(bus->name, "pci")) {
		of_node_put(parent);
		return NULL;
	}
	bus->count_cells(dev, &na, &ns);
	of_node_put(parent);
	if (!OF_CHECK_ADDR_COUNT(na))
		return NULL;

	/* Get "reg" or "assigned-addresses" property */
	prop = of_get_property(dev, bus->addresses, &psize);
	if (prop == NULL)
		return NULL;
	psize /= 4;

	onesize = na + ns;
	for (i = 0; psize >= onesize; psize -= onesize, prop += onesize, i++) {
		u32 val = be32_to_cpu(prop[0]);
		if ((val & 0xff) == ((bar_no * 4) + PCI_BASE_ADDRESS_0)) {
			if (size)
				*size = of_read_number(prop + na, ns);
			if (flags)
				*flags = bus->get_flags(prop);
			return prop;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(of_get_pci_address);

int of_pci_address_to_resource(struct device_node *dev, int bar,
			       struct resource *r)
{
	const __be32	*addrp;
	u64		size;
	unsigned int	flags;

	addrp = of_get_pci_address(dev, bar, &size, &flags);
	if (addrp == NULL)
		return -EINVAL;
	return __of_address_to_resource(dev, addrp, size, flags, NULL, r);
}
EXPORT_SYMBOL_GPL(of_pci_address_to_resource);

int of_pci_range_parser_init(struct of_pci_range_parser *parser,
				struct device_node *node)
{
	const int na = 3, ns = 2;
	int rlen;

	parser->node = node;
	parser->pna = of_n_addr_cells(node);
	parser->np = parser->pna + na + ns;

	parser->range = of_get_property(node, "ranges", &rlen);
	if (parser->range == NULL)
		return -ENOENT;

	parser->end = parser->range + rlen / sizeof(__be32);

	return 0;
}
EXPORT_SYMBOL_GPL(of_pci_range_parser_init);

struct of_pci_range *of_pci_range_parser_one(struct of_pci_range_parser *parser,
						struct of_pci_range *range)
{
	const int na = 3, ns = 2;

	if (!range)
		return NULL;

	if (!parser->range || parser->range + parser->np > parser->end)
		return NULL;

	range->pci_space = parser->range[0];
	range->flags = of_bus_pci_get_flags(parser->range);
	range->pci_addr = of_read_number(parser->range + 1, ns);
	range->cpu_addr = of_translate_address(parser->node,
				parser->range + na);
	range->size = of_read_number(parser->range + parser->pna + na, ns);

	parser->range += parser->np;

	/* Now consume following elements while they are contiguous */
	while (parser->range + parser->np <= parser->end) {
		u32 flags, pci_space;
		u64 pci_addr, cpu_addr, size;

		pci_space = be32_to_cpup(parser->range);
		flags = of_bus_pci_get_flags(parser->range);
		pci_addr = of_read_number(parser->range + 1, ns);
		cpu_addr = of_translate_address(parser->node,
				parser->range + na);
		size = of_read_number(parser->range + parser->pna + na, ns);

		if (flags != range->flags)
			break;
		if (pci_addr != range->pci_addr + range->size ||
		    cpu_addr != range->cpu_addr + range->size)
			break;

		range->size += size;
		parser->range += parser->np;
	}

	return range;
}
EXPORT_SYMBOL_GPL(of_pci_range_parser_one);

#endif /* CONFIG_PCI */

/*
 * ISA bus specific translator
 */

// ARM10C 20141018
// np: root node의 주소
static int of_bus_isa_match(struct device_node *np)
{
	// np->name: (root node의 주소)->name: NULL
	// strcmp((root node의 주소)->name, "isa"): -1
	return !strcmp(np->name, "isa");
	// return 0
}

static void of_bus_isa_count_cells(struct device_node *child,
				   int *addrc, int *sizec)
{
	if (addrc)
		*addrc = 2;
	if (sizec)
		*sizec = 1;
}

static u64 of_bus_isa_map(__be32 *addr, const __be32 *range, int na, int ns,
		int pna)
{
	u64 cp, s, da;

	/* Check address type match */
	if ((addr[0] ^ range[0]) & cpu_to_be32(1))
		return OF_BAD_ADDR;

	/* Read address values, skipping high cell */
	cp = of_read_number(range + 1, na - 1);
	s  = of_read_number(range + na + pna, ns);
	da = of_read_number(addr + 1, na - 1);

	pr_debug("OF: ISA map, cp=%llx, s=%llx, da=%llx\n",
		 (unsigned long long)cp, (unsigned long long)s,
		 (unsigned long long)da);

	if (da < cp || da >= (cp + s))
		return OF_BAD_ADDR;
	return da - cp;
}

static int of_bus_isa_translate(__be32 *addr, u64 offset, int na)
{
	return of_bus_default_translate(addr + 1, offset, na - 1);
}

static unsigned int of_bus_isa_get_flags(const __be32 *addr)
{
	unsigned int flags = 0;
	u32 w = be32_to_cpup(addr);

	if (w & 1)
		flags |= IORESOURCE_IO;
	else
		flags |= IORESOURCE_MEM;
	return flags;
}

/*
 * Array of bus specific translators
 */

// ARM10C 20141018
static struct of_bus of_busses[] = {
#ifdef CONFIG_PCI // CONFIG_PCI=n
	/* PCI */
	{
		.name = "pci",
		.addresses = "assigned-addresses",
		.match = of_bus_pci_match,
		.count_cells = of_bus_pci_count_cells,
		.map = of_bus_pci_map,
		.translate = of_bus_pci_translate,
		.get_flags = of_bus_pci_get_flags,
	},
#endif /* CONFIG_PCI */
	/* ISA */
	{
		.name = "isa",
		.addresses = "reg",
		.match = of_bus_isa_match,
		.count_cells = of_bus_isa_count_cells,
		.map = of_bus_isa_map,
		.translate = of_bus_isa_translate,
		.get_flags = of_bus_isa_get_flags,
	},
	/* Default */
	{
		.name = "default",
		.addresses = "reg",
		.match = NULL,
		.count_cells = of_bus_default_count_cells,
		.map = of_bus_default_map,
		.translate = of_bus_default_translate,
		.get_flags = of_bus_default_get_flags,
	},
};

// ARM10C 20141018
// parent: root node의 주소
static struct of_bus *of_match_bus(struct device_node *np)
{
	int i;

	// ARRAY_SIZE(of_busses): 2
	for (i = 0; i < ARRAY_SIZE(of_busses); i++)
		// i: 0, of_busses[0].match: of_bus_isa_match
		// np: root node의 주소, of_bus_isa_match(root node의 주소): 0
		// i: 1, of_busses[1].match: NULL  np: root node의 주소
		if (!of_busses[i].match || of_busses[i].match(np))
			// i: 1
			return &of_busses[i];
			// return &of_busses[1]
	BUG();
	return NULL;
}

static int of_translate_one(struct device_node *parent, struct of_bus *bus,
			    struct of_bus *pbus, __be32 *addr,
			    int na, int ns, int pna, const char *rprop)
{
	const __be32 *ranges;
	unsigned int rlen;
	int rone;
	u64 offset = OF_BAD_ADDR;

	/* Normally, an absence of a "ranges" property means we are
	 * crossing a non-translatable boundary, and thus the addresses
	 * below the current not cannot be converted to CPU physical ones.
	 * Unfortunately, while this is very clear in the spec, it's not
	 * what Apple understood, and they do have things like /uni-n or
	 * /ht nodes with no "ranges" property and a lot of perfectly
	 * useable mapped devices below them. Thus we treat the absence of
	 * "ranges" as equivalent to an empty "ranges" property which means
	 * a 1:1 translation at that level. It's up to the caller not to try
	 * to translate addresses that aren't supposed to be translated in
	 * the first place. --BenH.
	 *
	 * As far as we know, this damage only exists on Apple machines, so
	 * This code is only enabled on powerpc. --gcl
	 */
	ranges = of_get_property(parent, rprop, &rlen);
#if !defined(CONFIG_PPC)
	if (ranges == NULL) {
		pr_err("OF: no ranges; cannot translate\n");
		return 1;
	}
#endif /* !defined(CONFIG_PPC) */
	if (ranges == NULL || rlen == 0) {
		offset = of_read_number(addr, na);
		memset(addr, 0, pna * 4);
		pr_debug("OF: empty ranges; 1:1 translation\n");
		goto finish;
	}

	pr_debug("OF: walking ranges...\n");

	/* Now walk through the ranges */
	rlen /= 4;
	rone = na + pna + ns;
	for (; rlen >= rone; rlen -= rone, ranges += rone) {
		offset = bus->map(addr, ranges, na, ns, pna);
		if (offset != OF_BAD_ADDR)
			break;
	}
	if (offset == OF_BAD_ADDR) {
		pr_debug("OF: not found !\n");
		return 1;
	}
	memcpy(addr, ranges + na, 4 * pna);

 finish:
	of_dump_addr("OF: parent translation for:", addr, pna);
	pr_debug("OF: with offset: %llx\n", (unsigned long long)offset);

	/* Translate it into parent bus space */
	return pbus->translate(addr, offset, pna);
}

/*
 * Translate an address from the device-tree into a CPU physical address,
 * this walks up the tree and applies the various bus mappings on the
 * way.
 *
 * Note: We consider that crossing any level with #size-cells == 0 to mean
 * that translation is impossible (that is we are not dealing with a value
 * that can be mapped to a cpu physical address). This is not really specified
 * that way, but this is traditionally the way IBM at least do things
 */
// ARM10C 20141018
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// in_addr: gic node의 reg property의 값의 시작주소, "ranges"
static u64 __of_translate_address(struct device_node *dev,
				  const __be32 *in_addr, const char *rprop)
{
	struct device_node *parent = NULL;
	struct of_bus *bus, *pbus;
	// OF_MAX_ADDR_CELLS: 4
	__be32 addr[OF_MAX_ADDR_CELLS];
	int na, ns, pna, pns;
	// OF_BAD_ADDR: 0xFFFFFFFFFFFFFFFF
	u64 result = OF_BAD_ADDR;
	// result: 0xFFFFFFFFFFFFFFFF

	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_node_full_name(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): "/interrupt-controller@10481000"
	pr_debug("OF: ** translation for device %s **\n", of_node_full_name(dev));
	// "OF: ** translation for device "/interrupt-controller@10481000" **\n"

	/* Increase refcount at current level */
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	of_node_get(dev);

	/* Get parent & match bus type */
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_get_parent(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): root node의 주소
	parent = of_get_parent(dev);
	// parent: root node의 주소

	// parent: root node의 주소
	if (parent == NULL)
		goto bail;

	// parent: root node의 주소
	// of_match_bus(root node의 주소): &of_busses[1]
	bus = of_match_bus(parent);
	// bus: &of_busses[1]

	/* Count address cells & copy address locally */
	// bus->count_cells: (&of_busses[1])->count_cells: of_bus_default_count_cells
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_bus_default_count_cells(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, &na, &ns):
	// na: 1, ns: 1
	bus->count_cells(dev, &na, &ns);

	// na: 1, ns: 1
	// OF_CHECK_COUNTS(1, 1): 1
	if (!OF_CHECK_COUNTS(na, ns)) {
		printk(KERN_ERR "prom_parse: Bad cell count for %s\n",
		       of_node_full_name(dev));
		goto bail;
	}

	// in_addr: gic node의 reg property의 값의 시작주소, na: 1
	memcpy(addr, in_addr, na * 4);
	// addr[0]: 0x10481000

	// bus->name: (&of_busses[1])->name: "default", na: 1, ns: 1,
	// parent: root node의 주소, of_node_full_name(root node의 주소): "/"
	// addr[0]: 0x10481000
	pr_debug("OF: bus is %s (na=%d, ns=%d) on %s\n",
	    bus->name, na, ns, of_node_full_name(parent));
	of_dump_addr("OF: translating address:", addr, na);
	// "OF: bus is default (na=1, ns=1) on /\n"

	/* Translate */
	for (;;) {
		/* Switch to parent bus */
		// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
		of_node_put(dev); // null function

		// parent: root node의 주소
		dev = parent;
		// dev: root node의 주소

		// dev: root node의 주소, of_get_parent(root node의 주소): NULL
		parent = of_get_parent(dev);
		// parent: NULL

		/* If root, we have finished */
		// parent: NULL
		if (parent == NULL) {
			pr_debug("OF: reached root node\n");
			// addr[0]: 0x10481000, na: 1
			// of_read_number(addr, 1): 0x10481000
			result = of_read_number(addr, na);
			// result: 0x10481000
			break;
		}

		/* Get new parent bus and counts */
		pbus = of_match_bus(parent);
		pbus->count_cells(dev, &pna, &pns);
		if (!OF_CHECK_COUNTS(pna, pns)) {
			printk(KERN_ERR "prom_parse: Bad cell count for %s\n",
			       of_node_full_name(dev));
			break;
		}

		pr_debug("OF: parent bus is %s (na=%d, ns=%d) on %s\n",
		    pbus->name, pna, pns, of_node_full_name(parent));

		/* Apply bus translation */
		if (of_translate_one(dev, bus, pbus, addr, na, ns, pna, rprop))
			break;

		/* Complete the move up one level */
		na = pna;
		ns = pns;
		bus = pbus;

		of_dump_addr("OF: one level translation:", addr, na);
	}
 bail:
	// parent: root node의 주소
	of_node_put(parent); // null function

	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	of_node_put(dev); // null function

	// result: 0x10481000
	return result;
	// return 0x10481000
}

// ARM10C 20141018
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// addrp: gic node의 reg property의 값의 시작주소
// ARM10C 20141101
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// addrp: gic node의 reg property의 값의 시작주소 + 2
u64 of_translate_address(struct device_node *dev, const __be32 *in_addr)
{
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// in_addr: gic node의 reg property의 값의 시작주소
	// __of_translate_address(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// gic node의 reg property의 값의 시작주소, "ranges"): 0x10481000
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// in_addr: gic node의 reg property의 값의 시작주소 + 2
	// __of_translate_address(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// gic node의 reg property의 값의 시작주소 + 2, "ranges"): 0x10482000
	return __of_translate_address(dev, in_addr, "ranges");
	// return 0x10481000
	// return 0x10482000
}
EXPORT_SYMBOL(of_translate_address);

u64 of_translate_dma_address(struct device_node *dev, const __be32 *in_addr)
{
	return __of_translate_address(dev, in_addr, "dma-ranges");
}
EXPORT_SYMBOL(of_translate_dma_address);

bool of_can_translate_address(struct device_node *dev)
{
	struct device_node *parent;
	struct of_bus *bus;
	int na, ns;

	parent = of_get_parent(dev);
	if (parent == NULL)
		return false;

	bus = of_match_bus(parent);
	bus->count_cells(dev, &na, &ns);

	of_node_put(parent);

	return OF_CHECK_COUNTS(na, ns);
}
EXPORT_SYMBOL(of_can_translate_address);

// ARM10C 20141018
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 0, &size, &flags
// ARM10C 20141101
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 1,  &size, &flags
const __be32 *of_get_address(struct device_node *dev, int index, u64 *size,
		    unsigned int *flags)
{
	const __be32 *prop;
	unsigned int psize;
	struct device_node *parent;
	struct of_bus *bus;
	int onesize, i, na, ns;

	/* Get parent & match bus type */
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_get_parent(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): root node의 주소
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_get_parent(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소): root node의 주소
	parent = of_get_parent(dev);
	// parent: root node의 주소
	// parent: root node의 주소

	// parent: root node의 주소
	// parent: root node의 주소
	if (parent == NULL)
		return NULL;

	// parent: root node의 주소
	// of_match_bus(root node의 주소): &of_busses[1]
	// parent: root node의 주소
	// of_match_bus(root node의 주소): &of_busses[1]
	bus = of_match_bus(parent);
	// bus: &of_busses[1]
	// bus: &of_busses[1]

	// bus->count_cells: (&of_busses[1])->count_cells: of_bus_default_count_cells
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_bus_default_count_cells(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, &na, &ns)
	// bus->count_cells: (&of_busses[1])->count_cells: of_bus_default_count_cells
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_bus_default_count_cells(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, &na, &ns)
	bus->count_cells(dev, &na, &ns);
	// of_bus_default_count_cells에서 한일:
	// ns: 1, na: 1
	// of_bus_default_count_cells에서 한일:
	// ns: 1, na: 1

	// parent: root node의 주소
	// parent: root node의 주소
	of_node_put(parent); // null function

	// na: 1, OF_CHECK_ADDR_COUNT(1): 1
	// na: 1, OF_CHECK_ADDR_COUNT(1): 1
	if (!OF_CHECK_ADDR_COUNT(na))
		return NULL;

	/* Get "reg" or "assigned-addresses" property */
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// bus->addresses: (&of_busses[1])->addresses: "reg"
	// of_get_property(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, "reg", &psize):
	// gic node의 reg property의 값의 시작주소, psize: 32
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// bus->addresses: (&of_busses[1])->addresses: "reg"
	// of_get_property(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, "reg", &psize):
	// gic node의 reg property의 값의 시작주소, psize: 32
	prop = of_get_property(dev, bus->addresses, &psize);
	// prop: gic node의 reg property의 값의 시작주소
	// prop: gic node의 reg property의 값의 시작주소

	// prop: gic node의 reg property의 값의 시작주소
	// prop: gic node의 reg property의 값의 시작주소
	if (prop == NULL)
		return NULL;

	// psize: 32
	// psize: 32
	psize /= 4;
	// psize: 8
	// psize: 8

	// na: 1, ns: 1
	// na: 1, ns: 1
	onesize = na + ns;
	// onesize: 2
	// onesize: 2

	// psize: 8, onesize: 2
	// psize: 8, onesize: 2
	for (i = 0; psize >= onesize; psize -= onesize, prop += onesize, i++)
		// i: 0, index: 0
		// i: 1, index: 1
		if (i == index) {
			// size: &size
			// size: &size
			if (size)
				// prop: gic node의 reg property의 값의 시작주소, na: 1, ns: 1
				// of_read_number(gic node의 reg property의 값의 시작주소 + 1, 1): 0x1000
				// prop: gic node의 reg property의 값의 시작주소 + 2, na: 1, ns: 1
				// of_read_number(gic node의 reg property의 값의 시작주소 + 2 + 1, 1): 0x1000
				*size = of_read_number(prop + na, ns);
				// *size: size: 0x1000
				// *size: size: 0x1000

			// flags: &flags
			// flags: &flags
			if (flags)
				// bus->get_flags: (&of_busses[1])->get_flags: of_bus_default_get_flags
				// prop: gic node의 reg property의 값의 시작주소
				// of_bus_default_get_flags(gic node의 reg property의 값의 시작주소):
				// IORESOURCE_MEM: 0x00000200
				// bus->get_flags: (&of_busses[1])->get_flags: of_bus_default_get_flags
				// prop: gic node의 reg property의 값의 시작주소 + 2
				// of_bus_default_get_flags(gic node의 reg property의 값의 시작주소 + 2):
				// IORESOURCE_MEM: 0x00000200
				*flags = bus->get_flags(prop);
				// *flags: flags: IORESOURCE_MEM: 0x00000200
				// *flags: flags: IORESOURCE_MEM: 0x00000200

			// prop: gic node의 reg property의 값의 시작주소
			// prop: gic node의 reg property의 값의 시작주소 +  2
			return prop;
			// return gic node의 reg property의 값의 시작주소
			// return gic node의 reg property의 값의 시작주소 + 2
		}
	return NULL;
}
EXPORT_SYMBOL(of_get_address);

unsigned long __weak pci_address_to_pio(phys_addr_t address)
{
	if (address > IO_SPACE_LIMIT)
		return (unsigned long)-1;

	return (unsigned long) address;
}

// ARM10C 20141018
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// addrp: gic node의 reg property의 값의 시작주소, size: 0x1000, flags: IORESOURCE_MEM: 0x00000200
// name: NULL, r: &res
// ARM10C 20141101
// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
// addrp: gic node의 reg property의 값의 시작주소 + 2, size: 0x1000, flags: IORESOURCE_MEM: 0x00000200
// name: NULL, r: &res
static int __of_address_to_resource(struct device_node *dev,
		const __be32 *addrp, u64 size, unsigned int flags,
		const char *name, struct resource *r)
{
	u64 taddr;

	// flags: IORESOURCE_MEM: 0x00000200, IORESOURCE_IO: 0x00000100
	if ((flags & (IORESOURCE_IO | IORESOURCE_MEM)) == 0)
		return -EINVAL;

	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// addrp: gic node의 reg property의 값의 시작주소
	// of_translate_address(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// gic node의 reg property의 값의 시작주소): 0x10481000
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// addrp: gic node의 reg property의 값의 시작주소 + 2
	// of_translate_address(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// gic node의 reg property의 값의 시작주소 + 2): 0x10482000
	taddr = of_translate_address(dev, addrp);
	// taddr: 0x10481000
	// taddr: 0x10482000

	// taddr: 0x10481000, OF_BAD_ADDR: 0xFFFFFFFFFFFFFFFF
	// taddr: 0x10481000, OF_BAD_ADDR: 0xFFFFFFFFFFFFFFFF
	if (taddr == OF_BAD_ADDR)
		return -EINVAL;

	// r: &res
	// r: &res
	memset(r, 0, sizeof(struct resource));
	// res 값을 0으로 초기화
	// res 값을 0으로 초기화

	// flags: IORESOURCE_MEM: 0x00000200, IORESOURCE_IO: 0x00000100
	// flags: IORESOURCE_MEM: 0x00000200, IORESOURCE_IO: 0x00000100
	if (flags & IORESOURCE_IO) {
		unsigned long port;
		port = pci_address_to_pio(taddr);
		if (port == (unsigned long)-1)
			return -EINVAL;
		r->start = port;
		r->end = port + size - 1;
	} else {
		// r->start: (&res)->start, taddr: 0x10481000
		// r->start: (&res)->start, taddr: 0x10482000
		r->start = taddr;
		// r->start: (&res)->start: 0x10481000
		// r->start: (&res)->start: 0x10482000

		// r->end: (&res)->end, taddr: 0x10481000, size: 0x1000
		// r->end: (&res)->end, taddr: 0x10482000, size: 0x1000
		r->end = taddr + size - 1;
		// r->end: (&res)->end: 0x10481fff
		// r->end: (&res)->end: 0x10482fff
	}
	// r->flags: (&res)->flags, flags: IORESOURCE_MEM: 0x00000200
	// r->flags: (&res)->flags, flags: IORESOURCE_MEM: 0x00000200
	r->flags = flags;
	// r->flags: (&res)->flags: IORESOURCE_MEM: 0x00000200
	// r->flags: (&res)->flags: IORESOURCE_MEM: 0x00000200

	// r->name: (&res)->name, name: NULL
	// dev->full_name: (gic node의 주소)->full_name: "/interrupt-controller@10481000"
	// r->name: (&res)->name, name: NULL
	// dev->full_name: (gic node의 주소)->full_name: "/interrupt-controller@10481000"
	r->name = name ? name : dev->full_name;
	// r->name: (&res)->name: "/interrupt-controller@10481000"
	// r->name: (&res)->name: "/interrupt-controller@10481000"

	return 0;
	// return 0
	// return 0
}

/**
 * of_address_to_resource - Translate device tree address and return as resource
 *
 * Note that if your address is a PIO address, the conversion will fail if
 * the physical address can't be internally converted to an IO token with
 * pci_address_to_pio(), that is because it's either called to early or it
 * can't be matched to any host bridge IO space
 */
// ARM10C 20141018
// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 0, &res
// ARM10C 20141101
// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 1, &res
// ARM10C 20141206
// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, index: 0, &res
// ARM10C 20150110
// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소, index: 0
int of_address_to_resource(struct device_node *dev, int index,
			   struct resource *r)
{
	const __be32	*addrp;
	u64		size;
	unsigned int	flags;
	const char	*name = NULL;

	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 0
	// of_get_address(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 0, &size, &flags):
	// gic node의 reg property의 값의 시작주소, size: 0x1000, flags: IORESOURCE_MEM: 0x00000200
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 1
	// of_get_address(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 0, &size, &flags):
	// gic node의 reg property의 값의 시작주소 + 2, size: 0x1000, flags: IORESOURCE_MEM: 0x00000200
	addrp = of_get_address(dev, index, &size, &flags);
	// addrp: gic node의 reg property의 값의 시작주소
	// addrp: gic node의 reg property의 값의 시작주소 + 2

	// addrp: gic node의 reg property의 값의 시작주소
	// addrp: gic node의 reg property의 값의 시작주소 + 2
	if (addrp == NULL)
		return -EINVAL;

	/* Get optional "reg-names" property to add a name to a resource */
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 0
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 1
	of_property_read_string_index(dev, "reg-names",	index, &name);

	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// addrp: gic node의 reg property의 값의 시작주소, size: 0x1000, flags: IORESOURCE_MEM: 0x00000200
	// name: NULL, r: &res
	// __of_address_to_resource(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// gic node의 reg property의 값의 시작주소, 0x1000, IORESOURCE_MEM: 0x00000200, NULL, &res): 0
	// dev: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// addrp: gic node의 reg property의 값의 시작주소 + 2, size: 0x1000, flags: IORESOURCE_MEM: 0x00000200
	// name: NULL, r: &res
	// __of_address_to_resource(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소,
	// gic node의 reg property의 값의 시작주소 + 2, 0x1000, IORESOURCE_MEM: 0x00000200, NULL, &res): 0
	return __of_address_to_resource(dev, addrp, size, flags, name, r);
	// return 0
	// return 0
}
EXPORT_SYMBOL_GPL(of_address_to_resource);

struct device_node *of_find_matching_node_by_address(struct device_node *from,
					const struct of_device_id *matches,
					u64 base_address)
{
	struct device_node *dn = of_find_matching_node(from, matches);
	struct resource res;

	while (dn) {
		if (of_address_to_resource(dn, 0, &res))
			continue;
		if (res.start == base_address)
			return dn;
		dn = of_find_matching_node(dn, matches);
	}

	return NULL;
}


/**
 * of_iomap - Maps the memory mapped IO for a given device_node
 * @device:	the device whose io range will be mapped
 * @index:	index of the io range
 *
 * Returns a pointer to the mapped memory
 */
// ARM10C 20141018
// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 0
// ARM10C 20141101
// node: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 1
// ARM10C 20141206
// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, 0
// ARM10C 20150103
// ARM10C 20150110
// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소, 0
void __iomem *of_iomap(struct device_node *np, int index)
{
	struct resource res;

	// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 0
	// of_address_to_resource(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 0, &res): 0
	// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, index: 1
	// of_address_to_resource(devtree에서 allnext로 순회 하면서 찾은 gic node의 주소, 1, &res): 0
	// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, index: 0
	// of_address_to_resource(devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소, 0, &res): 0
	// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소, index: 0
	// of_address_to_resource(devtree에서 allnext로 순회 하면서 찾은 clock node의 주소, 0, &res): 0
	if (of_address_to_resource(np, index, &res))
		return NULL;

	// np: devtree에서 allnext로 순회 하면서 찾은 gic node의 주소
	// of_address_to_resource에서 한일(index: 0):
	// (&res)->start: 0x10481000
	// (&res)->end: 0x10481fff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/interrupt-controller@10481000"

	// of_address_to_resource에서 한일(index: 1):
	// (&res)->start: 0x10482000
	// (&res)->end: 0x10482fff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/interrupt-controller@10481000"

	// np: devtree에서 allnext로 순회 하면서 찾은 combiner node의 주소
	// of_address_to_resource에서 한일(index: 0):
	// (&res)->start: 0x10440000
	// (&res)->end: 0x10440fff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/interrupt-controller@10440000"

	// np: devtree에서 allnext로 순회 하면서 찾은 clock node의 주소
	// of_address_to_resource에서 한일(index: 0):
	// (&res)->start: 0x10010000
	// (&res)->end: 0x1003ffff
	// (&res)->flags: IORESOURCE_MEM: 0x00000200
	// (&res)->name: "/clock-controller@10010000"

	// res.start: 0x10481000, resource_size(&res): 0x1000
	// ioremap(0x10481000, 0x1000): 0xf0000000
	// res.start: 0x10482000, resource_size(&res): 0x1000
	// ioremap(0x10482000, 0x1000): 0xf0002000
	// res.start: 0x10440000, resource_size(&res): 0x1000
	// ioremap(0x10440000, 0x1000): 0xf0004000
	// res.start: 0x10010000, resource_size(&res): 0x30000
	// ioremap(0x10010000, 0x30000):
	return ioremap(res.start, resource_size(&res));
	// return 0xf0000000
	// return 0xf0002000
	// return 0xf0004000
}
EXPORT_SYMBOL(of_iomap);
