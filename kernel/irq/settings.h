/*
 * Internal header to deal with irq_desc->status which will be renamed
 * to irq_desc->settings.
 */
// ARM10C 20141004
// ARM10C 20141122
// ARM10C 20141220
enum {
	// IRQ_DEFAULT_INIT_FLAGS: 0xc00
	// _IRQ_DEFAULT_INIT_FLAGS: 0xc00
	_IRQ_DEFAULT_INIT_FLAGS	= IRQ_DEFAULT_INIT_FLAGS,
	// IRQ_PER_CPU: 0x200
	// _IRQ_PER_CPU: 0x200
	_IRQ_PER_CPU		= IRQ_PER_CPU,
	// IRQ_LEVEL: 0x100
	// _IRQ_LEVEL: 0x100
	_IRQ_LEVEL		= IRQ_LEVEL,
	// _IRQ_NOPROBE: 0x400
	_IRQ_NOPROBE		= IRQ_NOPROBE,
	// _IRQ_NOREQUEST: 0x800
	_IRQ_NOREQUEST		= IRQ_NOREQUEST,
	// _IRQ_NOTHREAD: 0x10000
	_IRQ_NOTHREAD		= IRQ_NOTHREAD,
	_IRQ_NOAUTOEN		= IRQ_NOAUTOEN,
	// IRQ_MOVE_PCNTXT: 0x4000
	// _IRQ_MOVE_PCNTXT: 0x4000
	_IRQ_MOVE_PCNTXT	= IRQ_MOVE_PCNTXT,
	// IRQ_NO_BALANCING: 0x2000
	// _IRQ_NO_BALANCING: 0x2000
	_IRQ_NO_BALANCING	= IRQ_NO_BALANCING,
	_IRQ_NESTED_THREAD	= IRQ_NESTED_THREAD,
	_IRQ_PER_CPU_DEVID	= IRQ_PER_CPU_DEVID,
	_IRQ_IS_POLLED		= IRQ_IS_POLLED,
	// IRQF_MODIFY_MASK: 0x3ff0f
	// _IRQF_MODIFY_MASK: 0x3ff0f
	_IRQF_MODIFY_MASK	= IRQF_MODIFY_MASK,
};

#define IRQ_PER_CPU		GOT_YOU_MORON
#define IRQ_NO_BALANCING	GOT_YOU_MORON
#define IRQ_LEVEL		GOT_YOU_MORON
#define IRQ_NOPROBE		GOT_YOU_MORON
#define IRQ_NOREQUEST		GOT_YOU_MORON
#define IRQ_NOTHREAD		GOT_YOU_MORON
#define IRQ_NOAUTOEN		GOT_YOU_MORON
#define IRQ_NESTED_THREAD	GOT_YOU_MORON
#define IRQ_PER_CPU_DEVID	GOT_YOU_MORON
#define IRQ_IS_POLLED		GOT_YOU_MORON
#undef IRQF_MODIFY_MASK
#define IRQF_MODIFY_MASK	GOT_YOU_MORON

// ARM10C 20141004
// desc: kmem_cache#28-o0, 0xFFFFFFFF, _IRQ_DEFAULT_INIT_FLAGS: 0xc00
// ARM10C 20141122
// desc: kmem_cache#28-oX (irq 16), clr: 0, set: 0x31600
// ARM10C 20141122
// desc: kmem_cache#28-oX (irq 16), clr: 0x800, set: 0x1400
static inline void
irq_settings_clr_and_set(struct irq_desc *desc, u32 clr, u32 set)
{
	// desc->status_use_accessors: (kmem_cache#28-o0)->status_use_accessors: 0
	// clr: 0, _IRQF_MODIFY_MASK: 0x3ff0f
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 16))->status_use_accessors: 0
	// clr: 0, _IRQF_MODIFY_MASK: 0x3ff0f
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
	// clr: 0x800, _IRQF_MODIFY_MASK: 0x3ff0f
	desc->status_use_accessors &= ~(clr & _IRQF_MODIFY_MASK);
	// desc->status_use_accessors: (kmem_cache#28-o0)->status_use_accessors: 0
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 16))->status_use_accessors: 0
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600

	// set: 0xc00, _IRQF_MODIFY_MASK: 0x3ff0f
	// set: 0x31600, _IRQF_MODIFY_MASK: 0x3ff0f
	// set: 0x1400, _IRQF_MODIFY_MASK: 0x3ff0f
	desc->status_use_accessors |= (set & _IRQF_MODIFY_MASK);
	// desc->status_use_accessors: (kmem_cache#28-o0)->status_use_accessors: 0xc00
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600
}

// ARM10C 20141122
// desc: kmem_cache#28-oX (irq 16)
static inline bool irq_settings_is_per_cpu(struct irq_desc *desc)
{
	// desc->status_use_accessors:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600,
	// _IRQ_PER_CPU: 0x200
	return desc->status_use_accessors & _IRQ_PER_CPU;
	// return 0x200
}

static inline bool irq_settings_is_per_cpu_devid(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_PER_CPU_DEVID;
}

static inline void irq_settings_set_per_cpu(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_PER_CPU;
}

static inline void irq_settings_set_no_balancing(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_NO_BALANCING;
}

// ARM10C 20141122
// desc: kmem_cache#28-oX (irq 16)
static inline bool irq_settings_has_no_balance_set(struct irq_desc *desc)
{
	// desc->status_use_accessors:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600,
	// _IRQ_NO_BALANCING: 0x2000
	return desc->status_use_accessors & _IRQ_NO_BALANCING;
	// return 0
}

// ARM10C 20141122
// desc: kmem_cache#28-oX (irq 16)
static inline u32 irq_settings_get_trigger_mask(struct irq_desc *desc)
{
	// desc->status_use_accessors:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600,
	// IRQ_TYPE_SENSE_MASK: 0x0000000f
	return desc->status_use_accessors & IRQ_TYPE_SENSE_MASK;
	// return 0
}

static inline void
irq_settings_set_trigger_mask(struct irq_desc *desc, u32 mask)
{
	desc->status_use_accessors &= ~IRQ_TYPE_SENSE_MASK;
	desc->status_use_accessors |= mask & IRQ_TYPE_SENSE_MASK;
}

// ARM10C 20141122
// desc: kmem_cache#28-oX (irq 16)
// ARM10C 20141220
// desc: kmem_cache#28-oX (irq 32)
static inline bool irq_settings_is_level(struct irq_desc *desc)
{
	// desc->status_use_accessors:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600,
	// _IRQ_LEVEL: 0x100
	return desc->status_use_accessors & _IRQ_LEVEL;
	// return 0
}

static inline void irq_settings_clr_level(struct irq_desc *desc)
{
	desc->status_use_accessors &= ~_IRQ_LEVEL;
}

static inline void irq_settings_set_level(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_LEVEL;
}

static inline bool irq_settings_can_request(struct irq_desc *desc)
{
	return !(desc->status_use_accessors & _IRQ_NOREQUEST);
}

static inline void irq_settings_clr_norequest(struct irq_desc *desc)
{
	desc->status_use_accessors &= ~_IRQ_NOREQUEST;
}

// ARM10C 20141220
// desc: kmem_cache#28-oX (irq 32)
static inline void irq_settings_set_norequest(struct irq_desc *desc)
{
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31600
	// _IRQ_NOREQUEST: 0x800
	desc->status_use_accessors |= _IRQ_NOREQUEST;
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31e00
}

static inline bool irq_settings_can_thread(struct irq_desc *desc)
{
	return !(desc->status_use_accessors & _IRQ_NOTHREAD);
}

static inline void irq_settings_clr_nothread(struct irq_desc *desc)
{
	desc->status_use_accessors &= ~_IRQ_NOTHREAD;
}

// ARM10C 20141220
// desc: kmem_cache#28-oX (irq 32)
static inline void irq_settings_set_nothread(struct irq_desc *desc)
{
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31e00,
	// _IRQ_NOTHREAD: 0x10000
	desc->status_use_accessors |= _IRQ_NOTHREAD;
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31e00
}

static inline bool irq_settings_can_probe(struct irq_desc *desc)
{
	return !(desc->status_use_accessors & _IRQ_NOPROBE);
}

static inline void irq_settings_clr_noprobe(struct irq_desc *desc)
{
	desc->status_use_accessors &= ~_IRQ_NOPROBE;
}

// ARM10C 20141220
// desc: kmem_cache#28-oX (irq 32)
static inline void irq_settings_set_noprobe(struct irq_desc *desc)
{
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31600
	// _IRQ_NOPROBE: 0x400
	desc->status_use_accessors |= _IRQ_NOPROBE;
	// desc->status_use_accessors: (kmem_cache#28-oX (irq 32))->status_use_accessors: 0x31600
}

// ARM10C 20141122
// desc: kmem_cache#28-oX (irq 16)
static inline bool irq_settings_can_move_pcntxt(struct irq_desc *desc)
{
	// desc->status_use_accessors:
	// (kmem_cache#28-oX (irq 16))->status_use_accessors: 0x31600,
	// _IRQ_MOVE_PCNTXT: 0x4000
	return desc->status_use_accessors & _IRQ_MOVE_PCNTXT;
	// return 0
}

static inline bool irq_settings_can_autoenable(struct irq_desc *desc)
{
	return !(desc->status_use_accessors & _IRQ_NOAUTOEN);
}

static inline bool irq_settings_is_nested_thread(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_NESTED_THREAD;
}

static inline bool irq_settings_is_polled(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_IS_POLLED;
}
