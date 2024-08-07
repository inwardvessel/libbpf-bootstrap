// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <errno.h>

char LICENSE[] SEC("license") = "GPL";

extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
extern void bpf_cpumask_copy(struct bpf_cpumask *dst, const struct cpumask *src) __ksym;
extern bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;
extern void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;

extern void generic_smp_call_function_single_interrupt(void) __ksym;

static const unsigned int nr_cpus = 16;

struct csd_queue_key {
	unsigned int cpu;
	void *func;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct csd_queue_key);
	__type(value, u64);
} csd_queue_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, unsigned int);
	__type(value, u64);
} csd_func_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, unsigned int);
	__type(value, u64);
} csd_func_latency_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, unsigned int);
	__type(value, u64);
} ipi_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, unsigned int);
	__type(value, u64);
} interrupt_map SEC(".maps");

struct update_ipi_ctx {
	u64 t;
	struct bpf_cpumask *cpumask;
};

SEC("tracepoint/csd/csd_queue_cpu")
int handle_csd_queue(struct trace_event_raw_csd_queue_cpu *ctx)
{
	const u64 t = bpf_ktime_get_ns();
	const struct csd_queue_key key = {
		.cpu = (unsigned int)ctx->cpu,
		.func = (void *)ctx->func
	};

	bpf_map_update_elem(&csd_queue_map, &key, &t, BPF_NOEXIST);

	return 0;
}

SEC("tp/csd/csd_function_entry")
int handle_csd_function_entry(struct trace_event_raw_csd_function *ctx)
{
	u64 *t0, t1;
	s64 dt;
	unsigned int cpu;
	struct csd_queue_key key;

	t1 = bpf_ktime_get_ns();
	cpu = bpf_get_smp_processor_id();

	key.cpu = cpu;
	key.func = (void *)ctx->func;
	t0 = bpf_map_lookup_elem(&csd_queue_map, &key);
	if (!t0)
		return 0;

	dt = t1 - *t0;
	if (dt < 0) {
		bpf_printk("unexpected time delta\n");
		return 0;
	}

	// @csd_queue_latency = hist(dt)
	bpf_map_update_elem(&csd_func_map, &cpu, &t1, BPF_NOEXIST);
	bpf_map_delete_elem(&csd_queue_map, &key);

	return 0;
}

SEC("tp/csd/csd_function_exit")
int handle_csd_function_exit(struct trace_event_raw_csd_function *ctx)
{
	u64 *t0, t1;
	s64 dt;
	unsigned int cpu;

	t1 = bpf_ktime_get_ns();
	t0 = bpf_map_lookup_elem(&csd_func_map, &cpu);
	if (!t0)
		return 0;

	dt = t1 - *t0;
	if (dt < 0) {
		bpf_printk("unexpected time delta\n");
		return 0;
	}

	// @csd_func_latency_map[func] = hist(dt)
	bpf_map_delete_elem(&csd_func_map, &cpu);

	return 0;
}

SEC("tp/ipi/ipi_send_cpu")
int handle_ipi_send_cpu(struct trace_event_raw_ipi_send_cpu *ctx)
{
	u64 t;
	unsigned int cpu;
	void *callback;

	t = bpf_ktime_get_ns();

	callback = ctx->callback;
	if (callback != generic_smp_call_function_single_interrupt)
		return 0;

	cpu = ctx->cpu;
	bpf_map_update_elem(&ipi_map, &cpu, &t, BPF_NOEXIST);

	return 0;
}

static long maybe_update_ipi_map(u32 i, void *ctx)
{
	struct update_ipi_ctx *x = (struct update_ipi_ctx *)ctx;

	if (bpf_cpumask_test_cpu(i, (struct cpumask *)x->cpumask))
		bpf_map_update_elem(&ipi_map, &i, &x->t, BPF_NOEXIST);

	return 0;
}

SEC("tp_btf/ipi_send_cpumask")
int handle_ipi_send_cpumask(struct bpf_raw_tracepoint_args *ctx)
{
	struct update_ipi_ctx x;
	void *callback;

	x.t = bpf_ktime_get_ns();

	callback = (void *)ctx->args[2];
	if (callback != generic_smp_call_function_single_interrupt)
		return 0;

	x.cpumask = bpf_cpumask_create();
	if (!x.cpumask)
		return -ENOMEM;

	bpf_cpumask_copy(x.cpumask, (struct cpumask *)ctx->args[0]);
	bpf_loop(16, maybe_update_ipi_map, &x, 0);
	bpf_cpumask_release(x.cpumask);

	return 0;
}

SEC("fentry/generic_smp_call_function_single_interrupt")
int handle_call_function_single_entry(void)
{
	u64 *t0, t1;
	s64 dt;
	unsigned int cpu;

	t1 = bpf_ktime_get_ns();
	cpu = bpf_get_smp_processor_id();
	t0 = bpf_map_lookup_elem(&ipi_map, &cpu);
	if (!t0)
		return 0;

	dt = t1 - *t0;
	if (dt < 0) {
		return -1;
	}

	bpf_map_delete_elem(&ipi_map, &cpu);

	// @ipi_latency = hist(dt)

	bpf_map_update_elem(&interrupt_map, &cpu, &t1, BPF_NOEXIST);

	return 0;
}

SEC("fexit/generic_smp_call_function_single_interrupt")
int handle_call_function_single_exit(void)
{
	u64 *t0, t1;
	s64 dt;
	unsigned int cpu;

	t1 = bpf_ktime_get_ns();
	cpu = bpf_get_smp_processor_id();
	t0 = bpf_map_lookup_elem(&interrupt_map, &cpu);
	if (!t0)
		return 0;

	dt = t1 - *t0;
	if (dt < 0) {
		bpf_printk("unexpected time delta\n");
		return -EINVAL;
	}

	bpf_map_delete_elem(&interrupt_map, &cpu);

	// @interrupt_latency = hist(dt)

	return 0;
}
