// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;

static const unsigned int nr_cpus = 16;

SEC("tracepoint/csd/csd_queue_cpu")
int handle_csd_queue(struct trace_event_raw_csd_queue_cpu *ctx)
{
	unsigned int cpu = (unsigned int)ctx->cpu;
	void *func = (void *)ctx->func;

	return 0;
}

SEC("tp/csd/csd_function_entry")
int handle_csd_function_entry(struct trace_event_raw_csd_function *ctx)
{
	return 0;
}

SEC("tp/csd/csd_function_exit")
int handle_csd_function_exit(struct trace_event_raw_csd_function *ctx)
{
	return 0;
}

SEC("tp/ipi/ipi_send_cpu")
int handle_ipi_send_cpu(struct trace_event_raw_ipi_send_cpu *ctx)
{
	return 0;
}

SEC("tp_btf/ipi_send_cpumask")
int handle_tp(struct bpf_raw_tracepoint_args *ctx)
{
	struct cpumask *cpumask = (struct cpumask *)ctx->args[0];
	u32 i, cpu = bpf_get_smp_processor_id();

	for (i = 0; i < nr_cpus; ++i) {
		if (bpf_cpumask_test_cpu(i, cpumask)) {
			return 0;
		}
	}

	return 0;
}

SEC("fentry/generic_smp_call_function_single_interrupt")
int handle_call_function_single_entry(void)
{
	bpf_printk("call function single\n");
	return 0;
}

SEC("fexit/generic_smp_call_function_single_interrupt")
int handle_call_function_single_exit(void)
{
	bpf_printk("call function single exit\n");
	return 0;
}
