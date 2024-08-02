// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/libbpf.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

bool bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;

SEC("tp/ipi/ipi_send_cpumask")
int handle_tp(void *ctx)
{
	struct cpumask orig = {};
	struct bpf_cpumask *cpumask = bpf_cpumask_create();
	u32 cpu = bpf_get_smp_processor_id();

	bpf_cpumask_copy(&orig, cpumask);
	bpf_cpumask_set_cpu(cpu, &cpumask);

	if (bpf_cpumask_test_cpu(cpu, &cpumask)) {
		bpf_printk("cpu set\n");
	} else {
		bpf_printk("cpu NOT set\n");
	}

	return 0;
}
