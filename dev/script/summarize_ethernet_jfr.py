#!/usr/bin/env python3
"""Aggregate JFR JSON from `jfr print --json --events ... recording.jfr`.

Keep the JFR as raw evidence. Allocation weights are sampled estimates, not
ThreadMXBean allocation totals; execution samples are not instrumented timings.
"""
import collections
import hashlib
import json
import pathlib
import sys


def frame_name(frame):
    method = frame["method"]
    return method["type"]["name"].replace("/", ".") + "." + method["name"]


def summarize(path):
    events = json.loads(path.read_text())["recording"]["events"]
    types = collections.Counter()
    classes = collections.Counter()
    allocation_sites = collections.Counter()
    cpu_top = collections.Counter()
    cpu_inclusive = collections.Counter()
    excluded_threads = collections.Counter()
    main_counts = collections.Counter()
    class_samples = collections.Counter()
    site_samples = collections.Counter()
    first_main_weight = None
    max_main_weight = 0
    for event in events:
        kind, value = event["type"], event["values"]
        types[kind] += 1
        thread = value.get("eventThread") if kind == "jdk.ObjectAllocationSample" else value.get("sampledThread")
        if kind in {"jdk.ObjectAllocationSample", "jdk.ExecutionSample"}:
            if (thread or {}).get("javaName") != "main":
                excluded_threads[(thread or {}).get("javaName", "unknown")] += 1
                continue
            main_counts[kind] += 1
        frames = (value.get("stackTrace") or {}).get("frames", [])
        names = [frame_name(frame) for frame in frames]
        if kind == "jdk.ObjectAllocationSample":
            weight = value["weight"]
            if first_main_weight is None:
                first_main_weight = weight
            max_main_weight = max(max_main_weight, weight)
            classes[value["objectClass"]["name"]] += weight
            class_samples[value["objectClass"]["name"]] += 1
            site = next((name for name in names if name.startswith("paclo.")), "outside-paclo")
            allocation_sites[site] += weight
            site_samples[site] += 1
        if kind == "jdk.ExecutionSample":
            cpu_top[names[0] if names else "no-stack"] += 1
            cpu_inclusive.update(set(name for name in names if name.startswith("paclo.")))
    return {
        "json_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "events": dict(types),
        "main_thread_events": dict(main_counts),
        "excluded_sample_thread_counts": dict(excluded_threads),
        "first_main_allocation_sample_weight": first_main_weight,
        "maximum_main_allocation_sample_weight": max_main_weight,
        "allocation_sample_counts_by_class": class_samples.most_common(),
        "allocation_sample_counts_by_first_paclo_frame": site_samples.most_common(),
        "allocation_sample_weights_by_class": classes.most_common(),
        "allocation_sample_weights_by_first_paclo_frame": allocation_sites.most_common(),
        "execution_top_frames": cpu_top.most_common(),
        "execution_inclusive_paclo_frames": cpu_inclusive.most_common(),
    }


if __name__ == "__main__":
    print(json.dumps(summarize(pathlib.Path(sys.argv[1])), indent=2))
