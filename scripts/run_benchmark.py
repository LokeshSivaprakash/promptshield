#!/usr/bin/env python3
"""
Measures PromptShield's inbound detection accuracy and per-request detector
overhead against demo/benchmark_dataset.jsonl -- a 40-example synthetic set
(20 malicious across 9 distinct injection/jailbreak techniques, 20 benign,
several of which deliberately include trigger words like "ignore" and
"instructions" in ordinary sentences to test the false-positive rate, not
just the true-positive rate).

Honesty note: this is a small, hand-built, synthetic dataset -- not a
published benchmark. The number this script prints is a real, reproducible
measurement of THIS detector against THESE 40 examples, not a claim about
performance against real-world adversarial traffic at scale. Report it on
a resume as exactly that ("measured N% detection rate on a 40-example
internal benchmark"), not as an unqualified industry-wide figure. Swapping
in a larger published set (e.g. deepset/prompt-injections on Hugging Face)
is the natural next step -- see README roadmap.

Usage:
    python scripts/run_benchmark.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.detectors import injection, obfuscation

DATASET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "demo", "benchmark_dataset.jsonl")


def load_dataset(path):
    examples = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                examples.append(json.loads(line))
    return examples


def classify(text: str) -> bool:
    """True if PromptShield's inbound gate would flag this as malicious --
    mirrors the actual default.yaml thresholds (0.5) for injection and
    obfuscation, the two detectors relevant to this benchmark's labels."""
    inj = injection.detect(text)
    obf = obfuscation.detect(text)
    return inj.confidence >= 0.5 or obf.confidence >= 0.5


def main():
    examples = load_dataset(DATASET_PATH)

    tp = fp = tn = fn = 0
    latencies = []
    misclassified = []

    for ex in examples:
        start = time.perf_counter()
        predicted_malicious = classify(ex["text"])
        latencies.append((time.perf_counter() - start) * 1000)  # ms

        actual_malicious = ex["label"] == "malicious"

        if predicted_malicious and actual_malicious:
            tp += 1
        elif predicted_malicious and not actual_malicious:
            fp += 1
            misclassified.append(("FALSE POSITIVE", ex))
        elif not predicted_malicious and actual_malicious:
            fn += 1
            misclassified.append(("FALSE NEGATIVE", ex))
        else:
            tn += 1

    total = len(examples)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")
    avg_latency_ms = sum(latencies) / len(latencies) if latencies else 0
    p95_latency_ms = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0

    print(f"PromptShield inbound detection benchmark -- {total} examples "
          f"({sum(1 for e in examples if e['label'] == 'malicious')} malicious, "
          f"{sum(1 for e in examples if e['label'] == 'benign')} benign)\n")
    print(f"  Accuracy:  {accuracy:.1%}")
    print(f"  Precision: {precision:.1%}   (of what we flagged, how much was actually malicious)")
    print(f"  Recall:    {recall:.1%}   (of actual attacks, how many we caught)")
    print(f"  F1:        {f1:.3f}")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}\n")
    print(f"  Avg detector latency: {avg_latency_ms:.3f} ms/request")
    print(f"  P95 detector latency: {p95_latency_ms:.3f} ms/request")
    print(f"  (measures injection+obfuscation detector overhead only -- excludes any upstream LLM call)\n")

    if misclassified:
        print("Misclassified examples:")
        for kind, ex in misclassified:
            print(f"  [{kind}] ({ex['technique']}) {ex['text'][:80]}")
    else:
        print("No misclassifications on this benchmark set.")


if __name__ == "__main__":
    main()
