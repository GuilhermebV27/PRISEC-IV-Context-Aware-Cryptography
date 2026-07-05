import csv
from benchmarks1 import run_benchmark

def write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

if __name__ == "__main__":
    results = run_benchmark()
    write_csv(results, "results_fase1.csv")
    print(f"Done — {len(results)} rows written.")