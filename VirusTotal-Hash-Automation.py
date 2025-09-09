import vt
import time
import csv

API_KEY = "API_KEY"
hashes = [
    "bf5ce4b2911f2d6592abafaf5096936e61d23f98fd9a6b6bbcd763269fba729b",
    "6b8cd32010895abeebbe3f8acfc9718748dfaa7b6a6a5994178b5b1712121c02",
    "d0cbcfa07cdc1727d14db175258ad5f056db38fe36134ff913cfb70c2954cf3c",
]
client = vt.Client(API_KEY)
with open("vt_results.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Hash", "Malicious", "Suspicious", "Undetected", "Harmless", "Score", "Verdict"])
    for file_hash in hashes:
        try:
            report = client.get_object(f"/files/{file_hash}")
            stats = report.last_analysis_stats

            total_engines = sum(stats.values())
            positives = stats["malicious"] + stats["suspicious"]
            score = f"{positives}/{total_engines}"
            # Verdict logic
            if stats["malicious"] > 5:
                verdict = "High Risk"
            elif stats["suspicious"] > 0:
                verdict = "Suspicious"
            else:
                verdict = "Likely Safe"
            writer.writerow([
                file_hash,
                stats["malicious"],
                stats["suspicious"],
                stats["undetected"],
                stats["harmless"],
                score,
                verdict
            ])
            print(f"{file_hash} → Score: {score} → {verdict}")
        except Exception as e:
            print(f"Error processing {file_hash}: {e}")
        # VT free API rate limit
        time.sleep(20)
client.close()


