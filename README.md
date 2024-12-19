
import re
import csv
import json
import os


current_dir = os.path.dirname(os.path.abspath(__file__))
log_file_path = os.path.join(current_dir, 'access_log.txt')
threat_feed_path = os.path.join(current_dir, 'threat_feed.html')
url_status_report_path = os.path.join(current_dir, 'url_status_report.txt')
malware_candidates_path = os.path.join(current_dir, 'malware_candidates.csv')
alert_json_path = os.path.join(current_dir, 'alert.json')
summary_report_path = os.path.join(current_dir, 'summary_report.json')


if not os.path.exists(log_file_path):
    raise FileNotFoundError(f"Log dosyası bulunamadı: {log_file_path}")

if not os.path.exists(threat_feed_path):
    raise FileNotFoundError(f"Threat feed dosyası bulunamadı: {threat_feed_path}")

with open(log_file_path, 'r') as log_file:
    log_data = log_file.readlines()


log_pattern = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (\S+) HTTP/\S+" (\d{3})')
url_statuses = []
status_404_count = {}

for line in log_data:
    match = log_pattern.search(line)
    if match:
        url, status_code = match.groups()
        url_statuses.append((url, int(status_code)))

        if int(status_code) == 404:
            status_404_count[url] = status_404_count.get(url, 0) + 1


# url_status_report.txt
def write_url_status_report():
    with open(url_status_report_path, 'w') as report_file:
        for url, status in url_statuses:
            report_file.write(f"{url} {status}\n")


def write_malware_candidates():
    with open(malware_candidates_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["URL", "Count"])
        for url, count in status_404_count.items():
            csv_writer.writerow([url, count])


with open(threat_feed_path, 'r') as threat_feed_file:
    threat_feed_data = threat_feed_file.read()

blacklisted_domains = re.findall(r'<li>(.*?)</li>', threat_feed_data)


blacklisted_urls = {url: count for url, count in status_404_count.items()
                    if any(domain in url for domain in blacklisted_domains)}


def write_alert_json():
    with open(alert_json_path, 'w') as alert_file:
        json.dump([{"url": url, "status": 404, "count": count} for url, count in blacklisted_urls.items()], alert_file, indent=4)


def write_summary_report():
    summary_data = {
        "total_urls_processed": len(url_statuses),
        "total_404_errors": len(status_404_count),
        "blacklisted_urls_count": len(blacklisted_urls),
        "blacklisted_domains": blacklisted_domains,
    }
    with open(summary_report_path, 'w') as summary_file:
        json.dump(summary_data, summary_file, indent=4)


write_url_status_report()
write_malware_candidates()
write_alert_json()
write_summary_report()
