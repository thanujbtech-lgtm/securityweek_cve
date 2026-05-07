import re
import os
import time
import requests
import feedparser
import pandas as pd

from datetime import datetime
from playwright.sync_api import sync_playwright

# ====================================
# CONFIG
# ====================================

RSS_URL = "https://www.securityweek.com/category/vulnerabilities/feed/"

DATA_FOLDER = "data"

os.makedirs(DATA_FOLDER, exist_ok=True)

CVE_PATTERN = r"CVE[\s\-–—]*\d{4}[\s\-–—]*\d{4,7}"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0 Safari/537.36"
    )
}

# ====================================
# CLEAN CVE
# ====================================

def clean_cve(cve):

    cve = cve.upper()

    cve = re.sub(r"[\s_–—]+", "-", cve)

    cve = re.sub(r"-+", "-", cve)

    return cve.strip("-")

# ====================================
# LOAD EXISTING CVEs
# ====================================

def load_existing(file_path):

    if not os.path.exists(file_path):
        return set()

    try:

        df = pd.read_excel(file_path)

        return set(df["CVE"].astype(str).tolist())

    except:
        return set()

# ====================================
# EXTRACT CVEs
# ====================================

def extract_cves(playwright, url):

    browser = playwright.chromium.launch(
        headless=True
    )

    page = browser.new_page()

    try:

        page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=60000
        )

        page.wait_for_timeout(5000)

        html = page.content()

        print("\nSTATUS: SUCCESS")
        print("URL:", url)

    except Exception as e:

        print("\nSTATUS: FAILED")
        print("URL:", url)
        print("ERROR:", e)

        browser.close()

        return []

    browser.close()

    raw = re.findall(
        CVE_PATTERN,
        html,
        re.IGNORECASE
    )

    cleaned = []

    for cve in raw:

        c = clean_cve(cve)

        if c not in cleaned:
            cleaned.append(c)

    return cleaned

# ====================================
# MAIN
# ====================================

def main():

    print("\nFetching RSS Feed...\n")

    response = requests.get(
        RSS_URL,
        headers=HEADERS,
        timeout=30
    )

    feed = feedparser.parse(response.content)

    print("RSS Articles Found:", len(feed.entries))

    with sync_playwright() as playwright:

        for idx, entry in enumerate(feed.entries, start=1):

            title = entry.title.strip()

            link = entry.link.strip()

            try:

                published = datetime(*entry.published_parsed[:6])

            except:

                published = datetime.now()

            date_str = published.strftime("%Y-%m-%d")

            file_path = os.path.join(
                DATA_FOLDER,
                f"{date_str}.xlsx"
            )

            existing = load_existing(file_path)

            print("\n" + "=" * 80)
            print(f"ARTICLE #{idx}")
            print("=" * 80)

            print("TITLE:", title)
            print("DATE :", date_str)
            print("LINK :", link)

            cves = extract_cves(
                playwright,
                link
            )

            if not cves:

                print("\nNo CVEs Found")
                continue

            rows = []

            print("\nCVEs Found:")

            for cve in cves:

                print(" -", cve)

                if cve not in existing:

                    rows.append({
                        "Date": date_str,
                        "Title": title,
                        "CVE": cve,
                        "URL": link
                    })

            if rows:

                new_df = pd.DataFrame(rows)

                if os.path.exists(file_path):

                    old_df = pd.read_excel(file_path)

                    final_df = pd.concat(
                        [old_df, new_df],
                        ignore_index=True
                    )

                else:

                    final_df = new_df

                final_df.to_excel(
                    file_path,
                    index=False
                )

                print(f"\nSaved -> {file_path}")

            else:

                print("\nNo New CVEs")

            time.sleep(2)

# ====================================
# RUN
# ====================================

if __name__ == "__main__":
    main()
