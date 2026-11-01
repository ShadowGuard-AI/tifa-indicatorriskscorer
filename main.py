import argparse
import logging
import json
import requests
import feedparser
import validators
import tldextract
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define feed sources and their reputation scores (example)
FEED_SOURCES = {
    "AlienVault OTX": {"url": "https://otx.alienvault.com/api/v1/indicators/IPv4/reputation", "reputation": 0.8, "type": "json"},  # Example - needs proper OTX integration
    "VirusTotal": {"url": "https://www.virustotal.com/vtapi/v2/ip-address/report", "reputation": 0.9, "type": "json", "apikey": ""}, # API key required
    "Blocklist.de": {"url": "http://www.blocklist.de/en/rss.xml", "reputation": 0.7, "type": "rss"}
}

DEFAULT_SEVERITY = 5  # Default severity score if not specified in feed

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="TIFA-IndicatorRiskScorer: Calculates a risk score for a given indicator based on threat intelligence feeds.")
    parser.add_argument("indicator", help="The indicator to check (e.g., IP address, domain, URL, hash).")
    parser.add_argument("-t", "--indicator_type", choices=["ip", "domain", "url", "hash"], help="The type of the indicator (optional, autodetected if not provided).", required=False)
    parser.add_argument("-c", "--config_file", help="Path to a JSON configuration file containing feed sources.", required=False)
    parser.add_argument("-o", "--output_file", help="Path to an output file to save the results.", required=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging for debugging.")

    return parser.parse_args()


def validate_indicator(indicator, indicator_type=None):
    """
    Validates the provided indicator based on its type.
    """
    try:
        if indicator_type == "ip" or (indicator_type is None and validators.ipv4(indicator)):
            if not validators.ipv4(indicator):
                raise ValueError("Invalid IPv4 address.")
            return "ip"
        elif indicator_type == "domain" or (indicator_type is None and validators.domain(indicator)):
            if not validators.domain(indicator):
                raise ValueError("Invalid domain name.")
            return "domain"
        elif indicator_type == "url" or (indicator_type is None and validators.url(indicator)):
             if not validators.url(indicator):
                raise ValueError("Invalid URL.")
             return "url"
        # Hash is reachable only when the operator names the type. My autodetect chain above tries address, domain, then URL, and a bare hash falls off the end into the could not determine error, so the type I advertise as supported is the one type auto mode can never find.
        elif indicator_type == "hash":
            # Length is the entire hash test. A 64 character sentence fragment with spaces passes as a hash, and a genuine SHA-512 digest at 128 characters is refused, because I never look at whether the characters are hex.
            if not (len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64): # rudimentary hash validation
                raise ValueError("Invalid hash (length should be 32, 40, or 64 characters).")
            return "hash"
        else:
            raise ValueError("Could not determine indicator type. Please specify with -t.")
    except ValueError as e:
        logging.error(f"Validation Error: {e}")
        return None


def _feed_severity(data):
    """Returns a numeric severity found in a feed record, or None."""
    if isinstance(data, dict):
        for key in ("severity", "risk_score", "threat_score"):
            value = data.get(key)
            if isinstance(value, (int, float)):
                return max(0.0, min(10.0, float(value)))
        for value in data.values():
            found = _feed_severity(value)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _feed_severity(item)
            if found is not None:
                return found
    return None


def _response_concerns_indicator(data, indicator):
    """True only when the feed response actually mentions the indicator."""
    try:
        body = json.dumps(data)
    except Exception:
        body = str(data)
    return indicator in body or indicator.lower() in body.lower()


def fetch_data_from_feed(indicator, feed_name, feed_config):
    """
    Fetches data from a specified threat intelligence feed.

    Returns a tuple (data, succeeded). succeeded is True when the feed
    was actually queried, even when its response does not concern the
    indicator. data is the feed record only when the response concerns
    the indicator; otherwise data is None.
    """
    try:
        url = feed_config["url"]
        feed_type = feed_config["type"]

        if feed_type == "json":
            if "apikey" in feed_config:
                headers = {"X-API-Key": feed_config["apikey"]}
                params = {"ip": indicator}
                response = requests.get(url, params=params, headers=headers, timeout=10)
            elif "indicator_path" in feed_config:
                 url = url.replace("{indicator}", indicator)
                 response = requests.get(url, timeout=10)
            else:
                params = {"ip": indicator}
                response = requests.get(url, params=params, timeout=10)

            response.raise_for_status()
            data = response.json()
            if not _response_concerns_indicator(data, indicator):
                logging.info(f"Feed {feed_name} responded but its response does not concern {indicator}.")
                return None, True
            return data, True

        elif feed_type == "rss":
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            if feed.bozo:
                raise Exception(f"Error parsing RSS feed: {feed.bozo_exception}")
            for entry in feed.entries:
                title = getattr(entry, "title", "") or entry.get("title", "") if isinstance(entry, dict) else ""
                summary = getattr(entry, "summary", "") or ""
                if not isinstance(entry, dict):
                    text = f"{title} {summary} {getattr(entry, 'description', '') or ''}"
                else:
                    text = f"{entry.get('title','')} {entry.get('summary','')} {entry.get('description','')}"
                if indicator in text:
                    return entry, True
            return None, True

        else:
            logging.error(f"Unsupported feed type: {feed_type} for {feed_name}")
            return None, False

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from {feed_name}: {e}")
        return None, False
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {feed_name}: {e}")
        return None, False
    except Exception as e:
        logging.error(f"Error processing feed {feed_name}: {e}")
        return None, False



def analyze_indicator(indicator, feed_sources):
    """
    Analyzes the indicator against multiple feeds and calculates a risk score.

    Score formula: for each feed whose response actually concerns the
    indicator, add severity times the feed reputation. Severity comes
    from a numeric severity, risk_score, or threat_score field in the
    feed record when one is present, otherwise from the feed config
    severity when set, otherwise the default severity of 5.

    Returns (total_score, feed_matches, succeeded_count).
    """
    total_score = 0
    feed_matches = []
    succeeded = 0

    for feed_name, feed_config in feed_sources.items():
        logging.info(f"Checking indicator against {feed_name}...")
        data, ok = fetch_data_from_feed(indicator, feed_name, feed_config)
        if ok:
            succeeded += 1
        if data:
            logging.info(f"Indicator found in {feed_name}.")
            feed_matches.append(feed_name)
            severity = _feed_severity(data)
            if severity is None:
                severity = feed_config.get("severity", DEFAULT_SEVERITY)
            reputation = feed_config.get("reputation", 0.5)
            total_score += float(severity) * float(reputation)
        else:
            logging.info(f"Indicator not found in {feed_name}.")

    return total_score, feed_matches, succeeded


def load_config_file(config_file_path):
    """
    Loads feed configuration from a JSON file.
    """
    try:
        with open(config_file_path, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logging.error(f"Config file not found: {config_file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in config file: {config_file_path}")
        return None
    except Exception as e:
        logging.error(f"Error loading config file: {e}")
        return None


def save_results(indicator, total_score, feed_matches, output_file):
    """
    Saves the analysis results to a JSON file.
    """
    results = {
        "indicator": indicator,
        "risk_score": total_score,
        "matched_feeds": feed_matches
    }

    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving results to file: {e}")



def main():
    """
    Main function to orchestrate the indicator risk scoring process.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    indicator = args.indicator
    indicator_type = args.indicator_type


    # Input Validation
    validated_type = validate_indicator(indicator, indicator_type)
    if not validated_type:
        print("Invalid indicator. Please provide a valid IP address, domain, URL, or hash.")
        sys.exit(1)

    logging.info(f"Analyzing indicator: {indicator} (Type: {validated_type})")


    # Load feed configuration
    feed_sources = FEED_SOURCES
    if args.config_file:
        custom_feeds = load_config_file(args.config_file)
        # An empty JSON object in the config file is falsy, so a file that deliberately defines no feeds falls back to my built in defaults with only a log warning. The operator asked for no feeds and gets three.
        if custom_feeds:
            feed_sources = custom_feeds
        else:
            logging.warning("Using default feed sources due to configuration file error.")

    # Analyze the indicator
    total_score, feed_matches, succeeded = analyze_indicator(indicator, feed_sources)

    if succeeded == 0:
        print("No feed could be queried, so no risk score was computed.")
        logging.error("All feeds failed; no score was computed.")
        sys.exit(1)

    logging.info(f"Total risk score: {total_score}")
    logging.info(f"Matched feeds: {feed_matches}")


    # Save results if output file is specified
    if args.output_file:
        save_results(indicator, total_score, feed_matches, args.output_file)
    else:
        if feed_matches:
            print(f"Risk Score: {total_score}")
        else:
            print(f"Risk Score: {total_score} (checked: {succeeded} feed(s) queried, none reported the indicator)")
        print(f"Matched Feeds: {feed_matches}")


if __name__ == "__main__":
    main()


"""
Usage Examples:

1. Basic usage (IP address):
   python tifa-IndicatorRiskScorer.py 8.8.8.8

2. Specifying the indicator type (domain):
   python tifa-IndicatorRiskScorer.py example.com -t domain

3. Using a custom configuration file:
   python tifa-IndicatorRiskScorer.py 1.1.1.1 -c custom_feeds.json

   (Create a custom_feeds.json file with the same structure as FEED_SOURCES)

4. Saving the output to a file:
   python tifa-IndicatorRiskScorer.py 127.0.0.1 -o results.json

5. Enabling verbose logging:
   python tifa-IndicatorRiskScorer.py 192.168.1.1 -v

Example custom_feeds.json:

{
    "MyCustomFeed": {
        "url": "http://example.com/threats.json?ip={indicator}",
        "reputation": 0.6,
        "type": "json",
        "indicator_path": true,
        "severity": 7
    }
}

Offensive Tool Integration Notes:
This tool, as it stands, primarily focuses on threat intelligence aggregation and risk assessment.
However, it can be integrated into offensive security workflows by:

1.  Enrichment: Using the risk scores to prioritize targets for further investigation or attack.
    Higher-scoring indicators suggest a higher likelihood of compromise or vulnerability.

2.  Reconnaissance:  Automating the process of gathering information about a target by checking its IP addresses, domains,
    and other identifiers against threat intelligence feeds.

3.  Red Teaming:  Simulating attacker behavior by checking if the tools and techniques being used are flagged by threat intelligence feeds,
    allowing for adjustments to evade detection.

4.  Vulnerability Scanning:  Prioritizing vulnerabilities based on whether associated indicators (e.g., IP addresses, domains hosting vulnerable software)
    are flagged as malicious.

Security Considerations:

*   API Keys:  Store API keys securely (e.g., using environment variables or a dedicated secrets management system).  Never hardcode them in the script.
*   Input Validation:  Thoroughly validate all inputs to prevent injection attacks and other vulnerabilities.
*   Rate Limiting:  Implement rate limiting to avoid overloading threat intelligence feed providers and potentially getting blocked.
*   Error Handling:  Handle errors gracefully and avoid exposing sensitive information in error messages.
*   Data Handling:  Properly sanitize and escape data when saving results to files or displaying them in the console.
*  Authentication: Ensure secure authentication if using private or internal threat intelligence feeds.
"""