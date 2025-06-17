import argparse
import logging
import json
import requests
import feedparser
import validators
import tldextract
import os

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
        elif indicator_type == "hash":
            if not (len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64): # rudimentary hash validation
                raise ValueError("Invalid hash (length should be 32, 40, or 64 characters).")
            return "hash"
        else:
            raise ValueError("Could not determine indicator type. Please specify with -t.")
    except ValueError as e:
        logging.error(f"Validation Error: {e}")
        return None


def fetch_data_from_feed(indicator, feed_name, feed_config):
    """
    Fetches data from a specified threat intelligence feed.
    Handles different feed types (JSON, RSS).
    """
    try:
        url = feed_config["url"]
        feed_type = feed_config["type"]

        if feed_type == "json":
            if "apikey" in feed_config:
                # Add API key to headers or parameters as required by the API
                headers = {"X-API-Key": feed_config["apikey"]} # Example header - adjust as necessary
                params = {"ip": indicator} # Example parameter - adjust as necessary

                response = requests.get(url, params=params, headers=headers)

            elif "indicator_path" in feed_config:
                 url = url.replace("{indicator}", indicator)  # Dynamically replace indicator

                 response = requests.get(url)

            else:
                params = {"ip": indicator}
                response = requests.get(url, params=params)

            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()
            return data

        elif feed_type == "rss":
            feed = feedparser.parse(url)
            # Check for errors in feed parsing
            if feed.bozo:
                raise Exception(f"Error parsing RSS feed: {feed.bozo_exception}")

            for entry in feed.entries:
                if indicator in entry.summary or indicator in entry.title:
                    return entry  # Return the entire entry

            return None  # Indicator not found in RSS feed

        else:
            logging.error(f"Unsupported feed type: {feed_type} for {feed_name}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from {feed_name}: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {feed_name}: {e}")
        return None
    except Exception as e:
        logging.error(f"Error processing feed {feed_name}: {e}")
        return None



def analyze_indicator(indicator, feed_sources):
    """
    Analyzes the indicator against multiple threat intelligence feeds and calculates a risk score.
    """
    total_score = 0
    feed_matches = []

    for feed_name, feed_config in feed_sources.items():
        logging.info(f"Checking indicator against {feed_name}...")
        data = fetch_data_from_feed(indicator, feed_name, feed_config)

        if data:
            logging.info(f"Indicator found in {feed_name}.")
            feed_matches.append(feed_name)

            # Determine severity and reputation based on feed data (example logic)
            severity = DEFAULT_SEVERITY  # Default severity
            if "severity" in feed_config:
                severity = feed_config["severity"]

            reputation = feed_config.get("reputation", 0.5) # Use .get() to avoid KeyError

            # Add feed-specific logic here to extract severity or other relevant information from the data.
            # For example, if the AlienVault OTX feed returns a 'pulse' count, you might weight severity based on that.

            total_score += severity * reputation

        else:
            logging.info(f"Indicator not found in {feed_name}.")

    return total_score, feed_matches


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
        return

    logging.info(f"Analyzing indicator: {indicator} (Type: {validated_type})")


    # Load feed configuration
    feed_sources = FEED_SOURCES
    if args.config_file:
        custom_feeds = load_config_file(args.config_file)
        if custom_feeds:
            feed_sources = custom_feeds
        else:
            logging.warning("Using default feed sources due to configuration file error.")

    # Analyze the indicator
    total_score, feed_matches = analyze_indicator(indicator, feed_sources)

    logging.info(f"Total risk score: {total_score}")
    logging.info(f"Matched feeds: {feed_matches}")


    # Save results if output file is specified
    if args.output_file:
        save_results(indicator, total_score, feed_matches, args.output_file)
    else:
        print(f"Risk Score: {total_score}")
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