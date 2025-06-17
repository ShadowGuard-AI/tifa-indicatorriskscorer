# tifa-IndicatorRiskScorer
Calculates a risk score for a given indicator (e.g., IP address, domain) based on the number of feeds it appears in and the severity level associated with each feed. Scores are weighted based on feed reputation. - Focused on Aggregates and analyzes threat intelligence feeds from various sources (e.g., AlienVault OTX, VirusTotal) to identify potentially malicious indicators (IP addresses, domains, URLs, hashes).  It normalizes data, filters for relevance, and allows for customizable alerting based on configurable rules. Focuses on identifying potential threats impacting the user's environment.

## Install
`git clone https://github.com/ShadowGuardAI/tifa-indicatorriskscorer`

## Usage
`./tifa-indicatorriskscorer [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: No description provided
- `-c`: Path to a JSON configuration file containing feed sources.
- `-o`: Path to an output file to save the results.
- `-v`: Enable verbose logging for debugging.

## License
Copyright (c) ShadowGuardAI
