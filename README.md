# tifa-IndicatorRiskScorer
Calculates a risk score for a given indicator (IP address, domain, URL, or hash) based on threat intelligence feeds. A feed contributes to the score only when its response actually concerns the queried indicator: for JSON feeds the indicator must appear in the response body, and for RSS feeds an entry must mention the indicator. Score formula: for each contributing feed, add severity times the feed reputation from the config. Severity comes from a numeric severity, risk_score, or threat_score field in the feed record when one is present, otherwise from the feed config severity when set, otherwise the default severity of 5. Feed requests use a 10 second timeout, including the RSS fetch. If every feed fails, no score is printed and the run exits non-zero. If feeds were queried and none reported the indicator, the score is printed as 0 with a note stating how many feeds were queried and that none reported it. An invalid indicator is rejected with a non-zero exit before any request. A configured API key is sent in the X-API-Key header.

## Install
`git clone https://github.com/ShadowGuard-AI/tifa-indicatorriskscorer`

## Usage
`./tifa-indicatorriskscorer [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: Indicator type: ip, domain, url, or hash
- `-c`: Path to a JSON configuration file containing feed sources.
- `-o`: Path to an output file to save the results.
- `-v`: Enable verbose logging for debugging.

## License
Copyright (c) ShadowGuardAI
