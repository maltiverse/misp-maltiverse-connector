# misp-maltiverse-connector
A connector to upload MISP Threat Intelligence to Maltiverse Platform

```
usage: misp-maltiverse-connector.py [-h] --maltiverse-api-key MALTIVERSE_API_KEY --misp-api-key MISP_API_KEY --misp-url MISP_URL
                                    [--publish-timestamp PUBLISH_TIMESTAMP] [--filter-to-ids TO_IDS] [--filter-org ORG] [--filter-eventid EVENTID]

options:
  -h, --help            show this help message and exit
  --maltiverse-api-key MALTIVERSE_API_KEY
                        Specifies Maltiverse APIKEY. Required
  --misp-api-key MISP_API_KEY
                        Specifies the MISP APIKEY to retrieve events from.
  --misp-url MISP_URL   Specifies the MISP URL to retrieve events from.
  --publish-timestamp PUBLISH_TIMESTAMP
                        Specifies the time window of events retrieved from MISP. Default 1h
  --filter-to-ids TO_IDS
                        Select if you want to filter only to_ids attributes. (0 | 1 | None)
  --filter-org ORG      Filter events by Organization ID
  --filter-eventid EVENTID
                        Filter events by Event ID
```
