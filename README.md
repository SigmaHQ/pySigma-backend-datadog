# pySigma Datadog Backend

![Tests](https://github.com/SigmaHQ/pySigma-backend-datadog/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/b4bb678c2533ee5dd3f4d06fa43198dc/raw/pySigma-backend-datadog.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

## Overview
This repository contains the Datadog backend package (`sigma.backends.datadog`) for pySigma. This package contains the DatadogBackend class, which can be used to convert Sigma rules to Datadog rules and queries for use with [Datadog’s Log Management](https://www.datadoghq.com/product/log-management/) and [Datadog's Cloud SIEM](https://www.datadoghq.com/product/cloud-siem/) products.

Additionally, this repository provides a minimal `datadog_pipeline` in the sigma.pipelines.datadog package. This pipeline does not include any predefined field transformations, so any necessary mapping must be configured manually based on your desired detection behavior and the log processing in your environment.

## Output Format
**Disclaimer**: Users should **always** verify the output of the conversion tool to ensure rule and query accuracy before using in their environment.

The Datadog pySigma backend does **not** apply any transformations or field mappings. All fields are kept as they appear in the Sigma rule and are prefixed with an `@` sign. Users must review and adjust field names to match those extracted by their Datadog log pipelines. For example, if a Sigma rule uses `UserName`, but your logs extract it as `usr.name`, you must update the field in the converted rule accordingly.

The tool supports the following output formats:

- `default`: queries generated using the Datadog Query Syntax to reflect a detection.

- `siem_rule`: Rules converted from Sigma to Datadog’s Cloud SIEM detection format.

The `siem-rule` output format will convert a rule in Sigma format to the Datadog Detection Rule format, which will have a `default type: log_detection`, indicating that the rule is a security rule with a [threshold detection method](https://docs.datadoghq.com/security/cloud_siem/log_detection_rules/?tab=threshold#detection-methods) indicated by `detectionMethod: threshold` in the rule output.

Either output option can be used for log search, custom alerts, dashboards, and reporting. However, users may want to include a log source in their queries to improve efficiency.

## Supported Rule Types
The backend can convert any Sigma rule, regardless of its log source. There are no restrictions on supported rule types, as the tool does not enforce specific mappings or transformations. However, users must ensure that field names in the converted rules align with their Datadog log processing pipelines for accurate detection.

The only exception is Sigma rules that use the `|re` (regex) field modifier, which is not supported by Datadog’s log query syntax.

## Installation
1. Clone `pysigma-datadog-backend` repository
2. Clone the [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
3. Create and activate a Python [virtual environment](https://docs.python.org/3/library/venv.html) using the following commands:
```
python3 -m venv .venv
. .venv/bin/activate
```
4. Run `pip install sigma-cli` and follow instructions in the [sigma-cli repository](https://github.com/SigmaHQ/sigma-cli)
5. Install the datadog backend `sigma plugin install datadog`
6. Using the `sigma-cli`, run the following command to convert a Sigma rule to a Datadog Cloud SIEM rule
   `sigma convert -t datadog ../../user.name/sigma/sigma/rules/cloud/aws -f siem_rule`
7. Run this command to convert a Sigma rule into a Datadog Query `sigma convert -t datadog ../../user.name/sigma/sigma/rules/cloud/aws`
8. Use a text editor to view the **/scripts/local_pysigma_dd_conversion.py script** within the `pysigma-datadog-backend` repo. Modify the `sigma_rules_to_convert` list to indicate the rules that should be converted using the path in your file system to the Sigma Rules Repository cloned in Step 1.

As an example:

To convert [AWS Cloudtrail Disable Logging Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_cloudtrail_disable_logging.yml), [Azure Blocked Account Attempt Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_blocked_account_attempt.yml), and [GCP Bucket Enumeration Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gcp/gcp_bucket_enumeration.yml) to Datadog Rules locally, modify the `sigma_rules_to_convert` List using [this script](https://github.com/DataDog/pysigma-backend-datadog/tree/main/scripts) with the path from the [Sigma Rules Repository](https://github.com/SigmaHQ/sigma/tree/master/rules) cloned in step 2.
```agsl
sigma_rules_to_convert = [
  r"/Users/user.name/sigma/sigma/rules/cloud/aws/aws_cloudtrail_disable_logging.yml",
  r"/Users/user.name/sigma/sigma/rules/cloud/azure/azure_blocked_account_attempt.yml",
  r"/Users/user.name/sigma/sigma/rules/cloud/gcp/gcp_bucket_enumeration.yml"
]
```
Run the script with the command `python3 scripts/local_pysigma_dd_conversion.py` which will output either a Datadog query using the `default` output, or a Datadog Cloud SIEM detection rule using the `siem_rule` output.

## Importing Sigma Rules to Datadog
The converted query or rule will use raw Sigma field names prefixed with `@`. Since the backend does not apply any field mappings, you must manually update field names to match those processed and extracted by your Datadog log pipelines. This step is essential to ensure that detections function correctly and align with the actual log attributes available in Datadog.

Datadog processes incoming logs through **log pipelines**, where fields may be extracted, transformed, or renamed before they become available in the **Logs Explorer** and used for detection. To ensure your rule works as expected, you need to align the fields in the converted Sigma rule with the actual attributes present in your logs. This requires **reviewing and adjusting field mappings** to match the naming conventions and transformations applied within Datadog.

Depending on the behavior you want your rule to detect, you may also need to adjust the specific field used in the query. Some logs may contain multiple similar fields representing the same concept (e.g., different representations of user identities, source IPs, or event types), so selecting the correct one is important for accurate detection.

To check field mappings in the Datadog UI:
- Hover over “Logs” and click “Log Configuration”.
- Search for the log source for which you want to check field mappings.
- Click to expand the arrow next to value in the “Pipeline Name” column.

The “Remapper” rows define how fields from each log source gets mapped to Datadog facets.

Keep in mind that Datadog log pipelines may also filter out certain logs, affecting the availability of fields for detection.

To create a new Detection Rule from a converted Sigma rule, make  a `POST` request to `/api/v2/security_monitoring/rules` via the [Datadog API](https://docs.datadoghq.com/api/latest/security-monitoring/#create-a-detection-rule).

## Maintainers
- Datadog Cloud SIEM | Email: [team-cloudsiembackend@datadoghq.com]()

## Limitations
- The [Datadog Query Syntax](https://docs.datadoghq.com/tracing/trace_explorer/query_syntax/) does not currently support Sigma Rules that use [RegEx modifers](https://patzke.org/introducing-sigma-value-modifiers.html)

  - A Sigma rule using the following modifier would cause an error when processed by the Datadog Backend Conversion tool:
  ```
    selection:
      field|re: "reg.*ex"
  ```
- The backend does not apply automatic field mapping. Users must manually adjust field names in converted queries and detection rules to match their Datadog log processing pipelines.
- Importing Sigma rules via the Datadog UI is not currently supported.
