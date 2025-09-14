# pylint: disable=too-many-lines
import pytest
import json
import re
from sigma.collection import SigmaCollection

from sigma.backends.datadog import DatadogBackend

# To convert a Datadog Rule from a Sigma rule (for testing purposes) use:
# datadog_backend.convert(sigma_rule, output_format="siem_rule")

################################ Smoke Tests / Utils / Testig Helpers ##################################################


@pytest.fixture
def datadog_backend():
    return DatadogBackend()


# The following tests check to ensure required fields are present in the converted rule.
# Since we don't want fragile tests, we're not comparing objects, but instead are checking to see if fields are
# present in the converted rules using the helpers below. Additional assertions per rule are made in each test.


# Helper function that compares two objects, lists, or values asserting their equality to handle the fact that JSON
# doesn't provide a guaranteed ordering of values.
def compare_rules(converted_rule, expected_rule):
    assert type(converted_rule) == type(expected_rule)
    if isinstance(converted_rule, dict):
        for key, value in converted_rule.items():
            compare_rules(value, expected_rule[key])
    elif isinstance(converted_rule, list):
        assert len(converted_rule) == len(expected_rule)
        sorted_rule_a = sorted(converted_rule)
        sorted_rule_b = sorted(expected_rule)
        for a, b in zip(sorted_rule_a, sorted_rule_b):
            compare_rules(a, b)
    else:
        assert converted_rule == expected_rule


# Helper function to check to see if required fields are present in the converted rule's message.
def check_message_fields(message):
    # Regex Patterns to check for fields in message object
    sigma_rule_id = r"Sigma Rule ID:[^3]*3bc0427d-b76f-4f26-95bf-78b8d7903dbd"
    false_positives = r"False Positives:(.*?)"
    author = r"Author:"

    assert re.search(sigma_rule_id, message)  # match anything
    assert re.search(false_positives, message)
    assert re.search(author, message)


# Helper function to runs assertions checking to see if Datadog rule structure is accurate
def sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule):
    _ = expected_dd_rule.pop("message")
    converted_message = deserialized_conversion_result.pop("message")
    compare_rules(deserialized_conversion_result, expected_dd_rule)
    check_message_fields(converted_message)


################################ Query Conversion Tests Only ###################################################
def test_datadog_and_expression(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD AND Expression
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        sel:
                            fieldA: valueA
                            fieldB: valueB
                        condition: sel
                """
            )
        )
        == ["@fieldA:valueA AND @fieldB:valueB"]
    )


def test_datadog_or_expression(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD OR Expression
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        sel1:
                            fieldA: valueA
                        sel2:
                            fieldB: valueB
                        condition: 1 of sel*
                """
            )
        )
        == ["@fieldA:valueA OR @fieldB:valueB"]
    )


def test_datadog_and_or_expression(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD AND / OR Expression 
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        sel:
                            fieldA:
                                - valueA1
                                - valueA2
                            fieldB:
                                - valueB1
                                - valueB2
                        condition: sel
                """
            )
        )
        == [
            "(@fieldA:valueA1 OR @fieldA:valueA2) AND (@fieldB:valueB1 OR @fieldB:valueB2)"
        ]
    )


def test_datadog_complex_expressions(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD Complex Expressions 
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        sel1:
                            fieldA: valueA1
                            fieldB: valueB1
                        sel2:
                            fieldA: valueA2
                            fieldB: valueB2
                        condition: 1 of sel*
                """
            )
        )
        == [
            "(@fieldA:valueA1 AND @fieldB:valueB1) OR (@fieldA:valueA2 AND @fieldB:valueB2)"
        ]
    )


def test_datadog_filters(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD Filters
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        selection:
                            - Product|contains: 'examplePhrase'
                        filter:
                            Image|endswith: '\\client32.exe'
                        condition: selection and not filter
                """
            )
        )
        == ["@Product:*examplePhrase* AND (NOT @Image:*\\client32.exe)"]
    )


def test_datadog_wildcard_expression(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD Wildcard
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        sel:
                            fieldA:
                                - valueA
                                - valueB
                                - valueC*
                        condition: sel
                """
            )
        )
        == ["@fieldA:valueA OR @fieldA:valueB OR @fieldA:valueC*"]
    )


def test_datadog_cidr_query(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD CIDR Format
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        sel:
                            field|cidr: 192.168.0.0/16
                        condition: sel
                """
            )
        )
        == ["@field:192.168.*"]
    )


def test_datadog_field_name_with_whitespace(datadog_backend: DatadogBackend):
    assert (
        datadog_backend.convert(
            SigmaCollection.from_yaml(
                """
                    title: Test DD Whitespace
                    status: test
                    logsource:
                        service: cloudtrail
                        product: aws
                    detection:
                        sel:
                            field name: value
                        condition: sel
                """
            )
        )
        == ["@field\\ name:value"]  # double slash is escaping the escape character
    )


#################################### Sigma to Datadog Rule Conversion Tests ##########################################
def test_datadog_siem_rule_output(datadog_backend: DatadogBackend):
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test DD SIEM Rule Output
            id: 3bc0427d-b76f-4f26-95bf-78b8d7903dbd
            author: "Clifford, @thebigreddog"
            status: test
            logsource:
                service: cloudtrail
                product: aws
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )
    expected_dd_rule = {
        "name": "Sigma Threshold Detection - Test DD SIEM Rule Output",
        "type": "log_detection",
        "queries": [
            {
                "query": "source:cloudtrail @fieldA:valueA AND @fieldB:valueB",
                "groupByFields": ["@userIdentity.arn"],
                "distinctFields": [],
            }
        ],
        "cases": [
            {"name": "", "status": "low", "condition": "a > 0", "notifications": []}
        ],
        "isEnabled": True,
        "options": {
            "detectionMethod": "threshold",
            "evaluationWindow": 3600,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": "Sigma Rule ID: \\n 3bc0427d-b76f-4f26-95bf-78b8d7903dbd  \\n \\n False Positives: \\n  \\n \\n Description: \\n None  \\n \\n Author: Clifford, @thebigreddog"
        " @thebigreddog",
        "tags": ["source:sigmahq"],
        "filters": [],
    }

    dd_rule_from_sigma_rule = datadog_backend.convert(
        sigma_rule, output_format="siem_rule"
    )
    deserialized_conversion_result = json.loads(dd_rule_from_sigma_rule[0])
    sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule)


def test_datadog_siem_rule_output_with_tags(datadog_backend: DatadogBackend):
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test DD SIEM rule output with Tags
            id: 3bc0427d-b76f-4f26-95bf-78b8d7903dbd
            status: test
            author: "Snoopy, @livetodance"
            logsource:
                service: cloudtrail
                product: aws
            tags:
                - attack.t1234
                - attack.t5678
                - attack.t8901.234
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
    )
    expected_dd_rule = {
        "name": "Sigma Threshold Detection - Test DD SIEM rule output with Tags",
        "type": "log_detection",
        "queries": [
            {
                "query": "source:cloudtrail @fieldA:valueA AND @fieldB:valueB",
                "groupByFields": ["@userIdentity.arn"],
                "distinctFields": [],
            }
        ],
        "cases": [
            {"name": "", "status": "low", "condition": "a > 0", "notifications": []}
        ],
        "isEnabled": True,
        "options": {
            "detectionMethod": "threshold",
            "evaluationWindow": 3600,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": "Sigma Rule ID: \\n 3bc0427d-b76f-4f26-95bf-78b8d7903dbd  \\n \\n False Positives: \\n  \\n \\n Description: \\n None  \\n \\n Author: Snoopy, @livetodance ",
        "tags": ["source:sigmahq", "attack:t1234", "attack:t5678", "attack:t8901.234"],
        "filters": [],
    }

    dd_rule_from_sigma_rule = datadog_backend.convert(
        sigma_rule, output_format="siem_rule"
    )
    deserialized_conversion_result = json.loads(dd_rule_from_sigma_rule[0])
    sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule)


def test_cloudtrail_rule(datadog_backend: DatadogBackend):
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Test DD Cloudtrail Rule
            id: 3bc0427d-b76f-4f26-95bf-78b8d7903dbd
            status: test
            author: "Toto, @tryingtogetbacktokansas"
            description: Follow the yellow brick road.
            references:
                - https://docs.aws.amazon.com
                - https://github.com/sigmahq
            date: 2023-05-27
            modified: 2023-06-03
            tags:
                - attack.privilege_escalation
                - attack.t1234.567
            logsource:
                product: aws
                service: cloudtrail
            detection:
                selection_usertype:
                    userIdentity.type: Root
                selection_eventtype:
                    eventType: AwsServiceEvent
                condition: selection_usertype and not selection_eventtype
            falsepositives:
                - AWS Task 1 with reference to https://docs.aws.amazon.com
                - AWS Task 2 with reference to https://docs.aws.amazon.com
            level: medium
        """
    )
    expected_dd_rule = {
        "name": "Sigma Threshold Detection - Test DD Cloudtrail Rule",
        "type": "log_detection",
        "queries": [
            {
                "query": "source:cloudtrail @userIdentity.type:Root AND (NOT @eventType:AwsServiceEvent)",
                "groupByFields": ["@userIdentity.arn"],
                "distinctFields": [],
            }
        ],
        "cases": [
            {"name": "", "status": "medium", "condition": "a > 0", "notifications": []}
        ],
        "isEnabled": True,
        "options": {
            "detectionMethod": "threshold",
            "evaluationWindow": 3600,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": "Sigma Rule ID: \\n 3bc0427d-b76f-4f26-95bf-78b8d7903dbd  \\n \\n False Positives: \\n AWS Task 1 with reference to https://docs.aws.amazon.com, AWS Task 2 with reference to https://docs.aws.amazon.com \\n \\n Description: \\n Follow the yellow brick road.  \\n \\n Author: Toto, @tryingtogetbacktokansas",
        "tags": ["source:sigmahq", "attack:privilege_escalation", "attack:t1234.567"],
        "filters": [],
    }

    dd_rule_from_sigma_rule = datadog_backend.convert(
        sigma_rule, output_format="siem_rule"
    )
    deserialized_conversion_result = json.loads(dd_rule_from_sigma_rule[0])
    sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule)


def test_cloudtrail_rule_with_filters(datadog_backend: DatadogBackend):
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Testing DD Cloudtrail Rule with Filters
            id: 3bc0427d-b76f-4f26-95bf-78b8d7903dbd
            name: Zoinks
            status: unsupported
            description: Get to the mystery machine
            date: 2023-05-25
            author: "Scoobydoo, @loves_scooby_snacks"
            references:
                - https://github.com/sigmahq
            tags:
                - attack.scooby_dooby_doo
                - attack.t1234
            falsepositives:
                - test1
                - test2
            logsource:
                product: aws
                service: cloudtrail
            detection:
                selection:
                    answer: '*'
                filter1:
                    ttl: '>0'
                filter2:
                    ttl: '<10'
                timeframe: 30s
                condition: selection and filter1 and filter2
            level: medium
        """
    )

    expected_dd_rule = {
        "name": "Sigma Threshold Detection - Testing DD Cloudtrail Rule with Filters",
        "type": "log_detection",
        "queries": [
            {
                "query": "source:cloudtrail @answer:* AND @ttl:\\>0 AND @ttl:\\<10",
                "groupByFields": ["@userIdentity.arn"],
                "distinctFields": [],
            }
        ],
        "cases": [
            {"name": "", "status": "medium", "condition": "a > 0", "notifications": []}
        ],
        "isEnabled": True,
        "options": {
            "detectionMethod": "threshold",
            "evaluationWindow": 3600,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": "Sigma Rule ID: \\n 3bc0427d-b76f-4f26-95bf-78b8d7903dbd  \\n \\n False Positives: \\n test1, test2 \\n \\n Description: \\n Get to the mystery machine  \\n \\n Author: Scoobydoo, @loves_scooby_snacks\\n",
        "tags": ["source:sigmahq", "attack:scooby_dooby_doo", "attack:t1234"],
        "filters": [],
    }

    dd_rule_from_sigma_rule = datadog_backend.convert(
        sigma_rule, output_format="siem_rule"
    )
    deserialized_conversion_result = json.loads(dd_rule_from_sigma_rule[0])
    sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule)


def test_azure_rule_from_auditlogs(datadog_backend: DatadogBackend):
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Testing Azure Auditlog Rules
            id: 3bc0427d-b76f-4f26-95bf-78b8d7903dbd
            status: test
            author: "Dogmatix, @idefix"
            description: |
                Obelix and Asterix friends
            tags:
                - attack.defense_evasion
                - attack.t1578
            logsource:
                product: azure
                service: auditlogs
            detection:
                selection:
                    CategoryValue: 'Woof'
                    ResourceProviderValue: 'Treats'
                    ResourceId|contains: '1234'
                    OperationNameValue: 'Ball'
                condition: selection
            falsepositives:
                - False Positive 1
                - False Positive 2
            level: medium
        """
    )

    expected_dd_rule = {
        "name": "Sigma Threshold Detection - Testing Azure Auditlog Rules",
        "type": "log_detection",
        "queries": [
            {
                "query": "source:azure.* @CategoryValue:Woof AND @ResourceProviderValue:Treats AND @ResourceId:*1234* AND @OperationNameValue:Ball",
                "groupByFields": ["@usr.id"],
                "distinctFields": [],
            }
        ],
        "cases": [
            {"name": "", "status": "medium", "condition": "a > 0", "notifications": []}
        ],
        "isEnabled": True,
        "options": {
            "detectionMethod": "threshold",
            "evaluationWindow": 3600,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": "Sigma Rule ID: \\n 3bc0427d-b76f-4f26-95bf-78b8d7903dbd  \\n \\n False Positives: \\n False Positive 1, False Positive 2 \\n \\n Description: \\n Obelix and Asterix friends\\n  Author: Dogmatix, @idefix \\n ",
        "tags": ["source:sigmahq", "attack:defense_evasion", "attack:t1578"],
        "filters": [],
    }

    dd_rule_from_sigma_rule = datadog_backend.convert(
        sigma_rule, output_format="siem_rule"
    )
    deserialized_conversion_result = json.loads(dd_rule_from_sigma_rule[0])
    sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule)


def test_azure_rule_from_signin(datadog_backend: DatadogBackend):
    sigma_rule = SigmaCollection.from_yaml(
        """
            title: Testing Azure Signin rules
            id: 3bc0427d-b76f-4f26-95bf-78b8d7903dbd
            status: test
            author: Beethoven, @friendlysaintbernard
            description: |
                'Test Description'
            tags:
                - attack.defense_evasion
                - attack.t1578
            logsource:
                product: azure
                service: signinlogs
            detection:
                selection:
                    CategoryValue: 'Woof'
                    ResourceProviderValue: 'Quack'
                    ResourceId|contains: 'Meow'
                    OperationNameValue: 'Moo'
                condition: selection
            falsepositives:
                - Testing
            level: medium
        """
    )

    expected_dd_rule = {
        "name": "Sigma Threshold Detection - Testing Azure Signin rules",
        "type": "log_detection",
        "queries": [
            {
                "query": "source:azure.* @CategoryValue:Woof AND @ResourceProviderValue:Quack AND @ResourceId:*Meow* AND @OperationNameValue:Moo",
                "groupByFields": ["@usr.id"],
                "distinctFields": [],
            }
        ],
        "cases": [
            {"name": "", "status": "medium", "condition": "a > 0", "notifications": []}
        ],
        "isEnabled": True,
        "options": {
            "detectionMethod": "threshold",
            "evaluationWindow": 3600,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": "Sigma Rule ID: \\n 3bc0427d-b76f-4f26-95bf-78b8d7903dbd  \\n \\n False Positives: \\n Testing \\n \\n Description: \\n 'Test Description'\\n  \\n \\n Author: Beethoven, @friendlysaintbernard",
        "tags": ["source:sigmahq", "attack:defense_evasion", "attack:t1578"],
        "filters": [],
    }
    dd_rule_from_sigma_rule = datadog_backend.convert(
        sigma_rule, output_format="siem_rule"
    )
    deserialized_conversion_result = json.loads(dd_rule_from_sigma_rule[0])

    sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule)


def test_gcp_rule(datadog_backend: DatadogBackend):
    sigma_rule = SigmaCollection.from_yaml(
        """
        title: Test GCP Rule
        id: 3bc0427d-b76f-4f26-95bf-78b8d7903dbd
        status: test
        description: Aggressive
        author: Cojo, @thesaintbernard
        references:
            - https://coolwebsite.com
            - https://anothercoolwebsite.com
        date: 2023-06-11
        modified: 2023-06-23
        tags:
            - attack.defense_evasion
            - attack.t1234
        logsource:
            product: gcp
            service: gcp.audit
        detection:
            selection:
                gcp.audit.method_name:
                    - v*.Compute.Firewalls.Delete
            condition: selection
        falsepositives:
            - False Positive 1
            - False Positive 2
        level: medium
        """
    )

    expected_dd_rule = {
        "name": "Sigma Threshold Detection - Test GCP Rule",
        "type": "log_detection",
        "queries": [
            {
                "query": "source:gcp @gcp.audit.method_name:v*.Compute.Firewalls.Delete",
                "groupByFields": ["project_id", "@usr.id"],
                "distinctFields": [],
            }
        ],
        "cases": [
            {"name": "", "status": "medium", "condition": "a > 0", "notifications": []}
        ],
        "isEnabled": True,
        "options": {
            "detectionMethod": "threshold",
            "evaluationWindow": 3600,
            "keepAlive": 3600,
            "maxSignalDuration": 86400,
        },
        "message": "Sigma Rule ID: \\n 3bc0427d-b76f-4f26-95bf-78b8d7903dbd  \\n \\n False Positives: \\nFalse Positive 1, False Positive 2 \\n \\n Description: \\nAggressive  \\n \\n Author:  Cojo, @thesaintbernard",
        "tags": ["source:sigmahq", "attack:defense_evasion", "attack:t1234"],
        "filters": [],
    }

    dd_rule_from_sigma_rule = datadog_backend.convert(
        sigma_rule, output_format="siem_rule"
    )
    deserialized_conversion_result = json.loads(dd_rule_from_sigma_rule[0])

    sigma_to_dd_rule_structure_tests(deserialized_conversion_result, expected_dd_rule)
