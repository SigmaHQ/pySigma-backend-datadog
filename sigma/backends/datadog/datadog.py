# pylint: disable=too-many-lines
import json
import re
from typing import Any, ClassVar, Dict, List, Optional, Pattern, Tuple, Union

from sigma.conditions import ConditionAND, ConditionItem, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.pipelines.datadog import datadog_pipeline
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaRegularExpression


class DatadogBackend(TextQueryBackend):
    """Generates a Datdog query using Datadog Query Syntax. More details at the following link:  https://docs.datadoghq.com/logs/explorer/search_syntax/"""

    name: ClassVar[str] = "Datadog Backend"
    formats: Dict[str, str] = {
        "default": "Datadog query syntax",
        "siem_rule": "Datadog Cloud SIEM Rule | See the following document to make a CURL request to the following API to "
        "use the output from the siem_rule in your repository. https://docs.datadoghq.com/api/latest/security-monitoring/?code-lang=curl",
    }
    processing_pipeline: ProcessingPipeline
    requires_pipeline: bool = False
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = datadog_pipeline()

    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )
    parenthesize: bool = True

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = (
        ":"  # Token inserted between field and value (without separator)
    )

    # String Output Fields Quoting
    # field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\\w+$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ### Escaping
    field_escape: ClassVar[str] = (
        "\\"  # Character to escape particular parts defined in field_escape_pattern.
    )
    field_escape_quote: ClassVar[bool] = (
        True  # Escape quote string defined in field_quote
    )

    field_escape_pattern: ClassVar[Pattern] = re.compile(
        "[\\s]"
    )  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    escape_char: ClassVar[str] = (
        "\\"  # Escaping character for special characters inside string
    )
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = (
        ' + - = && || ! ( ) { } [ ] < > ^ “ ” ~ * ? : " # '  # Characters quoted in addition to wildcards and string quote
    )
    bool_values: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }  # Values to which boolean values are mapped.

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field}:{value}*"
    endswith_expression: ClassVar[str] = "{field}:*{value}"
    contains_expression: ClassVar[str] = "{field}:*{value}*"
    icontains_token: ClassVar[str] = "{field}:*{value}*"

    re_escape_char: ClassVar[str] = "\\"

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field}:{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: ">=",
    }

    # Expression for comparing two event fields
    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[Optional[str]] = (
        "{field1}:{field2}"  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    # https://datadoghq.atlassian.net/wiki/spaces/TS/pages/454787474/Log+search+syntax+101#Searching-for-logs-that-don%E2%80%99t-have-a-specific-value-(same-for-attributes)
    field_null_expression: ClassVar[str] = "-{field}:[0* TO z*] AND {field}:*"

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str] = (
        "{field}:*"  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[str] = (
        "NOT ({field})"  # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    # Field value in list, e.g. "field in (value list)" or "field contains all (value list)"
    # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    field_in_list_expression: ClassVar[str] = (
        "{field}{op}({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )

    # and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = " OR "  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = (
        '"{value}"'  # Expression for string value not bound to a field as format string with placeholder {value}
    )
    unbound_value_num_expression: ClassVar[str] = (
        "{value}"  # Expression for number value not bound to a field as format string with placeholder {value}
    )

    def convert_condition_field_eq_val_re(
        self, cond: SigmaRegularExpression, state: Any
    ) -> None:
        """
        This function unconditionally raises an exception because Datadog's rule syntax does not support
        full regular expressions.
        """
        raise SigmaFeatureNotSupportedByBackendError(
            "Regular expressions are not currently supported in Datadog's rule query format"
        )

    def cloud_provider_groupby(self, provider: str) -> List[str]:
        """
        Helper function to return appropriate group by fields in Datadog based on the cloud provider
        """
        if provider == "cloudtrail":
            return ["@userIdentity.arn"]
        elif provider == "gcp":
            return ["project_id", "@usr.id"]
        elif provider == "azure.*":
            return ["@usr.id"]
        else:
            return []

    def concat_false_positive_as_string(self, false_positives: List[str]) -> str:
        return ", ".join(false_positives)

    def finalize_query_siem_rule(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Generation of Datadog Cloud SIEM Detection Rules.

        Using Sigma Rules in Datadog's Cloud SIEM currently only works with the Datadog API and we are unable to import
        Sigma rules from the User Interface.

        Currently, the Datadog backend only converts Threshold rules from AWS, GCP, or Azure sources.

        For more details on how to import a Sigma rule through the API, see:
        https://docs.datadoghq.com/api/latest/security-monitoring/?code-lang=curl#create-a-detection-rule
        For more details on Cloud SIEM Detection rules, see:
        https://docs.datadoghq.com/security/cloud_siem/log_detection_rules?tab=threshold
        For best practices for writing Datadog security rules see:
        https://www.datadoghq.com/blog/writing-datadog-security-detection-rules/
        """

        siem_rule = {
            "name": f"Sigma Threshold Detection - {rule.title}",
            "type": "log_detection",
            "queries": [
                {
                    "query": f"source:{rule.logsource.service} " + query,
                    "groupByFields": self.cloud_provider_groupby(
                        rule.logsource.service
                    ),
                    "distinctFields": [],
                }
            ],
            "cases": [
                {
                    "name": "",
                    "status": (
                        str(rule.level.name).lower()
                        if rule.level is not None
                        else "low"
                    ),
                    "condition": "a > 0",
                    "notifications": [],
                }
            ],
            "isEnabled": True,
            "options": {
                "detectionMethod": "threshold",
                "evaluationWindow": 3600,
                "keepAlive": 3600,
                "maxSignalDuration": 86400,
            },
            "message": f"Sigma Rule ID: \n {str(rule.id)} \n "
            f"False Positives: \n {self.concat_false_positive_as_string(rule.falsepositives)}  \n "
            f"Description: \n {str(rule.description)}  \n "
            f"Author: \n {str(rule.author) if rule.author is not None else []} \n ",
            "tags": ["source:sigmahq"]
            + [f"{tag.namespace}:{tag.name}" for tag in rule.tags],
            "filters": [],
        }
        return json.dumps(siem_rule)

    def finalize_output_siem_rule(self, queries: List[Dict]) -> List[Dict]:
        return list(queries)
