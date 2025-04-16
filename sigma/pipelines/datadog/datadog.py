# pylint: disable=too-many-lines
from dataclasses import dataclass

from sigma.processing.conditions import LogsourceCondition, RuleProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    ChangeLogsourceTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
)
from sigma.rule import SigmaRule


class AggregateRuleProcessingCondition(RuleProcessingCondition):
    def match(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> bool:
        """Match condition on Sigma rule."""
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum", "| near"]
        condition_string = " ".join(
            [field.lower() for field in rule.detection.condition]
        )
        return any(field in condition_string for field in agg_function_strings)


class DatadogFieldMappingTransformation(FieldMappingTransformation):
    def get_mapping(self, field: str):
        """
        If a field is not mapped using a Datadog Field Transformation for OOTB facets, included an @ sign to indicate
        the field is a facet. Users should double check that facets output by the pySigma-datadog-facets match the ones
        in their environment. Because facets are arbitrary, users should manually review each facet output from pySigma
        queries.
        """
        mapping = self.mapping.get(field)
        if not mapping:
            return f"@{field}"
        else:
            return mapping


def datadog_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Generic Log Source to Datadog Query Syntax Transformation",
        priority=20,
        items=[
            ProcessingItem(
                identifier=f"dd_mapping_fields",
                transformation=DatadogFieldMappingTransformation({}),
            ),
            # Datadog Supported Logsources
            ProcessingItem(
                identifier=f"dd_mapping_to_cloudtrail",
                transformation=ChangeLogsourceTransformation(
                    product="aws", service="cloudtrail"
                ),
                rule_conditions=[LogsourceCondition(product="aws")],
            ),
            ProcessingItem(
                identifier=f"dd_mapping_to_gcp",
                transformation=ChangeLogsourceTransformation(
                    product="gcp", service="gcp"
                ),
                rule_conditions=[LogsourceCondition(product="gcp")],
            ),
            ProcessingItem(
                identifier=f"dd_mapping_to_azure",
                transformation=ChangeLogsourceTransformation(
                    product="azure", service="azure.*"
                ),
                rule_condition_linking=any,  # Override default AND  condition for rule_conditions to OR
                rule_conditions=[LogsourceCondition(product="azure")],
            ),
            ProcessingItem(
                identifier="dd_fails_rule_conditions_not_supported",
                transformation=RuleFailureTransformation(
                    "The Datadog backend currently doesn't support rules with with aggregate function conditions like "
                    "count, min, max, avg, sum, and near as they're deprecated in the Sigma Spec. For more information, "
                    "see: https://sigmahq.github.io/sigma-specification/Sigma_specification.html"
                ),
                rule_conditions=[AggregateRuleProcessingCondition()],
            ),
        ],
    )
