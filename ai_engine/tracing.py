import os
import sentry_sdk

def init_sentry():
    dsn = os.getenv("SENTRY_DSN", "")
    if dsn:
        sentry_sdk.init(
            dsn=dsn,
            traces_sample_rate=1.0,
            profiles_sample_rate=1.0,
        )

def trace_ai_pipeline(finding_title: str, model_name: str):
    """
    Creates a custom Sentry transaction span to trace local Gemma AI remediation calls
    (Qualifies for Best Use of Sentry Agent Tracing Partner Category).
    """
    return sentry_sdk.start_span(op="ai.pipeline", description=f"Gemma Remediate: {finding_title} [{model_name}]")
