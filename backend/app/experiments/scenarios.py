"""Versioned, deterministic workloads for Phase 14; no personal files."""

from dataclasses import asdict, dataclass

from app.crypto.security_levels import SecurityLevel
from app.crypto.suites import SecurityArchitecture
from app.services.security_policy import DocumentCategory, Sensitivity


DATASET_VERSION = "adaptive-exp-v1"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    file_size_bytes: int
    sensitivity: Sensitivity
    document_category: DocumentCategory
    architecture: SecurityArchitecture
    recipient_count: int
    expected_adaptive_level: SecurityLevel
    description: str

    def as_dict(self) -> dict:
        result = asdict(self)
        return {key: value.value if hasattr(value, "value") else value
                for key, value in result.items()}


_KIB = 1024
_MIB = 1024 * _KIB
_BASE = (
    ("public-general", _KIB, Sensitivity.PUBLIC, DocumentCategory.GENERAL, 1, SecurityLevel.LOW),
    ("public-academic", 100 * _KIB, Sensitivity.PUBLIC, DocumentCategory.ACADEMIC, 1, SecurityLevel.LOW),
    ("internal-general", _MIB, Sensitivity.INTERNAL, DocumentCategory.GENERAL, 1, SecurityLevel.STANDARD),
    ("internal-source-code", 10 * _MIB, Sensitivity.INTERNAL, DocumentCategory.SOURCE_CODE, 1, SecurityLevel.STANDARD),
    ("confidential-financial", 25 * _MIB, Sensitivity.CONFIDENTIAL, DocumentCategory.FINANCIAL, 1, SecurityLevel.HIGH),
    ("confidential-legal", 100 * _KIB, Sensitivity.CONFIDENTIAL, DocumentCategory.LEGAL, 1, SecurityLevel.HIGH),
    ("public-medical", _MIB, Sensitivity.PUBLIC, DocumentCategory.MEDICAL, 1, SecurityLevel.HIGH),
    ("highly-confidential-general", 10 * _MIB, Sensitivity.HIGHLY_CONFIDENTIAL, DocumentCategory.GENERAL, 1, SecurityLevel.HIGH),
    ("public-credentials", _KIB, Sensitivity.PUBLIC, DocumentCategory.CREDENTIALS, 1, SecurityLevel.HIGH),
    ("public-five-recipients", 100 * _KIB, Sensitivity.PUBLIC, DocumentCategory.GENERAL, 5, SecurityLevel.LOW),
    ("internal-ten-recipients", 100 * _KIB, Sensitivity.INTERNAL, DocumentCategory.GENERAL, 10, SecurityLevel.STANDARD),
    ("confidential-twentyfive-recipients", 100 * _KIB, Sensitivity.CONFIDENTIAL, DocumentCategory.GENERAL, 25, SecurityLevel.HIGH),
)


def load_scenarios(profile: str) -> tuple[Scenario, ...]:
    if profile not in {"quick", "standard", "full"}:
        raise ValueError("Unknown experiment profile")
    selected = _BASE if profile != "quick" else (_BASE[0], _BASE[2], _BASE[6])
    return tuple(
        Scenario(f"{name}-{architecture.value.lower()}", size, sensitivity, category,
                 architecture, recipients, level,
                 f"Synthetic {sensitivity.value}/{category.value} workload")
        for architecture in (SecurityArchitecture.PQ_ONLY, SecurityArchitecture.HYBRID)
        for name, size, sensitivity, category, recipients, level in selected
    )
