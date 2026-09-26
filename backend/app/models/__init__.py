"""Model registry — imports all ORM models so Base.metadata discovers them."""

from app.models.evidence import Evidence, EvidenceType, EvidenceStatus
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.partition import Partition, FilesystemType
from app.models.mft_entry import MFTEntry, MFTEntryStatus
from app.models.fragment import Fragment, FragmentStatus
from app.models.fragment_feature import FragmentFeature
from app.models.fragment_match import FragmentMatch
from app.models.artifact import Artifact, RecoveryMethod, ArtifactStatus
from app.models.report import Report, ReportFormat, ReportStatus
from app.models.llm_interaction import LLMInteraction, LLMProvider, LLMInteractionType
from app.models.anomaly import Anomaly, AnomalyType, AnomalySeverity
from app.models.embedding import Embedding
from app.models.artifact_integrity import ArtifactIntegrity, IntegrityStatus
from app.models.classification import Classification

__all__ = [
    # Core models
    "Evidence", "EvidenceType", "EvidenceStatus",
    "Scan", "ScanType", "ScanStatus",
    "Partition", "FilesystemType",
    "MFTEntry", "MFTEntryStatus",
    "Fragment", "FragmentStatus",
    "FragmentFeature",
    "FragmentMatch",
    "Artifact", "RecoveryMethod", "ArtifactStatus",
    # Supplementary models
    "Report", "ReportFormat", "ReportStatus",
    "LLMInteraction", "LLMProvider", "LLMInteractionType",
    "Anomaly", "AnomalyType", "AnomalySeverity",
    "Embedding",
    "ArtifactIntegrity", "IntegrityStatus",
    "Classification",
]
