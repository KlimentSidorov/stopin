"""Harmless protocol experiments. Identifiers are capabilities, never identity claims."""
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class ExperimentFamily:
    name: str
    method: str
    presentation: str


FAMILIES = (
    ExperimentFamily("resource", "GET", "resource"),
    ExperimentFamily("protocol_action", "POST", "action"),
    ExperimentFamily("metadata_reference", "GET", "reference"),
)


@dataclass
class AgentExperiment:
    experiment_id: str
    challenge_id: str
    session_id: str
    experiment_type: str
    resource_id: str
    method: str
    presentation: str
    created_at: float
    expires_at: float
    activated: bool = False
    activation_order: int | None = None
    activation_phase: str | None = None
    replay_count: int = 0

    def descriptor(self):
        prefix = "/challenge/tripwire/" if self.experiment_type == "resource" else "/challenge/experiments/"
        descriptor = {"kind": self.presentation, "url": prefix + self.resource_id,
                      "method": self.method}
        if self.presentation == "action":
            descriptor["body"] = {}  # Harmless diagnostic action; no credentials or nonce.
        if self.presentation == "reference":
            descriptor["reference"] = "urn:stopin:notes:" + self.experiment_id
        return descriptor

    def observation(self):
        # Never log the resource capability, nonce, or other challenge credentials.
        return {"family": self.experiment_type, "activated": self.activated,
                "activation_order": self.activation_order, "activation_phase": self.activation_phase,
                "replays": self.replay_count}


def create_experiments(challenge_id, session_id, created_at, expires_at, *,
                       resource_id=None, families=FAMILIES):
    if not 1 <= len(families) <= len(FAMILIES) or len(set(families)) != len(families):
        raise ValueError("Select one to three distinct experiment families")
    if any(family not in FAMILIES for family in families):
        raise ValueError("Unknown experiment family")
    experiments = [AgentExperiment(
        experiment_id=secrets.token_urlsafe(32), challenge_id=challenge_id, session_id=session_id,
        experiment_type=family.name,
        resource_id=(resource_id if family.name == "resource" and resource_id else secrets.token_urlsafe(32)),
        method=family.method, presentation=family.presentation,
        created_at=created_at, expires_at=expires_at,
    ) for family in families]
    secrets.SystemRandom().shuffle(experiments)
    return experiments
