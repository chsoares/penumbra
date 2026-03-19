"""PS1 pipeline — register available passes."""

from penumbra.pipeline import register_pipeline
from penumbra.ps.encode import Base64EncodePass
from penumbra.types import PipelineType

register_pipeline(PipelineType.PS1, [Base64EncodePass()])
