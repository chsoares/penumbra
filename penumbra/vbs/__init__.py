"""VBS pipeline — register available passes."""

from penumbra.pipeline import register_pipeline
from penumbra.types import PipelineType
from penumbra.vbs.encode import VbsEncodePass
from penumbra.vbs.wrap import VbsWrapPass

register_pipeline(
    PipelineType.VBS,
    [VbsEncodePass(), VbsWrapPass()],
)
