"""Script pipeline — register available passes."""

from penumbra.pipeline import register_pipeline
from penumbra.script.encode import ScriptEncodePass
from penumbra.script.wrap import ScriptWrapPass
from penumbra.types import PipelineType

register_pipeline(PipelineType.SCRIPT, [ScriptWrapPass(), ScriptEncodePass()])
