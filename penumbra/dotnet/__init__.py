"""Dotnet IL pipeline — register available passes."""

from penumbra.dotnet.il_worker import (
    DotnetEncryptStringsPass,
    DotnetFlowPass,
    DotnetRenamePass,
    DotnetStripDebugPass,
)
from penumbra.pipeline import register_pipeline
from penumbra.types import PipelineType

register_pipeline(PipelineType.DOTNET_IL, [
    DotnetRenamePass(),
    DotnetEncryptStringsPass(),
    DotnetFlowPass(),
    DotnetStripDebugPass(),
])
