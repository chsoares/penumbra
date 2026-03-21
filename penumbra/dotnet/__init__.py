"""Dotnet IL pipeline — register available passes."""

from penumbra.dotnet.il_worker import (
    DotnetDInvokePass,
    DotnetEncryptStringsPass,
    DotnetFlowPass,
    DotnetRenamePass,
    DotnetStripDebugPass,
)
from penumbra.pipeline import register_pipeline
from penumbra.types import PipelineType

register_pipeline(PipelineType.DOTNET_IL, [
    DotnetDInvokePass(),
    DotnetRenamePass(),
    DotnetEncryptStringsPass(),
    DotnetFlowPass(),
    DotnetStripDebugPass(),
])
