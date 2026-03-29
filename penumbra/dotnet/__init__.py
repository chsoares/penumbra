"""Dotnet IL pipeline — register available passes."""

from penumbra.dotnet.clm_bypass import ClmBypassPass
from penumbra.dotnet.embed import DotnetEmbedPass
from penumbra.dotnet.il_worker import (
    DotnetDInvokePass,
    DotnetEncryptStringsPass,
    DotnetFlowPass,
    DotnetRenamePass,
    DotnetStripDebugPass,
)
from penumbra.dotnet.lolbas import InstallUtilPass, RegAsmPass
from penumbra.pipeline import register_pipeline
from penumbra.types import PipelineType

register_pipeline(PipelineType.DOTNET_IL, [
    DotnetDInvokePass(),
    DotnetRenamePass(),
    DotnetEncryptStringsPass(),
    DotnetFlowPass(),
    DotnetStripDebugPass(),
    DotnetEmbedPass(),
    InstallUtilPass(),
    RegAsmPass(),
    ClmBypassPass(),
])
