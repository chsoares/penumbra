"""PS1 pipeline — register available passes."""

from penumbra.pipeline import register_pipeline
from penumbra.ps.amsi import AmsiBypassPass
from penumbra.ps.encode import Base64EncodePass
from penumbra.ps.rename import RenamePass
from penumbra.ps.tokenize import TokenizePass
from penumbra.types import PipelineType

register_pipeline(
    PipelineType.PS1,
    [AmsiBypassPass(), RenamePass(), TokenizePass(), Base64EncodePass()],
)
