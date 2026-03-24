"""Shellcode pipeline — register available passes."""

from penumbra.pipeline import register_pipeline
from penumbra.shellcode.encrypt import ShellcodeEncryptPass
from penumbra.shellcode.loader import ShellcodeLoaderPass
from penumbra.types import PipelineType

register_pipeline(
    PipelineType.SHELLCODE,
    [ShellcodeEncryptPass(), ShellcodeLoaderPass()],
)
