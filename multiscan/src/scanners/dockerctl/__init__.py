"""Docker control: a thin ``docker`` CLI wrapper (:mod:`client`) and the
target-container lifecycle manager for the dynamic phase (:mod:`lifecycle`)."""
from . import client, lifecycle  # noqa: F401
from .lifecycle import ContainerManager, Running, TargetUnscannable  # noqa: F401
