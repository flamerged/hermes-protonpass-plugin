"""Directory-install shim for the Hermes Proton Pass plugin."""

if __package__:
    from .hermes_protonpass import register
else:  # pytest may import this file without a package parent
    from hermes_protonpass import register

__all__ = ["register"]
