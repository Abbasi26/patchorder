"""Errors an operator can act on. These are not tracebacks."""


class PatchwindowError(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code
