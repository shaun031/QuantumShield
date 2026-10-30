"""Application services (lazy exports keep offline policy tools config-free)."""

__all__ = ["AuthService", "DuplicateEmailError", "FileService"]


def __getattr__(name: str):
    if name in {"AuthService", "DuplicateEmailError"}:
        from app.services.auth import AuthService, DuplicateEmailError
        return {"AuthService": AuthService, "DuplicateEmailError": DuplicateEmailError}[name]
    if name == "FileService":
        from app.services.files import FileService
        return FileService
    raise AttributeError(name)
