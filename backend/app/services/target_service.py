from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetUpdate


def create_target(
    db: Session,
    project_id: str,
    target_data: TargetCreate,
    owner_id: str,
) -> Target:
    # Only the project owner can create targets.
    project = db.scalars(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == owner_id,
        )
    ).first()

    if project is None:
        raise ValueError("Project not found")

    target = Target(
        project_id=project_id,
        value=target_data.value,
        target_type=target_data.target_type,
        notes=target_data.notes,
        authorization_status="pending",
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    return target


def list_project_targets(
    db: Session,
    project_id: str,
    owner_id: str,
) -> list[Target]:
    # Verify ownership before listing targets.
    project = db.scalars(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == owner_id,
        )
    ).first()

    if project is None:
        raise ValueError("Project not found")

    statement = (
        select(Target)
        .where(Target.project_id == project_id)
        .order_by(Target.created_at.desc())
    )

    return list(db.scalars(statement).all())


def get_target(
    db: Session,
    target_id: str,
    owner_id: str,
) -> Target | None:
    statement = (
        select(Target)
        .join(Project, Target.project_id == Project.id)
        .where(
            Target.id == target_id,
            Project.owner_id == owner_id,
        )
    )

    return db.scalars(statement).first()


def update_target(
    db: Session,
    target_id: str,
    target_data: TargetUpdate,
    owner_id: str,
) -> Target | None:
    target = get_target(db, target_id, owner_id)

    if target is None:
        return None

    updates = target_data.model_dump(exclude_unset=True)

    for field, value in updates.items():
        setattr(target, field, value)

    try:
        db.commit()
        db.refresh(target)
    except Exception:
        db.rollback()
        raise

    return target


def delete_target(
    db: Session,
    target_id: str,
    owner_id: str,
) -> bool:
    target = get_target(db, target_id, owner_id)

    if target is None:
        return False

    try:
        db.delete(target)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return True