from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.project import Project
from app.schemas.project import ProjectCreate, ProjectUpdate


def create_project(db: Session, data: ProjectCreate) -> Project:
    project = Project(
        name=data.name.strip(),
        description=data.description,
    )

    if not project.name:
        raise ValueError("Project name cannot be empty.")

    db.add(project)
    db.commit()
    db.refresh(project)

    return project


def list_projects(db: Session) -> list[Project]:
    statement = select(Project).order_by(Project.created_at.desc())
    return list(db.scalars(statement).all())


def get_project(db: Session, project_id: str) -> Project | None:
    return db.get(Project, project_id)


def update_project(
    db: Session,
    project: Project,
    data: ProjectUpdate,
) -> Project:
    updates = data.model_dump(exclude_unset=True)

    for field, value in updates.items():
        if field == "name" and value is not None:
            value = value.strip()

            if not value:
                raise ValueError("Project name cannot be empty.")

        if field == "status" and value is None:
            raise ValueError("Project status cannot be null.")

        setattr(project, field, value)

    db.commit()
    db.refresh(project)

    return project


def delete_project(db: Session, project: Project) -> None:
    db.delete(project)
    db.commit()