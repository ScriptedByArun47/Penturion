from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.target import TargetCreate, TargetUpdate, TargetResponse
from app.services import target_service
from app.api.dependencies import get_current_user


router = APIRouter(
    tags=["Targets"],
    dependencies=[Depends(get_current_user)],
)


@router.post(
    "/projects/{project_id}/targets",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_project_target(
    project_id: str,
    target_data: TargetCreate,
    db: Session = Depends(get_db),
):
    try:
        return target_service.create_target(
            db=db,
            project_id=project_id,
            target_data=target_data,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/projects/{project_id}/targets",
    response_model=list[TargetResponse],
)
def list_project_targets(
    project_id: str,
    db: Session = Depends(get_db),
):
    try:
        return target_service.list_project_targets(
            db=db,
            project_id=project_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/targets/{target_id}",
    response_model=TargetResponse,
)
def get_target(
    target_id: str,
    db: Session = Depends(get_db),
):
    target = target_service.get_target(
        db=db,
        target_id=target_id,
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    return target


@router.patch(
    "/targets/{target_id}",
    response_model=TargetResponse,
)
def update_target(
    target_id: str,
    target_data: TargetUpdate,
    db: Session = Depends(get_db),
):
    target = target_service.update_target(
        db=db,
        target_id=target_id,
        target_data=target_data,
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    return target


@router.delete(
    "/targets/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_target(
    target_id: str,
    db: Session = Depends(get_db),
):
    deleted = target_service.delete_target(
        db=db,
        target_id=target_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)