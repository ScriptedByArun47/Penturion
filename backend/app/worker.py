"""Background worker for executing queued PENTURION scans."""

import logging
import signal
import time

from app.core.database import SessionLocal
from app.services.scan_service import run_worker_cycle

POLL_INTERVAL = 5
shutdown_requested = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("penturion.worker")


def handle_shutdown(signum, frame):
    global shutdown_requested
    logger.info("Shutdown requested. Finishing current cycle...")
    shutdown_requested = True


def main():
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    logger.info("PENTURION worker started.")
    logger.info("Polling interval: %s seconds", POLL_INTERVAL)

    while not shutdown_requested:
        db = SessionLocal()

        try:
            scan = run_worker_cycle(db=db)

            if scan is not None:
                logger.info(
                    "Scan processed: id=%s status=%s",
                    scan.id,
                    scan.status,
                )

        except Exception:
            db.rollback()
            logger.exception("Worker cycle failed.")

        finally:
            db.close()

        if not shutdown_requested:
            time.sleep(POLL_INTERVAL)

    logger.info("PENTURION worker stopped.")


if __name__ == "__main__":
    main()
