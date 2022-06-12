from celery import Celery
from celery.schedules import crontab

from decouple import config

from models.users import User, Blacklist
from db import engine
from fastapi import Depends
from sqlalchemy.orm import Session
from sqlalchemy import select, text

celery = Celery(
    broker_url = f"redis://:{config('redis_password')}@{config('redis_url')}",
)

celery.conf.update(
    task_serializer = "json",
    result_serializer = "json",
    task_ignore_result = True,
)


@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(
        crontab(minute=0, hour=0),
        blacklist_delete.s(),
    )


@celery.task(name="blacklist_delete")
def blacklist_delete():
    """
    Delete all rows from blacklist table once a day
    """
    with engine.connect() as connection:
        delete_blacklist = connection.execute(text("DELETE FROM blacklist"))
        result = connection.execute(text("select * from blacklist"))
        data = result.fetchall()
    return len(data)
