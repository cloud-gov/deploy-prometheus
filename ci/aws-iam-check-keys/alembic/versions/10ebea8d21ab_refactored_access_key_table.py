"""Refactored access_key table

Revision ID: 10ebea8d21ab
Revises: 
Create Date: 2024-04-17 17:50:58.940420

"""
from typing import Sequence, Union
import logging

from alembic import op
from datetime import date
from datetime import datetime
import sqlalchemy as sa
from sqlalchemy import ForeignKey
from sqlalchemy import orm
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy import select
from typing import List
from typing import Optional

# revision identifiers, used by Alembic.
revision: str = '10ebea8d21ab'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

class Base(DeclarativeBase):
    pass

class Access_Key(Base):
    __tablename__ = "access_key"
    id: Mapped[int] = mapped_column(primary_key=True)
    key_num: Mapped[int]
    access_key_active: Mapped[Optional[bool]]
    access_key_last_rotated: Mapped[Optional[datetime]]
    access_key_last_used_date: Mapped[Optional[datetime]]
    access_key_last_used_region: Mapped[Optional[str]]
    access_key_last_used_service: Mapped[Optional[str]]
    cert_active: Mapped[bool]
    cert_last_rotated: Mapped[Optional[datetime]]
    user_id:Mapped[int] = mapped_column(ForeignKey("iam_keys.id"))

    def __str__(self):
        print(f"{self.id}")

    def __repr__(self):
        print(f'{self.id}')
        print(f'{self.key_num}')
        if self.access_key_active:
            print(f'{self.access_key_active}')
        else:
            print("no key active value")
        if self.access_key_last_rotated:
            print(f'{self.access_key_last_rotated}')
        else:
            print("no key last rotated value")
        if self.access_key_last_used_date:
            print(f'{self.access_key_last_used_date}')
        else:
            print("no key last used date value")
        if self.access_key_last_used_region:
            print(f'{self.access_key_last_used_region}')
        else:
            print("no key last used region value")
        if self.access_key_last_used_service:
            print(f'{self.access_key_last_used_service}')
        else:
            print("no key last used service value")
        if self.cert_active:
            print(f'{self.cert_active}')
        else:
            print("no cert active value")
        if self.cert_last_rotated:
            print(f'{self.cert_last_rotated}')
        else:
            print("no cert last rotated value")
class IAM_Keys(Base):
    __tablename__ = "iam_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    iam_user: Mapped[str]
    aws_account: Mapped[str]
    arn: Mapped[str] = mapped_column(unique=True)
    user_creation_time: Mapped[Optional[datetime]]
    password_enabled: Mapped[Optional[bool]]
    password_last_used: Mapped[Optional[datetime]]
    password_last_changed: Mapped[Optional[datetime]]
    password_next_rotation: Mapped[Optional[datetime]]
    mfa_active: Mapped[Optional[bool]]
    created_at: Mapped[datetime]
    updated_at: Mapped[Optional[datetime]]
    events: Mapped[List["Event"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    access_key_1_active: Mapped[bool]
    access_key_1_last_rotated: Mapped[Optional[datetime]]
    access_key_1_last_used_date: Mapped[Optional[datetime]]
    access_key_1_last_used_region: Mapped[Optional[str]]
    access_key_1_last_used_service: Mapped[Optional[str]]
    access_key_2_active: Mapped[bool]
    access_key_2_last_rotated: Mapped[Optional[datetime]]
    access_key_2_last_used_date: Mapped[Optional[datetime]]
    access_key_2_last_used_region: Mapped[Optional[str]]
    access_key_2_last_used_service: Mapped[Optional[str]]
    cert_1_active: Mapped[bool]
    cert_1_last_rotated: Mapped[Optional[datetime]]
    cert_2_active: Mapped[bool]
    cert_2_last_rotated: Mapped[Optional[datetime]]

class Event_Type(Base):
    __tablename__ = "event_type"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_type_name: Mapped[Optional[str]]
    created_at: Mapped[datetime]
    events: Mapped[List["Event"]] = relationship(back_populates="event_type", cascade="all, delete-orphan")
class Event(Base):
    __tablename__ = "event"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("iam_keys.id"))
    user: Mapped["IAM_Keys"] = relationship(back_populates="events")
    event_type_id: Mapped[int] = mapped_column(ForeignKey("event_type.id"))
    event_type:Mapped["Event_Type"] = relationship(back_populates="events")
    access_key_num: Mapped[int]
    cleared: Mapped[bool]
    cleared_date: Mapped[Optional[datetime]]
    warning_delta: Mapped[Optional[datetime]]
    violation_delta: Mapped[Optional[datetime]]
    alert_sent: Mapped[bool]
    created_at: Mapped[datetime]

def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('access_key',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('key_num', sa.Integer(), nullable=False),
    sa.Column('access_key_active', sa.Boolean(), nullable=True),
    sa.Column('access_key_last_rotated', sa.TIMESTAMP(timezone=False), nullable=True),
    sa.Column('access_key_last_used_date', sa.TIMESTAMP(timezone=False), nullable=True),
    sa.Column('access_key_last_used_region', sa.String(), nullable=True),
    sa.Column('access_key_last_used_service', sa.String(), nullable=True),
    sa.Column('cert_active', sa.Boolean(), nullable=False),
    sa.Column('cert_last_rotated', sa.TIMESTAMP(timezone=False), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['iam_keys.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    bind = op.get_bind()
    session=orm.Session(bind=bind)
    # logger = logging.getLogger("alembic")
    for iam_key in session.query(IAM_Keys):
        access_key1 = Access_Key()
        access_key1.key_num=1
        access_key1.access_key_active=iam_key.access_key_1_active
        access_key1.access_key_last_rotated=iam_key.access_key_1_last_rotated
        access_key1.access_key_last_used_date=iam_key.access_key_1_last_used_date
        access_key1.access_key_last_used_region=iam_key.access_key_1_last_used_region
        access_key1.access_key_last_used_service=iam_key.access_key_1_last_used_service
        access_key1.cert_active=iam_key.cert_1_active
        access_key1.cert_last_rotated=iam_key.cert_1_last_rotated
        access_key1.user_id = iam_key.id
        session.add(access_key1)

        access_key2 = Access_Key()
        access_key2.key_num=2
        access_key2.access_key_active=iam_key.access_key_2_active
        access_key2.access_key_last_rotated=iam_key.access_key_2_last_rotated
        access_key2.access_key_last_used_date=iam_key.access_key_2_last_used_date
        access_key2.access_key_last_used_region=iam_key.access_key_2_last_used_region
        access_key2.access_key_last_used_service=iam_key.access_key_2_last_used_service
        access_key2.cert_active=iam_key.cert_2_active
        access_key2.cert_last_rotated=iam_key.cert_2_last_rotated
        access_key2.user_id = iam_key.id
        session.add(access_key2)
    session.commit()

    op.add_column('event', sa.Column('warning_delta', sa.TIMESTAMP(timezone=False), nullable=True))
    op.add_column('event', sa.Column('violation_delta', sa.TIMESTAMP(timezone=False), nullable=True))
    op.drop_index('event_event_type_id', table_name='event')
    op.drop_index('event_user_id', table_name='event')
    op.alter_column('event_type', 'event_type_name',
               existing_type=sa.VARCHAR(length=255),
               nullable=True)
    op.drop_index('event_type_event_type_name', table_name='event_type')
    op.alter_column('iam_keys', 'password_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=True)
    op.alter_column('iam_keys', 'mfa_active',
               existing_type=sa.BOOLEAN(),
               nullable=True)
    op.drop_index('iam_keys_arn', table_name='iam_keys')
    op.create_unique_constraint(None, 'iam_keys', ['arn'])
    op.drop_column('iam_keys', 'cert_2_last_rotated')
    op.drop_column('iam_keys', 'access_key_1_last_rotated')
    op.drop_column('iam_keys', 'cert_1_active')
    op.drop_column('iam_keys', 'cert_2_active')
    op.drop_column('iam_keys', 'access_key_2_last_rotated')
    op.drop_column('iam_keys', 'access_key_2_active')
    op.drop_column('iam_keys', 'access_key_2_last_used_service')
    op.drop_column('iam_keys', 'access_key_2_last_used_region')
    op.drop_column('iam_keys', 'access_key_2_last_used_date')
    op.drop_column('iam_keys', 'access_key_1_last_used_region')
    op.drop_column('iam_keys', 'access_key_1_last_used_service')
    op.drop_column('iam_keys', 'cert_1_last_rotated')
    op.drop_column('iam_keys', 'access_key_1_active')
    op.drop_column('iam_keys', 'access_key_1_last_used_date')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    postgres_logger = logging.getLogger("alembic")
    op.add_column('iam_keys', sa.Column('access_key_1_last_used_date', postgresql.TIMESTAMP(timezone=False), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_1_active', sa.BOOLEAN(), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('cert_1_last_rotated', postgresql.TIMESTAMP(timezone=False), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_1_last_used_service', sa.VARCHAR(length=255), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_1_last_used_region', sa.VARCHAR(length=255), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_2_last_used_date', postgresql.TIMESTAMP(timezone=False), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_2_last_used_region', sa.VARCHAR(length=255), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_2_last_used_service', sa.VARCHAR(length=255), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_2_active', sa.BOOLEAN(), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_2_last_rotated', postgresql.TIMESTAMP(timezone=False), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('cert_2_active', sa.BOOLEAN(), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('cert_1_active', sa.BOOLEAN(), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('access_key_1_last_rotated', postgresql.TIMESTAMP(timezone=False), autoincrement=False, nullable=True))
    op.add_column('iam_keys', sa.Column('cert_2_last_rotated', postgresql.TIMESTAMP(timezone=False), autoincrement=False, nullable=True))
    #op.drop_constraint(None, 'iam_keys', type_='unique')
    op.create_index('iam_keys_arn', 'iam_keys', ['arn'], unique=True)
    op.alter_column('iam_keys', 'mfa_active',
               existing_type=sa.BOOLEAN(),
               nullable=False)
    op.alter_column('iam_keys', 'password_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False)
    op.create_index('event_type_event_type_name', 'event_type', ['event_type_name'], unique=True)
    op.alter_column('event_type', 'event_type_name',
               existing_type=sa.VARCHAR(length=255),
               nullable=False)
    op.create_index('event_user_id', 'event', ['user_id'], unique=False)
    op.create_index('event_event_type_id', 'event', ['event_type_id'], unique=False)
    op.drop_column('event', 'violation_delta')
    op.drop_column('event', 'warning_delta')
    # pull data from access_key into IAM_Key
    bind = op.get_bind()
    session=orm.Session(bind=bind)
    for access_key in session.query(Access_Key):
        query = select(IAM_Keys).where(IAM_Keys.id == access_key.user_id)
        iam_key = session.scalar(query)
        logging.debug(f"found key iam_key and it has {iam_key.access_key_1_active}\n")

        if access_key.key_num == 1:
            iam_key.access_key_1_active = access_key.access_key_active
            logging.debug("====> access_key_1_active: %s",iam_key.access_key_1_active)
            iam_key.access_key_1_last_rotated = access_key.access_key_last_rotated
            logging.debug("====> access_key_1_last_rotated: %s",iam_key.access_key_1_last_rotated)
            iam_key.access_key_1_last_used_date = access_key.access_key_last_used_date
            logging.debug("====> access_key_1_last_used_date: %s",iam_key.access_key_1_last_used_date)
            iam_key.access_key_1_last_used_region = access_key.access_key_last_used_region
            logging.debug("====> access_key_1_last_used_region: %s",iam_key.access_key_1_last_used_region)
            iam_key.access_key_1_last_used_service = access_key.access_key_last_used_service
            logging.debug("====> access_key_1_last_used_service: %s",iam_key.access_key_1_last_used_service)
            iam_key.cert_1_active = access_key.cert_active
            logging.debug("====> cert_1_active: %s",iam_key.cert_1_active)
            iam_key.cert_1_last_rotated = access_key.cert_last_rotated
            logging.debug("====> cert_1_last_rotated: %s",iam_key.cert_1_last_rotated)
            session.add(iam_key)

        if access_key.key_num == 2:
            iam_key.access_key_2_active = access_key.access_key_active
            logging.debug("====> access_key_active: %s",iam_key.access_key_2_active)
            iam_key.access_key_2_last_rotated = access_key.access_key_last_rotated
            logging.debug("====> access_key_2_last_rotated: %s",iam_key.access_key_2_last_rotated)
            iam_key.access_key_2_last_used_date = access_key.access_key_last_used_date
            logging.debug("====> access_key_2_last_used_date: %s",iam_key.access_key_2_last_used_date)
            iam_key.access_key_2_last_used_region = access_key.access_key_last_used_region
            logging.debug("====> access_key_2_last_used_region: %s",iam_key.access_key_2_last_used_region)
            iam_key.access_key_2_last_used_service = access_key.access_key_last_used_service
            logging.debug("====> access_key_2_last_used_service: %s",iam_key.access_key_2_last_used_service)
            iam_key.cert_2_active = access_key.cert_active
            logging.debug("====> cert_2_active: %s",iam_key.cert_2_active)
            iam_key.cert_2_last_rotated = access_key.cert_last_rotated
            logging.debug("====> cert_2_last_rotated: %s",iam_key.cert_2_last_rotated)
            session.add(iam_key)
    session.commit()
    op.alter_column('iam_keys', 'access_key_1_active', existing_type=sa.BOOLEAN(), nullable=False)
    op.alter_column('iam_keys', 'access_key_2_active', existing_type=sa.BOOLEAN(), nullable=False)
    op.alter_column('iam_keys', 'cert_1_active', existing_type=sa.BOOLEAN(), nullable=False)
    op.alter_column('iam_keys', 'cert_2_active', existing_type=sa.BOOLEAN(), nullable=False)

    op.drop_table('access_key')
    # ### end Alembic commands ###
